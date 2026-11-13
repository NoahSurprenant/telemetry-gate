package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Tempo allows a TraceQL search, narrowed to the tenant's spans, and fetching a trace by id, cut down to the tenant's
// spans and the related services' spans of the tenant's requests (Related). The tenant is resource.service.name.
type Tempo struct {
	Gate
	Related
}

// Related names the services whose spans a tenant's trace keeps where they belong to the tenant's requests
// (FilterTrace).
type Related struct {
	// Edge: the services in front of the tenants (the ingress, the CDN). A trace keeps their spans the tenant's sit
	// under, and those spans' own edge spans; a search names their roots.
	Edge map[string]bool
	// Downstream: the services the tenants call (a gateway to another API). A trace keeps their spans under the
	// tenant's.
	Downstream map[string]bool
}

const tracePath = "/api/v2/traces/"

var traceID = regexp.MustCompile(`^[0-9a-fA-F]{1,32}$`)

func (t *Tempo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/search":
		t.search(w, r)
	case strings.HasPrefix(r.URL.Path, tracePath) && traceID.MatchString(strings.TrimPrefix(r.URL.Path, tracePath)):
		t.trace(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (t *Tempo) search(w http.ResponseWriter, r *http.Request) {
	tenant := t.tenant(w, r)
	if tenant == "" {
		return
	}
	values, ok := form(w, r)
	if !ok {
		return
	}
	q, err := EnforceTraceQL(values.Get("q"), tenant)
	if err != nil {
		t.refuse(w, r, tenant, err.Error())
		return
	}
	kept := only(values, "start", "end", "limit", "spss", "minDuration", "maxDuration")
	kept.Set("q", q)
	t.filter(w, r, tenant, r.URL.Path, kept, func(body map[string]any) bool { return FilterSearch(body, tenant, t.Related) })
}

func (t *Tempo) trace(w http.ResponseWriter, r *http.Request) {
	tenant := t.tenant(w, r)
	if tenant == "" {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	t.filter(w, r, tenant, r.URL.Path, only(r.URL.Query(), "start", "end"), func(body map[string]any) bool { return FilterTrace(body, tenant, t.Related) })
}

// filter reads the upstream's JSON answer and sends it on after keep; keep false is a 404.
func (t *Tempo) filter(w http.ResponseWriter, r *http.Request, tenant, path string, query map[string][]string, keep func(map[string]any) bool) {
	resp, err := t.fetch(r, path, query)
	if err != nil {
		t.Log.Error("upstream", "tenant", tenant, "path", path, "error", err)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Errors (a bad query, a trace not found) carry no telemetry: passed on.
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, io.LimitReader(resp.Body, 64<<10))
		return
	}
	var body map[string]any
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxBody))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		http.Error(w, "unreadable upstream answer", http.StatusBadGateway)
		return
	}
	if !keep(body) {
		t.Log.Info("passed", "tenant", tenant, "path", path, "status", http.StatusNotFound)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	t.Log.Info("passed", "tenant", tenant, "path", path, "status", http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}

var (
	errTraceQL = errors.New("only a single spanset filter {...}, optionally | select(attributes)")
	// Trace-level intrinsics and the parent scope reach outside the tenant's own spans.
	outsideSpan = regexp.MustCompile(`(?i)\b(trace|parent)\s*[:.]`)
	selectStage = regexp.MustCompile(`^\s*(?:\|\s*select\s*\(([^()]*)\))?\s*$`)
	attribute   = regexp.MustCompile(`^\s*[A-Za-z0-9_.:\-]+\s*$`)
)

// EnforceTraceQL wraps the query's spanset filter as {resource.service.name="tenant" && (filter)}, so it matches the
// tenant's spans only. The query is one spanset filter (no structural or spanset operators: braces only around it and
// in strings), with no trace-level intrinsics or parent scope, optionally followed by | select(attributes).
func EnforceTraceQL(query, tenant string) (string, error) {
	query = strings.TrimSpace(query)
	end, ok := scanBraces(query)
	if !ok {
		return "", errTraceQL
	}
	filter, rest := strings.TrimSpace(query[1:end]), query[end+1:]
	bare, ok := outsideStrings(filter)
	if !ok || outsideSpan.MatchString(bare) {
		return "", errTraceQL
	}
	m := selectStage.FindStringSubmatch(rest)
	if m == nil {
		return "", errTraceQL
	}
	enforced := "resource.service.name = " + quote(tenant)
	if filter != "" {
		enforced += " && (" + filter + ")"
	}
	out := "{" + enforced + "}"
	if m[1] != "" || strings.Contains(rest, "select") {
		attrs := strings.Split(m[1], ",")
		for i, a := range attrs {
			if !attribute.MatchString(a) || outsideSpan.MatchString(a) {
				return "", errTraceQL
			}
			attrs[i] = strings.TrimSpace(a)
		}
		out += " | select(" + strings.Join(attrs, ", ") + ")"
	}
	return out, nil
}

// FilterSearch keeps what a search may say about other services: a trace's root is named only when it is the
// tenant's or an edge service's (every trace found has the tenant's spans), and the per-service counts keep the
// tenant's and the related services'. The matched spans are the tenant's already. False when the answer isn't a
// search's.
func FilterSearch(body map[string]any, tenant string, related Related) bool {
	traces, ok := body["traces"].([]any)
	if !ok {
		_, has := body["traces"]
		return !has
	}
	for _, t := range traces {
		trace, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if root, _ := trace["rootServiceName"].(string); root != tenant && !related.Edge[root] {
			delete(trace, "rootServiceName")
			delete(trace, "rootTraceName")
		}
		if stats, ok := trace["serviceStats"].(map[string]any); ok {
			for service := range stats {
				if service != tenant && !related.Edge[service] && !related.Downstream[service] {
					delete(stats, service)
				}
			}
		}
	}
	return true
}

// FilterTrace keeps a trace's resource spans whose service.name is the tenant; of the edge services' spans the ones
// the tenant's sit under (Cloudflare's request, Traefik's router) and their own edge spans (Cloudflare's firewall and
// response); and of the downstream services' spans the ones under the tenant's (the Halo gateway's), through
// downstream spans only. Not an edge span under the tenant's (an ingress the tenant calls through to another app), nor
// one of another request's. False when the tenant has no spans.
func FilterTrace(body map[string]any, tenant string, related Related) bool {
	edge, downstream := related.Edge, related.Downstream
	trace, ok := body["trace"].(map[string]any)
	if !ok {
		return false
	}
	resources, _ := trace["resourceSpans"].([]any)

	type ref struct{ parent, service string }
	spans := map[string]ref{}
	children := map[string][]string{}
	for _, rs := range resources {
		service := serviceName(rs)
		for _, span := range spansOf(rs) {
			id, _ := span["spanId"].(string)
			parent, _ := span["parentSpanId"].(string)
			if id != "" {
				spans[id] = ref{parent, service}
				children[parent] = append(children[parent], id)
			}
		}
	}

	// The edge spans above the tenant's, then their edge descendants
	shown := map[string]bool{}
	var queue []string
	for _, r := range spans {
		if r.service != tenant {
			continue
		}
		for id := r.parent; id != "" && !shown[id] && edge[spans[id].service]; id = spans[id].parent {
			shown[id] = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, child := range children[id] {
			if !shown[child] && edge[spans[child].service] {
				shown[child] = true
				queue = append(queue, child)
			}
		}
	}

	// The downstream spans under the tenant's, and theirs
	for id, r := range spans {
		if r.service == tenant {
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, child := range children[id] {
			if !shown[child] && downstream[spans[child].service] {
				shown[child] = true
				queue = append(queue, child)
			}
		}
	}

	var kept []any
	hasTenant := false
	for _, rs := range resources {
		switch service := serviceName(rs); {
		case service == tenant:
			hasTenant = true
			kept = append(kept, rs)
		case edge[service] || downstream[service]:
			if keepSpans(rs, func(span map[string]any) bool {
				id, _ := span["spanId"].(string)
				return id != "" && shown[id]
			}) {
				kept = append(kept, rs)
			}
		}
	}
	if !hasTenant {
		return false
	}
	trace["resourceSpans"] = kept
	return true
}

// spansOf reads the spans of a resourceSpans entry.
func spansOf(rs any) []map[string]any {
	m, _ := rs.(map[string]any)
	scopes, _ := m["scopeSpans"].([]any)
	var out []map[string]any
	for _, ss := range scopes {
		scope, _ := ss.(map[string]any)
		spans, _ := scope["spans"].([]any)
		for _, s := range spans {
			if span, ok := s.(map[string]any); ok {
				out = append(out, span)
			}
		}
	}
	return out
}

// keepSpans drops the spans of a resourceSpans entry that keep answers false for, and the scopes left empty. True when
// any span is left.
func keepSpans(rs any, keep func(map[string]any) bool) bool {
	m, _ := rs.(map[string]any)
	scopes, _ := m["scopeSpans"].([]any)
	var keptScopes []any
	for _, ss := range scopes {
		scope, _ := ss.(map[string]any)
		spans, _ := scope["spans"].([]any)
		var keptSpans []any
		for _, s := range spans {
			if span, ok := s.(map[string]any); ok && keep(span) {
				keptSpans = append(keptSpans, span)
			}
		}
		if len(keptSpans) > 0 {
			scope["spans"] = keptSpans
			keptScopes = append(keptScopes, scope)
		}
	}
	if m != nil {
		m["scopeSpans"] = keptScopes
	}
	return len(keptScopes) > 0
}

// serviceName reads resource.attributes[service.name].stringValue of a resourceSpans entry.
func serviceName(rs any) string {
	m, _ := rs.(map[string]any)
	resource, _ := m["resource"].(map[string]any)
	attrs, _ := resource["attributes"].([]any)
	for _, a := range attrs {
		attr, _ := a.(map[string]any)
		if attr["key"] == "service.name" {
			value, _ := attr["value"].(map[string]any)
			s, _ := value["stringValue"].(string)
			return s
		}
	}
	return ""
}
