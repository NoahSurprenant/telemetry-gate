package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// Tempo allows a TraceQL search, narrowed to the tenant's spans, and fetching a trace by id, cut down to the tenant's
// spans and the related services' spans of the tenant's requests (Related). The tenant is resource.service.name.
type Tempo struct {
	Gate
	Related
	// Hosts: each tenant's own hosts, the evidence an edge span is its request's. Read only when there are edge
	// services; none read (an error) shows no edge span.
	Hosts Hosts
}

// Related names the services whose spans a tenant's trace keeps where they belong to the tenant's requests
// (FilterTrace).
type Related struct {
	// Edge: the services in front of the tenants (the ingress, the CDN). A trace keeps their spans the tenant's sit
	// under, and those spans' own edge spans; a search names their roots.
	Edge map[string]bool
	// Downstream: the services the tenants call (a gateway to another API). A trace keeps their spans under the
	// tenant's, from one whose Caller attribute names the tenant.
	Downstream map[string]bool
	// Caller: the attribute a downstream service's span names its caller by, set by that service from what the
	// caller proved (the Halo gateway's grunt.api_key: the name of the API key it was called with). Unset, no
	// downstream span is kept: a tenant writes its own span ids, so being under one proves nothing.
	Caller string
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
	t.filter(w, r, tenant, r.URL.Path, kept, func(body map[string]any) bool { return FilterSearch(body, tenant) })
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
	t.filter(w, r, tenant, r.URL.Path, only(r.URL.Query(), "start", "end"), func(body map[string]any) bool { return FilterTrace(body, tenant, t.Related, t.tenantHosts(r.Context(), tenant, body)) })
}

// tenantHosts reads the tenant's hosts when the trace has edge spans to show; nil (so none shown) when they can't
// be read.
func (t *Tempo) tenantHosts(ctx context.Context, tenant string, body map[string]any) map[string]bool {
	if len(t.Edge) == 0 || t.Hosts == nil || !hasService(body, t.Edge) || !hasService(body, map[string]bool{tenant: true}) {
		return nil
	}
	hosts, err := t.Hosts.Hosts(ctx, tenant)
	if err != nil {
		t.Log.Warn("hosts", "tenant", tenant, "error", err)
		return nil
	}
	return hosts
}

// hasService says whether a trace has spans of one of services.
func hasService(body map[string]any, services map[string]bool) bool {
	trace, _ := body["trace"].(map[string]any)
	resources, _ := trace["resourceSpans"].([]any)
	for _, rs := range resources {
		if services[serviceName(rs)] {
			return true
		}
	}
	return false
}

// checkRelated refuses related services that would blur whose a span is: one in both lists (its spans would be
// kept as both, above and under the tenant's), or one named like a tenant (a tenant's spans would pass for it).
func checkRelated(related Related, namespaces *regexp.Regexp) error {
	for name := range related.Edge {
		if related.Downstream[name] {
			return fmt.Errorf("%s is both an edge and a downstream service", name)
		}
	}
	if len(related.Downstream) > 0 && related.Caller == "" {
		return errors.New("downstream services need a caller attribute (-downstream-caller-attribute): being under a tenant's span proves nothing")
	}
	for _, set := range []map[string]bool{related.Edge, related.Downstream} {
		for name := range set {
			if namespaces.MatchString(name) {
				return fmt.Errorf("%s is named like a tenant", name)
			}
		}
	}
	return nil
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
// tenant's, and the per-service counts keep the tenant's (a root or a count of the related services' may be another
// request's). The matched spans are the tenant's already. False when the answer isn't a search's.
func FilterSearch(body map[string]any, tenant string) bool {
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
		if trace["rootServiceName"] != tenant {
			delete(trace, "rootServiceName")
			delete(trace, "rootTraceName")
		}
		if stats, ok := trace["serviceStats"].(map[string]any); ok {
			for service := range stats {
				if service != tenant {
					delete(stats, service)
				}
			}
		}
	}
	return true
}

// FilterTrace keeps a trace's resource spans whose service.name is the tenant, and of the related services' spans
// only those of the tenant's own requests (false when the tenant has no spans):
//   - edge: up the chain of edge spans a tenant's span sits under, each span while it leads to no other app
//     (leadsElsewhere: so not the Cloudflare request of a second origin fetch for another app) and names no host but
//     the tenant's (hosts: its IngressRoutes'), when the chain starts the trace or sits under the tenant's own span
//     (its browser's), not another service's (another app calling the tenant through the ingress), and only when one
//     of its spans names one of the tenant's hosts (Cloudflare's request, Traefik's router): the evidence it is the
//     tenant's request. Then those spans' edge descendants that lead to no other app and name no other host
//     (Cloudflare's firewall and response). A cycle or a chain longer than maxEdgeChain shows nothing, and no hosts
//     (they couldn't be read) no edge span;
//   - downstream: the spans under the tenant's, through downstream spans only (the Halo gateway's).
//
// A span id two spans share links nothing: the trace's spans come from its services, a tenant's included, so one
// could reuse another's id to sit under or over its spans.
func FilterTrace(body map[string]any, tenant string, related Related, hosts map[string]bool) bool {
	trace, ok := body["trace"].(map[string]any)
	if !ok {
		return false
	}
	resources, _ := trace["resourceSpans"].([]any)
	if len(related.Edge) == 0 && len(related.Downstream) == 0 {
		return keepResources(trace, resources, tenant, Related{}, nil)
	}

	g := indexSpans(resources, related)
	shown := map[string]bool{}

	// Edge: up from each of the tenant's spans through edge spans, each one shown while it leads to no other app,
	// unless the chain sits under another service's span; then their edge descendants that lead to no other app
	elsewhere := g.leadsElsewhere(tenant, related.Edge, hosts)
	var edgeQueue []string
	for _, id := range g.of(tenant) {
		if g.shared[id] {
			continue
		}
		var chain []string
		seen := map[string]bool{}
		top := g.spans[id].parent
		for top != "" && related.Edge[g.service(top)] && !g.shared[top] && !seen[top] && len(chain) < maxEdgeChain {
			seen[top] = true
			chain = append(chain, top)
			top = g.spans[top].parent
		}
		// Only a chain that starts the trace or sits under the tenant's own span (its browser's): not under a cycle, a
		// chain too long, a shared id, another service's span or one not in the trace (sampled out, not ingested, forged)
		if len(chain) == 0 || seen[top] || g.shared[top] || (top != "" && g.service(top) != tenant) {
			continue
		}
		// The evidence is on its top, the request's own root (a tenant can't forge a span above it): the tenant's host.
		// And none of it leads to another app or names another host.
		if !hosts[g.spans[chain[len(chain)-1]].host] || slices.ContainsFunc(chain, func(edgeID string) bool {
			host := g.spans[edgeID].host
			return elsewhere(edgeID) || (host != "" && !hosts[host])
		}) {
			continue
		}
		for _, edgeID := range chain {
			if !shown[edgeID] {
				shown[edgeID] = true
				edgeQueue = append(edgeQueue, edgeID)
			}
		}
	}
	g.descend(edgeQueue, shown, func(child string) bool {
		host := g.spans[child].host
		return related.Edge[g.service(child)] && (host == "" || hosts[host]) && !elsewhere(child)
	})

	// Downstream: under the tenant's spans, from one naming the tenant as its caller (a tenant could copy another's
	// span id to sit over that one's calls; it can't make the downstream service name it)
	var downQueue []string
	for _, id := range g.of(tenant) {
		if !g.shared[id] {
			downQueue = append(downQueue, id)
		}
	}
	g.descend(downQueue, shown, func(child string) bool {
		if related.Caller == "" || !related.Downstream[g.service(child)] {
			return false
		}
		// Each hop names the tenant or no one (the gateway's own inner spans); the first one, under the tenant's span,
		// must name it
		caller := g.spans[child].caller
		if g.service(g.spans[child].parent) == tenant {
			return caller == tenant
		}
		return caller == "" || caller == tenant
	})

	return keepResources(trace, resources, tenant, related, shown)
}

// maxEdgeChain caps the edge spans walked up from one of the tenant's spans: a real chain (Cloudflare's, then
// Traefik's) is a handful deep, and a longer one (forged) shows nothing.
const maxEdgeChain = 32

// maxEdgeDepth caps how far below an edge span leadsElsewhere looks: Cloudflare's and Traefik's spans are a few
// levels deep, and anything deeper (forged) counts as another app's.
const maxEdgeDepth = 64

// leadsElsewhere answers, for an edge span, whether anything under it is another app's: through edge spans, a span
// of a service neither the tenant nor an edge one, an edge span naming another host, a shared id, a cycle, a tree
// deeper than maxEdgeDepth, or a client call (Traefik's proxying) whose callee isn't in the trace (not ingested
// yet, sampled out, untraced). The tenant's spans end the search.
func (g spanGraph) leadsElsewhere(tenant string, edge, hosts map[string]bool) func(id string) bool {
	known := map[string]bool{}
	visiting := map[string]bool{}
	// below answers for id reached at depth, and whether the depth cap decided it (then it isn't kept: from nearer
	// the top the answer may differ)
	var below func(id string, depth int) (bool, bool)
	below = func(id string, depth int) (result, capped bool) {
		if v, done := known[id]; done {
			return v, false
		}
		if visiting[id] {
			return true, false
		}
		if depth > maxEdgeDepth {
			return true, true
		}
		visiting[id] = true
		defer delete(visiting, id)
		children := g.children[id]
		result = len(children) == 0 && g.spans[id].kind == clientKind
		for _, child := range children {
			if result {
				break
			}
			switch service := g.service(child); {
			case g.shared[child]:
				result = true
			case service == tenant:
			case edge[service]:
				if host := g.spans[child].host; host != "" && !hosts[host] {
					result = true
				} else {
					var childCapped bool
					result, childCapped = below(child, depth+1)
					capped = capped || childCapped
				}
			default:
				result = true
			}
		}
		if !capped {
			known[id] = result
		}
		return result, capped
	}
	// From the top (depth 0) an answer is final: kept, so a chain many of the tenant's spans share is looked at once
	answered := map[string]bool{}
	return func(id string) bool {
		if v, done := answered[id]; done {
			return v
		}
		result, _ := below(id, 0)
		answered[id] = result
		return result
	}
}

const clientKind = "SPAN_KIND_CLIENT"

// hostOf reads a span's server.address as a host: lower case, without a port or a trailing dot; "" for none, or an
// address on a client call (Traefik's proxying to a pod, whose callee's own spans say whose it is). An address on
// any other span is another origin's, named so it matches no tenant's host.
func hostOf(span map[string]any, kind string) string {
	if host := normalHost(spanAttribute(span, "server.address")); host != "" {
		if net.ParseIP(host) != nil {
			if kind == clientKind {
				return ""
			}
			return "address:" + host
		}
		return host
	}
	return ""
}

// spanAttribute reads a span's string attribute; "" when it has none.
func spanAttribute(span map[string]any, key string) string {
	attrs, _ := span["attributes"].([]any)
	for _, a := range attrs {
		attr, _ := a.(map[string]any)
		if attr["key"] == key {
			value, _ := attr["value"].(map[string]any)
			v, _ := value["stringValue"].(string)
			return v
		}
	}
	return ""
}

// spanGraph indexes a trace's spans by id: each one's parent and service, its children, and the ids more than one
// span has (shared, linked to nothing).
type spanGraph struct {
	spans     map[string]spanRef
	children  map[string][]string
	shared    map[string]bool
	byService map[string][]string
}

// spanRef is a span as the filter sees it: host is the server.address it names, when that is a host name (Cloudflare's
// request, Traefik's router; not Traefik's proxying, which names the pod's address).
// caller is the value of Related.Caller on it (a downstream service's record of who called it).
type spanRef struct{ parent, service, kind, host, caller string }

func indexSpans(resources []any, related Related) spanGraph {
	g := spanGraph{spans: map[string]spanRef{}, children: map[string][]string{}, shared: map[string]bool{}, byService: map[string][]string{}}
	for _, rs := range resources {
		service := serviceName(rs)
		for _, span := range spansOf(rs) {
			id, _ := span["spanId"].(string)
			if id == "" {
				continue
			}
			parent, _ := span["parentSpanId"].(string)
			kind, _ := span["kind"].(string)
			if _, seen := g.spans[id]; seen {
				g.shared[id] = true
			}
			caller := ""
			if related.Caller != "" && related.Downstream[service] {
				caller = spanAttribute(span, related.Caller)
			}
			g.spans[id] = spanRef{parent, service, kind, hostOf(span, kind), caller}
			g.children[parent] = append(g.children[parent], id)
			g.byService[service] = append(g.byService[service], id)
		}
	}
	return g
}

func (g spanGraph) service(id string) string { return g.spans[id].service }
func (g spanGraph) of(service string) []string { return g.byService[service] }

// descend marks, breadth first from queue, each child take accepts (not a shared id), and goes on from it.
func (g spanGraph) descend(queue []string, shown map[string]bool, take func(child string) bool) {
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, child := range g.children[id] {
			if !shown[child] && !g.shared[child] && take(child) {
				shown[child] = true
				queue = append(queue, child)
			}
		}
	}
}

// keepResources keeps the tenant's resource spans whole and, of the related services', the shown spans; false when
// the tenant has none.
func keepResources(trace map[string]any, resources []any, tenant string, related Related, shown map[string]bool) bool {
	var kept []any
	hasTenant := false
	for _, rs := range resources {
		switch service := serviceName(rs); {
		case service == tenant:
			hasTenant = true
			kept = append(kept, rs)
		case related.Edge[service] || related.Downstream[service]:
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
