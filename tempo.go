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
// spans. The tenant is resource.service.name.
type Tempo struct {
	Gate
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
	t.filter(w, r, tenant, r.URL.Path, only(r.URL.Query(), "start", "end"), func(body map[string]any) bool { return FilterTrace(body, tenant) })
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
// tenant's, and the per-service counts keep the tenant's. The matched spans are the tenant's already. False when
// the answer isn't a search's.
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

// FilterTrace keeps a trace's resource spans whose service.name is the tenant; false when none are.
func FilterTrace(body map[string]any, tenant string) bool {
	trace, ok := body["trace"].(map[string]any)
	if !ok {
		return false
	}
	resources, _ := trace["resourceSpans"].([]any)
	var kept []any
	for _, rs := range resources {
		if serviceName(rs) == tenant {
			kept = append(kept, rs)
		}
	}
	if len(kept) == 0 {
		return false
	}
	trace["resourceSpans"] = kept
	return true
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
