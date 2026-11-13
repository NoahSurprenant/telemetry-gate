package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// --- PromQL

// selectorsOf lists every selector's matchers in a query.
func selectorsOf(t *testing.T, query string) [][]*labels.Matcher {
	t.Helper()
	expr, err := promQL.ParseExpr(query)
	if err != nil {
		t.Fatalf("enforced query doesn't parse: %v\n%s", err, query)
	}
	var all [][]*labels.Matcher
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			all = append(all, vs.LabelMatchers)
		}
		return nil
	})
	return all
}

func TestEnforcePromQLNarrowsEverySelector(t *testing.T) {
	for _, q := range []string{
		`up`,
		`sum(rate(http_server_request_duration_seconds_count{service_name="grif-prod",http_route!~"/health/.*"}[2m]))`,
		`histogram_quantile(0.95, sum by (le) (rate(x_bucket[5m]))) * 1000`,
		`up or on() vector(1) or {__name__=~".+"}`,
		`max_over_time(rate(a[1m])[1h:5m]) / ignoring(x) b offset 1d`,
		`{service_name=~".+"}`,
		`label_replace(up, "service_name", "grif-prod", "", "")`,
	} {
		out, err := EnforcePromQL(q, "service_name", "grif-test")
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		selectors := selectorsOf(t, out)
		if len(selectors) == 0 {
			t.Fatalf("%s: no selectors", q)
		}
		for _, matchers := range selectors {
			found := false
			for _, m := range matchers {
				if m.Name == "service_name" && m.Type == labels.MatchEqual && m.Value == "grif-test" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s -> %s: a selector without service_name=\"grif-test\"", q, out)
			}
		}
	}
}

func TestEnforcePromQLRefusesWhatDoesntParse(t *testing.T) {
	if _, err := EnforcePromQL(`sum(`, "service_name", "x"); err == nil {
		t.Fatal("want an error")
	}
	if _, err := EnforcePromQL(``, "service_name", "x"); err == nil {
		t.Fatal("want an error for no query")
	}
}

// --- LogQL

func TestEnforceLogQL(t *testing.T) {
	cases := map[string]string{
		`{service_name="grif-prod"}`: `{service_name="grif-test", service_name="grif-prod"}`,
		`{service_name="grif-prod"} | detected_level=~"warn|error" |~ "(?i)a \"quoted\" \\(x\\) {}"`: `{service_name="grif-test", service_name="grif-prod"} | detected_level=~"warn|error" |~ "(?i)a \"quoted\" \\(x\\) {}"`,
		` {namespace=~".+"} | line_format "{{.message}}" `: `{service_name="grif-test", namespace=~".+"} | line_format "{{.message}}"`,
		"{app=`x}`} |= `}`":                                  "{service_name=\"grif-test\", app=`x}`} |= `}`",
		`{}`:                                                  `{service_name="grif-test"}`,
	}
	for in, want := range cases {
		got, err := EnforceLogQL(in, "service_name", "grif-test")
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestEnforceLogQLRefusesAnythingButALogQuery(t *testing.T) {
	for _, q := range []string{
		``,
		`count_over_time({a="b"}[5m])`,
		`sum by (namespace) (rate({a="b"}[1m]))`,
		`{a="b"} or {c="d"}`,
		`{a="b"}[5m]`,
		`{a="b" # } , c="d"
		}`,
		`{a="b"} # {`,
		`{a="b"`,
		`{a="b}`,
		`{a={}}`,
		`{a="b"} |= "unclosed`,
		`{a="b"} |= ` + "`unclosed",
	} {
		if got, err := EnforceLogQL(q, "service_name", "grif-test"); err == nil {
			t.Errorf("%q: want refused, got %s", q, got)
		}
	}
}

// --- TraceQL

func TestEnforceTraceQL(t *testing.T) {
	cases := map[string]string{
		`{resource.service.name="grif-prod"} | select(span.http.route, span.http.response.status_code)`: `{resource.service.name = "grif-test" && (resource.service.name="grif-prod")} | select(span.http.route, span.http.response.status_code)`,
		`{status=error || duration>=250ms}`: `{resource.service.name = "grif-test" && (status=error || duration>=250ms)}`,
		`{}`:                                `{resource.service.name = "grif-test"}`,
		`{span.x = "} && {"}`:               `{resource.service.name = "grif-test" && (span.x = "} && {")}`,
	}
	for in, want := range cases {
		got, err := EnforceTraceQL(in, "grif-test")
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestEnforceTraceQLRefusesWhatReachesOtherServices(t *testing.T) {
	for _, q := range []string{
		``,
		`{a=1} && {resource.service.name="loki"}`,
		`{a=1} >> {b=2}`,
		`{a=1} || {b=2}`,
		`{a=1} | count() > 1`,
		`{trace:rootService="loki"}`,
		`{trace:duration > 1s}`,
		`{parent.span.x = "y"}`,
		`{a=1} | select(trace:rootName)`,
		`{a=1} | select()`,
		`{a=1} | select(span.x) | select(span.y)`,
		`{a=1`,
		`{a={b}}`,
		`{a="unclosed}`,
	} {
		if got, err := EnforceTraceQL(q, "grif-test"); err == nil {
			t.Errorf("%q: want refused, got %s", q, got)
		}
	}
}

func TestFilterSearchHidesOtherServicesRoots(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"traces":[
		{"traceID":"a","rootServiceName":"grif-test","rootTraceName":"GET x","serviceStats":{"grif-test":{"spanCount":1},"traefik":{"spanCount":2}}},
		{"traceID":"b","rootServiceName":"traefik","rootTraceName":"router secret","serviceStats":{"traefik":{"spanCount":1}}}
	]}`), &body)

	if !FilterSearch(body, "grif-test", Related{}) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "traefik") || strings.Contains(string(out), "router secret") {
		t.Errorf("other services left in: %s", out)
	}
	if !strings.Contains(string(out), `"rootTraceName":"GET x"`) {
		t.Errorf("the tenant's root removed: %s", out)
	}
	if !FilterSearch(map[string]any{}, "grif-test", Related{}) {
		t.Error("an empty answer is kept")
	}
	if FilterSearch(map[string]any{"traces": "nonsense"}, "grif-test", Related{}) {
		t.Error("a malformed answer is refused")
	}
}

const traceJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[{"name":"mine"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[{"name":"secret"}]}]}
]}}`

func TestFilterTraceKeepsTheTenantsSpans(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(traceJSON), &body)
	if !FilterTrace(body, "grif-test", Related{}) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "secret") || !strings.Contains(string(out), "mine") {
		t.Errorf("got %s", out)
	}

	json.Unmarshal([]byte(traceJSON), &body)
	if FilterTrace(body, "grif-prod", Related{}) {
		t.Error("a trace without the tenant's spans is refused")
	}
	if FilterTrace(map[string]any{}, "grif-test", Related{}) {
		t.Error("no trace is refused")
	}
}

// A request through Cloudflare and Traefik to grif-test, which calls another app through Traefik; and another request's
// Traefik span in the same trace.
const edgeTraceJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge_processing"}}]},"scopeSpans":[{"spans":[
		{"spanId":"cf1","name":"cloudflare_request"},
		{"spanId":"cf2","parentSpanId":"cf1","name":"response"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"origin_fetch"}}]},"scopeSpans":[{"spans":[
		{"spanId":"of1","parentSpanId":"cf1","name":"origin"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
		{"spanId":"t1","parentSpanId":"of1","name":"router"},
		{"spanId":"t1b","parentSpanId":"t1","name":"ReverseProxy"},
		{"spanId":"t2","parentSpanId":"g2","name":"inner secret"},
		{"spanId":"t3","name":"unrelated secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"g1","parentSpanId":"t1b","name":"GET x"},
		{"spanId":"g2","parentSpanId":"g1","name":"call"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"other-app"}}]},"scopeSpans":[{"spans":[
		{"spanId":"o1","parentSpanId":"t2","name":"other secret"}]}]}
]}}`

func TestFilterTraceKeepsTheEdgeSpansTheTenantsSitUnder(t *testing.T) {
	edge := map[string]bool{"edge_processing": true, "origin_fetch": true, "traefik": true}
	var body map[string]any
	json.Unmarshal([]byte(edgeTraceJSON), &body)
	if !FilterTrace(body, "grif-test", Related{Edge: edge}) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	for _, name := range []string{"cloudflare_request", "response", "origin", "router", "ReverseProxy", "GET x", "call"} {
		if !strings.Contains(string(out), `"`+name+`"`) {
			t.Errorf("%s removed: %s", name, out)
		}
	}
	if strings.Contains(string(out), "secret") {
		t.Errorf("a span not leading to the tenant's left in: %s", out)
	}

	json.Unmarshal([]byte(edgeTraceJSON), &body)
	if FilterTrace(body, "grif-prod", Related{Edge: edge}) {
		t.Error("a trace with the edge's spans but not the tenant's is refused")
	}
	json.Unmarshal([]byte(edgeTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{})
	if out, _ := json.Marshal(body); strings.Contains(string(out), "router") {
		t.Errorf("without edge services only the tenant's spans: %s", out)
	}
}

// grif-test calls the Halo gateway, which another tenant's request uses too in the same trace (as if joined).
const downstreamTraceJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"g1","name":"GET x"},
		{"spanId":"g2","parentSpanId":"g1","name":"GET halo-gateway"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"halo-gateway"}}]},"scopeSpans":[{"spans":[
		{"spanId":"h1","parentSpanId":"g2","name":"GET /stats"},
		{"spanId":"h2","parentSpanId":"h1","name":"GET halo api"},
		{"spanId":"h3","parentSpanId":"p1","name":"prod secret"},
		{"spanId":"h4","name":"loose secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-prod"}}]},"scopeSpans":[{"spans":[
		{"spanId":"p1","name":"prod secret request"}]}]}
]}}`

func TestFilterTraceKeepsTheDownstreamSpansUnderTheTenants(t *testing.T) {
	related := Related{Downstream: map[string]bool{"halo-gateway": true}}
	var body map[string]any
	json.Unmarshal([]byte(downstreamTraceJSON), &body)
	if !FilterTrace(body, "grif-test", related) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	for _, name := range []string{"GET x", "GET halo-gateway", "GET /stats", "GET halo api"} {
		if !strings.Contains(string(out), `"`+name+`"`) {
			t.Errorf("%s removed: %s", name, out)
		}
	}
	if strings.Contains(string(out), "secret") {
		t.Errorf("a span not under the tenant's left in: %s", out)
	}

	// An edge-only setting keeps no downstream span, and a downstream one no edge span above the tenant's
	json.Unmarshal([]byte(downstreamTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"halo-gateway": true}})
	if out, _ := json.Marshal(body); strings.Contains(string(out), "GET /stats") {
		t.Errorf("an edge service's span under the tenant's kept: %s", out)
	}
	json.Unmarshal([]byte(edgeTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"traefik": true}})
	if out, _ := json.Marshal(body); strings.Contains(string(out), "router") || !strings.Contains(string(out), "inner secret") {
		t.Errorf("a downstream service kept above the tenant's, or not under it: %s", out)
	}
}

func TestFilterSearchNamesOnlyTheTenantsRootAndCounts(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"traces":[{"traceID":"a","rootServiceName":"edge_processing","rootTraceName":"another app's request",
		"serviceStats":{"grif-test":{"spanCount":1},"edge_processing":{"spanCount":4},"halo-gateway":{"spanCount":2}}}]}`), &body)
	FilterSearch(body, "grif-test", Related{Edge: map[string]bool{"edge_processing": true}, Downstream: map[string]bool{"halo-gateway": true}})
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "another app's request") || strings.Contains(string(out), "edge_processing") || strings.Contains(string(out), "halo-gateway") {
		t.Errorf("a root or count that may be another request's left in: %s", out)
	}
	if !strings.Contains(string(out), `"grif-test":{"spanCount":1}`) {
		t.Errorf("the tenant's count removed: %s", out)
	}
}

// Edge spans and the requests they belong to: one Cloudflare request fetching from two origins (grif-test and
// grif-prod), grif-prod calling grif-test through Traefik, and grif-test's browser span above Cloudflare's.
const edgeLeakJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge_processing"}}]},"scopeSpans":[{"spans":[
		{"spanId":"cf1","parentSpanId":"b1","name":"cloudflare_request"},
		{"spanId":"cf2","parentSpanId":"cf1","name":"response"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"origin_fetch"}}]},"scopeSpans":[{"spans":[
		{"spanId":"of1","parentSpanId":"cf1","name":"origin"},
		{"spanId":"of2","parentSpanId":"cf1","name":"prod origin secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
		{"spanId":"t1","parentSpanId":"of1","name":"router"},
		{"spanId":"t5","parentSpanId":"of2","name":"prod router secret"},
		{"spanId":"t6","parentSpanId":"p2","name":"prod call secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"b1","name":"browser click"},
		{"spanId":"g1","parentSpanId":"t1","name":"GET x"},
		{"spanId":"g9","parentSpanId":"t6","name":"called by prod"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-prod"}}]},"scopeSpans":[{"spans":[
		{"spanId":"p1","parentSpanId":"t5","name":"prod request"},
		{"spanId":"p2","parentSpanId":"p1","name":"prod call"}]}]}
]}}`

func TestFilterTraceKeepsOnlyTheEdgeSpansOfTheTenantsOwnRequests(t *testing.T) {
	edge := map[string]bool{"edge_processing": true, "origin_fetch": true, "traefik": true}
	var body map[string]any
	json.Unmarshal([]byte(edgeLeakJSON), &body)
	if !FilterTrace(body, "grif-test", Related{Edge: edge}) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	for _, name := range []string{"cloudflare_request", "response", "origin", "router", "GET x", "browser click", "called by prod"} {
		if !strings.Contains(string(out), `"`+name+`"`) {
			t.Errorf("%s removed: %s", name, out)
		}
	}
	if strings.Contains(string(out), "secret") {
		t.Errorf("another request's edge span left in: %s", out)
	}
}

// grif-test reuses grif-prod's span id p1, under which the Halo gateway serves prod's request (the tenant's span
// last, so an index that keeps the last span of an id takes it for the tenant's).
const duplicateIDJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-prod"}}]},"scopeSpans":[{"spans":[
		{"spanId":"p1","name":"prod request"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"p1","name":"forged"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"halo-gateway"}}]},"scopeSpans":[{"spans":[
		{"spanId":"h1","parentSpanId":"p1","name":"prod gateway secret"}]}]}
]}}`

func TestFilterTraceFollowsNoSpanIDTwoSpansShare(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(duplicateIDJSON), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"halo-gateway": true}})
	if out, _ := json.Marshal(body); strings.Contains(string(out), "secret") {
		t.Errorf("a span under a shared id left in: %s", out)
	}
}

func TestSetOf(t *testing.T) {
	got := setOf(" traefik, edge_processing,,origin_fetch ")
	if len(got) != 3 || !got["traefik"] || !got["edge_processing"] || !got["origin_fetch"] {
		t.Errorf("got %v", got)
	}
	if len(setOf("")) != 0 {
		t.Error("an empty list is no services")
	}
}

// --- The handlers

type fixedTenants map[string]string

func (f fixedTenants) Tenant(_ context.Context, ip string) (string, error) {
	if t, ok := f[ip]; ok {
		return t, nil
	}
	return "", fmt.Errorf("%w: %s", ErrUnknownCaller, ip)
}

type brokenTenants struct{}

func (brokenTenants) Tenant(context.Context, string) (string, error) {
	return "", fmt.Errorf("API down")
}

// upstream records what reached it and answers body.
func upstream(t *testing.T, status int, body string) (*url.URL, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u, &seen
}

func gate(u *url.URL, tenants Tenants) Gate {
	return Gate{Upstream: u, Client: http.DefaultClient, Tenants: tenants, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func call(h http.Handler, method, target, remote string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.RemoteAddr = remote + ":5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var tenants = fixedTenants{"10.0.1.5": "grif-test"}

func TestPrometheusHandler(t *testing.T) {
	u, seen := upstream(t, 200, `{"status":"success"}`)
	h := &Prometheus{Gate: gate(u, tenants), Label: "service_name"}

	rec := call(h, "GET", "/api/v1/query_range?query=up&start=1&end=2&step=15s&dedup=false", "10.0.1.5", nil)
	if rec.Code != 200 || rec.Body.String() != `{"status":"success"}` {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	got := (*seen)[0].URL.Query()
	if got.Get("query") != `up{service_name="grif-test"}` || got.Get("step") != "15s" || got.Has("dedup") {
		t.Errorf("upstream got %v", got)
	}

	rec = call(h, "POST", "/api/v1/query", "10.0.1.5", url.Values{"query": {`sum(x)`}})
	if rec.Code != 200 || (*seen)[1].URL.Query().Get("query") != `sum(x{service_name="grif-test"})` {
		t.Errorf("POST: %d, upstream got %v", rec.Code, (*seen)[1].URL.Query())
	}

	for path, want := range map[string]int{"/api/v1/series?match[]=up": 404, "/api/v1/labels": 404, "/federate": 404} {
		if rec := call(h, "GET", path, "10.0.1.5", nil); rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}
	if rec := call(h, "GET", "/api/v1/query?query=sum(", "10.0.1.5", nil); rec.Code != 400 {
		t.Errorf("bad query: %d", rec.Code)
	}
	if rec := call(h, "DELETE", "/api/v1/query?query=up", "10.0.1.5", nil); rec.Code != 405 {
		t.Errorf("DELETE: %d", rec.Code)
	}
	if rec := call(h, "GET", "/api/v1/query?query=up", "10.0.9.9", nil); rec.Code != 403 {
		t.Errorf("unknown caller: %d", rec.Code)
	}
	if len(*seen) != 2 {
		t.Errorf("refused requests reached upstream: %d", len(*seen))
	}

	broken := &Prometheus{Gate: gate(u, brokenTenants{}), Label: "service_name"}
	if rec := call(broken, "GET", "/api/v1/query?query=up", "10.0.1.5", nil); rec.Code != 503 {
		t.Errorf("API down: %d", rec.Code)
	}
}

func TestLokiHandler(t *testing.T) {
	u, seen := upstream(t, 200, `{"status":"success","data":{"result":[]}}`)
	h := &Loki{Gate: gate(u, tenants), Label: "service_name"}

	rec := call(h, "GET", "/loki/api/v1/query_range?"+url.Values{"query": {`{service_name="x"} |= "y"`}, "limit": {"10"}, "direction": {"backward"}}.Encode(), "10.0.1.5", nil)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	got := (*seen)[0].URL.Query()
	if got.Get("query") != `{service_name="grif-test", service_name="x"} |= "y"` || got.Get("limit") != "10" {
		t.Errorf("upstream got %v", got)
	}
	if rec := call(h, "GET", "/loki/api/v1/query?query="+url.QueryEscape(`sum(rate({a="b"}[1m]))`), "10.0.1.5", nil); rec.Code != 400 {
		t.Errorf("metric query: %d", rec.Code)
	}
	for _, path := range []string{"/loki/api/v1/labels", "/loki/api/v1/series", "/loki/api/v1/tail", "/loki/api/v1/push"} {
		if rec := call(h, "GET", path, "10.0.1.5", nil); rec.Code != 404 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if len(*seen) != 1 {
		t.Errorf("refused requests reached upstream: %d", len(*seen))
	}
}

func TestTempoHandler(t *testing.T) {
	search, seen := upstream(t, 200, `{"traces":[{"traceID":"a","rootServiceName":"traefik","rootTraceName":"secret","durationMs":12345678901234}]}`)
	h := &Tempo{Gate: gate(search, tenants)}

	rec := call(h, "GET", "/api/search?"+url.Values{"q": {`{status=error}`}, "limit": {"20"}, "tags": {"x"}}.Encode(), "10.0.1.5", nil)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	got := (*seen)[0].URL.Query()
	if got.Get("q") != `{resource.service.name = "grif-test" && (status=error)}` || got.Get("limit") != "20" || got.Has("tags") {
		t.Errorf("upstream got %v", got)
	}
	if strings.Contains(rec.Body.String(), "secret") || !strings.Contains(rec.Body.String(), "12345678901234") {
		t.Errorf("answer %s", rec.Body)
	}
	if rec := call(h, "GET", "/api/search?q="+url.QueryEscape(`{a=1} && {b=2}`), "10.0.1.5", nil); rec.Code != 400 {
		t.Errorf("two spansets: %d", rec.Code)
	}
	for _, path := range []string{"/api/search/tags", "/api/traces/abc", "/api/v2/traces/not-hex", "/api/v2/search/tag/x/values"} {
		if rec := call(h, "GET", path, "10.0.1.5", nil); rec.Code != 404 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}

	byID, _ := upstream(t, 200, traceJSON)
	h = &Tempo{Gate: gate(byID, tenants)}
	rec = call(h, "GET", "/api/v2/traces/0123abc", "10.0.1.5", nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "secret") || !strings.Contains(rec.Body.String(), "mine") {
		t.Errorf("trace: %d %s", rec.Code, rec.Body)
	}
	other := fixedTenants{"10.0.1.6": "grif-prod"}
	if rec := call(&Tempo{Gate: gate(byID, other)}, "GET", "/api/v2/traces/0123abc", "10.0.1.6", nil); rec.Code != 404 {
		t.Errorf("another tenant's trace: %d %s", rec.Code, rec.Body)
	}

	missing, _ := upstream(t, 404, `trace not found`)
	if rec := call(&Tempo{Gate: gate(missing, tenants)}, "GET", "/api/v2/traces/abc", "10.0.1.5", nil); rec.Code != 404 {
		t.Errorf("not found: %d", rec.Code)
	}
}

// --- Who is calling

func TestPodResolver(t *testing.T) {
	answers := map[string]string{
		"10.0.1.5": `{"items":[{"metadata":{"namespace":"grif-pr-12"},"spec":{}}]}`,
		"10.0.1.6": `{"items":[{"metadata":{"namespace":"kube-system"},"spec":{}}]}`,
		"192.0.2.4": `{"items":[{"metadata":{"namespace":"grif-prod"},"spec":{"hostNetwork":true}}]}`,
		"10.0.1.7": `{"items":[]}`,
	}
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer token" || r.URL.Query().Get("labelSelector") != "app=grif-backend" {
			w.WriteHeader(401)
			return
		}
		ip := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("fieldSelector"), "status.podIP="), ",status.phase=Running")
		io.WriteString(w, answers[ip])
	}))
	defer api.Close()
	r := newPodResolver(api.URL, "app=grif-backend", regexp.MustCompile(`^grif-(prod|staging|test|pr-[0-9]+)$`), api.Client(), func() (string, error) { return "token", nil })

	if tenant, err := r.Tenant(context.Background(), "10.0.1.5"); err != nil || tenant != "grif-pr-12" {
		t.Errorf("preview: %q %v", tenant, err)
	}
	r.Tenant(context.Background(), "10.0.1.5")
	if calls != 1 {
		t.Errorf("not cached: %d calls", calls)
	}
	for _, ip := range []string{"10.0.1.6", "192.0.2.4", "10.0.1.7"} {
		if _, err := r.Tenant(context.Background(), ip); err == nil || !strings.Contains(err.Error(), ErrUnknownCaller.Error()) {
			t.Errorf("%s: want unknown, got %v", ip, err)
		}
	}

	down := newPodResolver(api.URL, "app=other", regexp.MustCompile(`.*`), api.Client(), func() (string, error) { return "token", nil })
	if _, err := down.Tenant(context.Background(), "10.0.1.5"); err == nil || strings.Contains(err.Error(), ErrUnknownCaller.Error()) {
		t.Errorf("API refusing: want a transient error, got %v", err)
	}
	before := calls
	down.Tenant(context.Background(), "10.0.1.5")
	if calls != before+1 {
		t.Error("a transient error was cached")
	}
}
