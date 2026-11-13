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
	"time"

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

	if !FilterSearch(body, "grif-test") {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "traefik") || strings.Contains(string(out), "router secret") {
		t.Errorf("other services left in: %s", out)
	}
	if !strings.Contains(string(out), `"rootTraceName":"GET x"`) {
		t.Errorf("the tenant's root removed: %s", out)
	}
	if !FilterSearch(map[string]any{}, "grif-test") {
		t.Error("an empty answer is kept")
	}
	if FilterSearch(map[string]any{"traces": "nonsense"}, "grif-test") {
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
	if !FilterTrace(body, "grif-test", Related{}, testHosts) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "secret") || !strings.Contains(string(out), "mine") {
		t.Errorf("got %s", out)
	}

	json.Unmarshal([]byte(traceJSON), &body)
	if FilterTrace(body, "grif-prod", Related{}, testHosts) {
		t.Error("a trace without the tenant's spans is refused")
	}
	if FilterTrace(map[string]any{}, "grif-test", Related{}, testHosts) {
		t.Error("no trace is refused")
	}
}

// A request through Cloudflare and Traefik to grif-test, which calls another app through Traefik; and another request's
// Traefik span in the same trace.
const edgeTraceJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge_processing"}}]},"scopeSpans":[{"spans":[
		{"spanId":"cf1","name":"cloudflare_request","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]},
		{"spanId":"cf2","parentSpanId":"cf1","name":"response"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"origin_fetch"}}]},"scopeSpans":[{"spans":[
		{"spanId":"of1","parentSpanId":"cf1","name":"origin"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
		{"spanId":"t1","parentSpanId":"of1","name":"router","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]},
		{"spanId":"t1b","parentSpanId":"t1","name":"ReverseProxy"},
		{"spanId":"t2","parentSpanId":"g2","name":"inner secret"},
		{"spanId":"t3","name":"unrelated secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"g1","parentSpanId":"t1b","name":"GET x"},
		{"spanId":"g2","parentSpanId":"g1","name":"call"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"other-app"}}]},"scopeSpans":[{"spans":[
		{"spanId":"o1","parentSpanId":"t2","name":"other secret"}]}]}
]}}`

// The hosts grif-test's IngressRoutes serve (Hosts).
var testHosts = map[string]bool{"grif-test.example": true}

func TestFilterTraceKeepsTheEdgeSpansTheTenantsSitUnder(t *testing.T) {
	edge := map[string]bool{"edge_processing": true, "origin_fetch": true, "traefik": true}
	var body map[string]any
	json.Unmarshal([]byte(edgeTraceJSON), &body)
	if !FilterTrace(body, "grif-test", Related{Edge: edge}, testHosts) {
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
	if FilterTrace(body, "grif-prod", Related{Edge: edge}, testHosts) {
		t.Error("a trace with the edge's spans but not the tenant's is refused")
	}
	json.Unmarshal([]byte(edgeTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{}, testHosts)
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
		{"spanId":"h1","parentSpanId":"g2","name":"GET /stats","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-test"}}]},
		{"spanId":"h2","parentSpanId":"h1","name":"GET halo api"},
		{"spanId":"h3","parentSpanId":"p1","name":"prod secret"},
		{"spanId":"h4","name":"loose secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-prod"}}]},"scopeSpans":[{"spans":[
		{"spanId":"p1","name":"prod secret request"}]}]}
]}}`

func TestFilterTraceKeepsTheDownstreamSpansUnderTheTenants(t *testing.T) {
	related := Related{Downstream: map[string]bool{"halo-gateway": true}, Caller: "grunt.api_key"}
	var body map[string]any
	json.Unmarshal([]byte(downstreamTraceJSON), &body)
	if !FilterTrace(body, "grif-test", related, testHosts) {
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
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"halo-gateway": true}}, testHosts)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "GET /stats") {
		t.Errorf("an edge service's span under the tenant's kept: %s", out)
	}
	json.Unmarshal([]byte(edgeTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"traefik": true}, Caller: "grunt.api_key"}, testHosts)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "router") {
		t.Errorf("a downstream service kept above the tenant's: %s", out)
	}
}

func TestFilterSearchNamesOnlyTheTenantsRootAndCounts(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"traces":[{"traceID":"a","rootServiceName":"edge_processing","rootTraceName":"another app's request",
		"serviceStats":{"grif-test":{"spanCount":1},"edge_processing":{"spanCount":4},"halo-gateway":{"spanCount":2}}}]}`), &body)
	FilterSearch(body, "grif-test")
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
		{"spanId":"cf1","parentSpanId":"b1","name":"shared request secret","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]},
		{"spanId":"cf2","parentSpanId":"cf1","name":"shared response secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"origin_fetch"}}]},"scopeSpans":[{"spans":[
		{"spanId":"of1","parentSpanId":"cf1","name":"origin"},
		{"spanId":"of2","parentSpanId":"cf1","name":"prod origin secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
		{"spanId":"t1","parentSpanId":"of1","name":"router","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]},
		{"spanId":"t5","parentSpanId":"of2","name":"prod router secret","attributes":[{"key":"server.address","value":{"stringValue":"prod.example"}}]},
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
	if !FilterTrace(body, "grif-test", Related{Edge: edge}, testHosts) {
		t.Fatal("want kept")
	}
	out, _ := json.Marshal(body)
	// The Cloudflare request fetched from two origins: it is prod's request's too, so its chain (whose top it is)
	// shows nothing, not even grif-test's own origin fetch and router under it
	for _, name := range []string{"GET x", "browser click", "called by prod"} {
		if !strings.Contains(string(out), `"`+name+`"`) {
			t.Errorf("%s removed: %s", name, out)
		}
	}
	if strings.Contains(string(out), "secret") || strings.Contains(string(out), `"router"`) || strings.Contains(string(out), `"origin"`) {
		t.Errorf("an edge span of a chain whose top is another request's left in: %s", out)
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
		{"spanId":"h1","parentSpanId":"p1","name":"prod gateway secret","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-test"}}]}]}]}
]}}`

// A second origin fetch whose app's spans aren't in the trace (not yet ingested, sampled out or untraced): its
// Traefik call has no callee here.
const missingCalleeJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge_processing"}}]},"scopeSpans":[{"spans":[
		{"spanId":"cf1","name":"shared request secret","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"origin_fetch"}}]},"scopeSpans":[{"spans":[
		{"spanId":"of1","parentSpanId":"cf1","name":"origin"},
		{"spanId":"of2","parentSpanId":"cf1","name":"other origin secret"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
		{"spanId":"t1","parentSpanId":"of1","name":"router","kind":"SPAN_KIND_SERVER","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]},
		{"spanId":"t5","parentSpanId":"of2","name":"other router secret","kind":"SPAN_KIND_SERVER"},
		{"spanId":"t5b","parentSpanId":"t5","name":"other proxy secret","kind":"SPAN_KIND_CLIENT"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"g1","parentSpanId":"t1","name":"GET x"}]}]}
]}}`

func TestFilterTraceTreatsACallWhoseCalleeIsMissingAsAnotherApps(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(missingCalleeJSON), &body)
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"edge_processing": true, "origin_fetch": true, "traefik": true}}, testHosts)
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "secret") {
		t.Errorf("a span of a request to an app not in the trace left in: %s", out)
	}
	if strings.Contains(string(out), `"router"`) || strings.Contains(string(out), `"origin"`) {
		t.Errorf("an edge span of a chain whose top leads elsewhere left in: %s", out)
	}
}

func TestFilterTraceEndsOnACycleOfEdgeSpans(t *testing.T) {
	for _, cycle := range []string{
		`{"spanId":"f","parentSpanId":"f","name":"loop"}`,
		`{"spanId":"f","parentSpanId":"e","name":"loop"},{"spanId":"e","parentSpanId":"f","name":"loop"}`,
	} {
		var body map[string]any
		json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
			{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[`+cycle+`]}]},
			{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
				{"spanId":"g","parentSpanId":"f","name":"mine"}]}]}]}}`), &body)
		done := make(chan bool, 1)
		go func() { done <- FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"traefik": true}}, testHosts) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: still filtering after 5s", cycle)
		}
		if out, _ := json.Marshal(body); strings.Contains(string(out), "loop") {
			t.Errorf("a cycle's spans left in: %s", out)
		}
	}
}

// edgeChain: n Traefik spans in a chain above grif-test's g, the top one carrying host.
func edgeChain(n int, host string) map[string]any {
	var spans []string
	for i := 0; i < n; i++ {
		parent := ""
		if i+1 < n {
			parent = fmt.Sprintf(`,"parentSpanId":"e%d"`, i+1)
		}
		attrs := ""
		if i+1 == n && host != "" {
			attrs = `,"attributes":[{"key":"server.address","value":{"stringValue":"` + host + `"}}]`
		}
		spans = append(spans, fmt.Sprintf(`{"spanId":"e%d"%s,"name":"edge %d"%s}`, i, parent, i, attrs))
	}
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[`+strings.Join(spans, ",")+`]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"g","parentSpanId":"e0","name":"mine"}]}]}]}}`), &body)
	return body
}

func TestFilterTraceShowsAnEdgeChainOnlyWithTheTenantsHost(t *testing.T) {
	traefik := Related{Edge: map[string]bool{"traefik": true}}
	shown := func(body map[string]any) bool {
		out, _ := json.Marshal(body)
		return strings.Contains(string(out), "edge 0")
	}
	cases := []struct {
		name  string
		body  map[string]any
		hosts map[string]bool
		want  bool
	}{
		{"the tenant's host", edgeChain(3, "grif-test.example"), testHosts, true},
		{"another host", edgeChain(3, "prod.example"), testHosts, false},
		{"no host at all", edgeChain(3, ""), testHosts, false},
		{"an address, not a host", edgeChain(3, "10.42.3.22"), map[string]bool{"10.42.3.22": true}, false},
		{"no hosts known (the lookup failed)", edgeChain(3, "grif-test.example"), nil, false},
		{"32 spans", edgeChain(32, "grif-test.example"), testHosts, true},
		{"33 spans", edgeChain(33, "grif-test.example"), testHosts, false},
		{"a port", edgeChain(3, "grif-test.example:443"), testHosts, true},
		{"a trailing dot, upper case", edgeChain(3, "GRIF-test.example."), testHosts, true},
	}
	for _, c := range cases {
		if FilterTrace(c.body, "grif-test", traefik, c.hosts); shown(c.body) != c.want {
			t.Errorf("%s: shown %v, want %v", c.name, !c.want, c.want)
		}
	}
}

func TestFilterTraceStopsAChainAtAnotherHost(t *testing.T) {
	// grif-test's own Traefik router, under the Cloudflare request of another host (another app's request that reached
	// grif-test): the chain's top is another host's, so none of it is shown
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge_processing"}}]},"scopeSpans":[{"spans":[
			{"spanId":"cf","name":"other request secret","attributes":[{"key":"server.address","value":{"stringValue":"prod.example"}}]}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
			{"spanId":"t","parentSpanId":"cf","name":"router","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"g","parentSpanId":"t","name":"mine"}]}]}]}}`), &body)
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"edge_processing": true, "traefik": true}}, testHosts)
	out, _ := json.Marshal(body)
	if strings.Contains(string(out), "secret") || strings.Contains(string(out), `"router"`) {
		t.Errorf("got %s", out)
	}
}

// A tenant's forged Traefik span naming its own host, under another request's host-less Cloudflare span: the chain's
// top (that request's root) names another host, so nothing is shown.
func TestFilterTraceTakesNoEvidenceFromBelowTheChainsTop(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"edge_processing"}}]},"scopeSpans":[{"spans":[
			{"spanId":"cf","name":"victim request secret","attributes":[{"key":"server.address","value":{"stringValue":"prod.example"}}]},
			{"spanId":"fw","parentSpanId":"cf","name":"victim firewall secret"}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
			{"spanId":"fake","parentSpanId":"fw","name":"forged secret","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"g","parentSpanId":"fake","name":"mine"}]}]}]}}`), &body)
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"edge_processing": true, "traefik": true}}, testHosts)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "secret") {
		t.Errorf("got %s", out)
	}
}

// The chain's top sits under a span not in the trace (a caller sampled out, not ingested, or a forged id): not shown.
func TestFilterTraceShowsNoChainUnderAMissingSpan(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
			{"spanId":"t","parentSpanId":"missing","name":"router","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"g","parentSpanId":"t","name":"mine"}]}]}]}}`), &body)
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"traefik": true}}, testHosts)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "router") {
		t.Errorf("got %s", out)
	}
}

func TestIngressRouteHosts(t *testing.T) {
	calls := 0
	failing := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer token" || r.URL.Path != "/apis/traefik.io/v1alpha1/ingressroutes" || failing {
			w.WriteHeader(500)
			return
		}
		io.WriteString(w, strings.ReplaceAll(`{"items":[
			{"metadata":{"namespace":"grif-test"},"spec":{"routes":[
				{"match":"Host(´grif-test.example´)"},
				{"match":"Host(´grif-test.example´) && PathRegexp(´^/hub/´)"},
				{"match":"(Host(´a.example´) || Host(\"b.example\")) && PathPrefix(´/x´)"},
				{"match":"Host(´m1.example´, ´m2.example´)"},
				{"match":"Host( ´s.example´ )"},
				{"match":"!Host(´grif.prod´)"},
				{"match":"Header(\"X-Note\", \"Host(´fake.example´)\")"},
				{"match":"Host(´shared.example´)"},
				{"match":"! Host(´neg1.example´)"},
				{"match":"!(Host(´neg2.example´) || Host(´neg3.example´))"},
				{"match":"Header(\"X-Note\", \"a Host(´nested.example´)\")"}]}},
			{"metadata":{"namespace":"grif-prod"},"spec":{"routes":[
				{"match":"Host(´grif.prod´) || Host(´shared.example´)"}]}}]}`, "´", "`"))
	}))
	defer api.Close()
	h := newIngressRouteHosts(api.URL, api.Client(), func() (string, error) { return "token", nil })

	got, err := h.Hosts(context.Background(), "grif-test")
	want := []string{"grif-test.example", "a.example", "b.example", "m1.example", "m2.example", "s.example"}
	if err != nil || len(got) != len(want) {
		t.Errorf("got %v %v", got, err)
	}
	for _, host := range want {
		if !got[host] {
			t.Errorf("%s missing from %v", host, got)
		}
	}
	if prod, _ := h.Hosts(context.Background(), "grif-prod"); len(prod) != 1 || !prod["grif.prod"] {
		t.Errorf("prod: %v (a host two namespaces claim is neither's)", prod)
	}
	if calls != 1 {
		t.Errorf("one cluster-wide read, cached: %d calls", calls)
	}

	failing = true
	broken := newIngressRouteHosts(api.URL, api.Client(), func() (string, error) { return "token", nil })
	before := calls
	if got, err := broken.Hosts(context.Background(), "grif-test"); err == nil || got != nil {
		t.Errorf("API failing: want an error and no hosts, got %v %v", got, err)
	}
	broken.Hosts(context.Background(), "grif-test")
	if calls != before+1 {
		t.Errorf("a failed read is kept briefly: %d calls", calls-before)
	}
}

func TestIngressRouteHostsReadsOnItsOwnContext(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.ReplaceAll(`{"items":[{"metadata":{"namespace":"grif-test"},"spec":{"routes":[{"match":"Host(´grif-test.example´)"}]}}]}`, "´", "`"))
	}))
	defer api.Close()
	h := newIngressRouteHosts(api.URL, api.Client(), func() (string, error) { return "token", nil })
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	// A caller that went away doesn't spoil the read every tenant shares
	if hosts, err := h.Hosts(gone, "grif-test"); err != nil || !hosts["grif-test.example"] {
		t.Errorf("got %v %v", hosts, err)
	}
}

// A forged wide trace: an edge span with the tenant's host, many of the tenant's spans under it, and a long line of
// edge spans under it too. Filtering stays quick.
func TestFilterTraceStaysQuickOnAWideForgedTrace(t *testing.T) {
	const tenantSpans, line = 20000, 70
	var edge, mine []string
	edge = append(edge, `{"spanId":"top","name":"top","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]}`)
	for i := 0; i < tenantSpans; i++ {
		mine = append(mine, fmt.Sprintf(`{"spanId":"m%d","parentSpanId":"top","name":"mine"}`, i))
	}
	for i := 0; i < line; i++ {
		parent := "top"
		if i > 0 {
			parent = fmt.Sprintf("l%d", i-1)
		}
		edge = append(edge, fmt.Sprintf(`{"spanId":"l%d","parentSpanId":"%s","name":"line"}`, i, parent))
	}
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[`+strings.Join(mine, ",")+`]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[`+strings.Join(edge, ",")+`]}]}]}}`), &body)
	done := make(chan bool, 1)
	go func() { done <- FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"traefik": true}}, testHosts) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("still filtering after 5s")
	}
}

// An edge span that is no client call naming an address (not a host) is another origin's, not the tenant's.
func TestFilterTraceTakesAnAddressOnAnEdgeServerSpanForAnotherOrigin(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[
			{"spanId":"top","name":"router","attributes":[{"key":"server.address","value":{"stringValue":"grif-test.example"}}]},
			{"spanId":"by-ip","parentSpanId":"top","name":"another origin secret","kind":"SPAN_KIND_SERVER","attributes":[{"key":"server.address","value":{"stringValue":"203.0.113.9"}}]},
			{"spanId":"proxy","parentSpanId":"top","name":"proxy","kind":"SPAN_KIND_CLIENT","attributes":[{"key":"server.address","value":{"stringValue":"10.42.3.22"}}]}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"g","parentSpanId":"proxy","name":"mine"}]}]}]}}`), &body)
	FilterTrace(body, "grif-test", Related{Edge: map[string]bool{"traefik": true}}, testHosts)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "secret") {
		t.Errorf("got %s", out)
	}
}

func TestTempoTraceReadsNoHostsWithoutTheTenantsSpans(t *testing.T) {
	u, _ := upstream(t, 200, `{"trace":{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"traefik"}}]},"scopeSpans":[{"spans":[{"spanId":"t","name":"x"}]}]}]}}`)
	hosts := &countingHosts{}
	h := &Tempo{Gate: gate(u, tenants), Related: Related{Edge: map[string]bool{"traefik": true}}, Hosts: hosts}
	if rec := call(h, "GET", "/api/v2/traces/0123abc", "10.0.1.5", nil); rec.Code != 404 || hosts.calls != 0 {
		t.Errorf("got %d, %d host reads", rec.Code, hosts.calls)
	}
}

// grif-prod calls grif-test, sending its client span's id p9; grif-test copies p9 as a span of its own, under which
// prod's own call to the Halo gateway would sit. The gateway's spans there aren't grif-test's.
func TestFilterTraceKeepsNoDownstreamSpanUnderACallersCopiedSpan(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"p9","name":"copied","kind":"SPAN_KIND_CLIENT"},
			{"spanId":"g","parentSpanId":"p9","name":"mine","kind":"SPAN_KIND_SERVER"}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"halo-gateway"}}]},"scopeSpans":[{"spans":[
			{"spanId":"h","parentSpanId":"p9","name":"prod gateway secret","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-prod"}}]}]}]}]}`), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"halo-gateway": true}, Caller: "grunt.api_key"}, testHosts)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "secret") {
		t.Errorf("got %s", out)
	}
}

type countingHosts struct{ calls int }

func (c *countingHosts) Hosts(context.Context, string) (map[string]bool, error) {
	c.calls++
	return testHosts, nil
}

func TestTempoTraceReadsNoHostsWithoutEdgeSpans(t *testing.T) {
	u, _ := upstream(t, 200, traceJSON)
	hosts := &countingHosts{}
	h := &Tempo{Gate: gate(u, tenants), Related: Related{Edge: map[string]bool{"edge_processing": true}}, Hosts: hosts}
	if rec := call(h, "GET", "/api/v2/traces/0123abc", "10.0.1.5", nil); rec.Code != 200 || hosts.calls != 0 {
		t.Errorf("got %d, %d host reads", rec.Code, hosts.calls)
	}
}

type failingHosts struct{}

func (failingHosts) Hosts(context.Context, string) (map[string]bool, error) { return nil, fmt.Errorf("API down") }

func TestTempoTraceShowsNoEdgeSpansWhenTheHostsCantBeRead(t *testing.T) {
	u, _ := upstream(t, 200, edgeTraceJSON)
	h := &Tempo{Gate: gate(u, tenants), Related: Related{Edge: map[string]bool{"edge_processing": true, "origin_fetch": true, "traefik": true}}, Hosts: failingHosts{}}
	rec := call(h, "GET", "/api/v2/traces/0123abc", "10.0.1.5", nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "cloudflare_request") || !strings.Contains(rec.Body.String(), "GET x") {
		t.Errorf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestCheckRelated(t *testing.T) {
	namespaces := regexp.MustCompile(`^grif-(prod|test)$`)
	if err := checkRelated(Related{Edge: map[string]bool{"traefik": true}, Downstream: map[string]bool{"halo-gateway": true}, Caller: "grunt.api_key"}, namespaces); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := checkRelated(Related{Downstream: map[string]bool{"halo-gateway": true}}, namespaces); err == nil {
		t.Error("downstream services without a caller attribute are accepted")
	}
	if err := checkRelated(Related{Edge: map[string]bool{"traefik": true}, Downstream: map[string]bool{"traefik": true}}, namespaces); err == nil {
		t.Error("a service in both lists is accepted")
	}
	if err := checkRelated(Related{Edge: map[string]bool{"grif-test": true}}, namespaces); err == nil {
		t.Error("a tenant as an edge service is accepted")
	}
}

func TestFilterTraceFollowsNoSpanIDTwoSpansShare(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(duplicateIDJSON), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"halo-gateway": true}, Caller: "grunt.api_key"}, testHosts)
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
