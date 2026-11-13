package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// routeHosts reads a rule as Traefik does (Go expressions): quoted text with its escapes, no comments, no negation,
// and nothing that could be one of the gate's own address names.
func TestRouteHosts(t *testing.T) {
	cases := []struct {
		rule string
		want []string
	}{
		{"Host(`a.example`)", []string{"a.example"}},
		{"Host(`a.example`, \"b.example\")", []string{"a.example", "b.example"}},
		{"Host( `s.example` ) && PathPrefix(`/x`)", []string{"s.example"}},
		// An escaped quote: the Host is inside Path's argument, as Traefik reads it
		{"Path(\"\\\"\") && Path(\"x Host(`esc.example`) \")", nil},
		// A negation hidden from a scanner that ignores escapes
		{"Path(\"\\\"\") && ! /*\"*/ Host(`x.example`)", nil},
		{"/* note */ Host(`c.example`)", nil},
		{"Host(`c.example`) // note", nil},
		{"ÄHost(`v.example`)", nil},
		{"Host(`[address:203.0.113.9]:80`)", nil},
		{"Host(`203.0.113.9`)", nil},
		{"Host(`a@b.example`)", nil},
		// A comment inside Host's arguments: Traefik routes only mine.example
		{"Host(/*\"victim.example\"*/ \"mine.example\")", nil},
		{"Host(\"mine.example\" /* ) && Host(\"victim.example\") */)", nil},
	}
	for _, c := range cases {
		if got := routeHosts(c.rule); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.rule, got, c.want)
		}
	}
}

// A rule the gate can't read still claims what it might route, so that host is no one's: another namespace can't
// take it alone with a rule Traefik never matches.
func TestIngressRouteHostsCountsAnUnreadableRulesHostsAsClaimed(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"items":[
			{"metadata":{"namespace":"grif-prod"},"spec":{"routes":[{"match":"Host(\u0060b.example\u0060) && !PathPrefix(\u0060/admin\u0060)"}]}},
			{"metadata":{"namespace":"grif-test"},"spec":{"routes":[{"match":"Host(\u0060b.example\u0060) && Header(\u0060X-No\u0060, \u00601\u0060)"}]}}]}`))
	}))
	defer api.Close()
	h := newIngressRouteHosts(api.URL, api.Client(), func() (string, error) { return "token", nil })
	if hosts, err := h.Hosts(context.Background(), "grif-test"); err != nil || hosts["b.example"] {
		t.Errorf("got %v %v", hosts, err)
	}
}

func TestIngressRouteHostsKeepsAFailedReadFromWhenItEnds(t *testing.T) {
	const ttl = 50 * time.Millisecond
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		time.Sleep(2 * ttl)
		w.WriteHeader(500)
	}))
	defer api.Close()
	h := newIngressRouteHosts(api.URL, api.Client(), func() (string, error) { return "token", nil })
	h.failedTTL = ttl
	h.Hosts(context.Background(), "grif-test")
	h.Hosts(context.Background(), "grif-test")
	if calls != 1 {
		t.Errorf("a read slower than failedTTL was read again at once: %d calls", calls)
	}
}

// A caller waiting for another's read gives up with its own context; the read goes on for the rest.
func TestIngressRouteHostsWaitsOnlyAsLongAsTheCaller(t *testing.T) {
	release := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Write([]byte(`{"items":[]}`))
	}))
	defer api.Close()
	defer close(release)
	h := newIngressRouteHosts(api.URL, api.Client(), func() (string, error) { return "token", nil })
	go h.Hosts(context.Background(), "grif-test")
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := h.Hosts(ctx, "grif-test"); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Errorf("got %v after %v", err, time.Since(start))
	}
}

const callerTraceJSON = `{"trace":{"resourceSpans":[
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
		{"spanId":"g","name":"mine"},
		{"spanId":"c1","parentSpanId":"g","name":"call 1"},
		{"spanId":"c2","parentSpanId":"g","name":"call 2"},
		{"spanId":"c3","parentSpanId":"g","name":"call 3"}]}]},
	{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"halo-gateway"}}]},"scopeSpans":[{"spans":[
		{"spanId":"h1","parentSpanId":"c1","name":"for me","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-test"}}]},
		{"spanId":"h1a","parentSpanId":"h1","name":"under for me"},
		{"spanId":"h2","parentSpanId":"c2","name":"prod's secret","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-prod"}}]},
		{"spanId":"h2a","parentSpanId":"h2","name":"under prod's secret"},
		{"spanId":"h3","parentSpanId":"c3","name":"no caller secret"}]}]}]}}`

// A downstream service's spans are kept only from one that names the tenant as its caller (the gateway's own record
// of the key it was called with): a tenant can't forge that, as it can its own span ids.
func TestFilterTraceKeepsDownstreamSpansOnlyOfTheTenantsOwnCalls(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(callerTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"halo-gateway": true}, Caller: "grunt.api_key"}, nil)
	out, _ := json.Marshal(body)
	if !strings.Contains(string(out), `"for me"`) || !strings.Contains(string(out), `"under for me"`) || strings.Contains(string(out), "secret") {
		t.Errorf("got %s", out)
	}

	// Without a caller attribute, no downstream span is the tenant's for sure: none kept
	json.Unmarshal([]byte(callerTraceJSON), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"halo-gateway": true}}, nil)
	if out, _ := json.Marshal(body); strings.Contains(string(out), "for me") {
		t.Errorf("without a caller attribute: %s", out)
	}
}

// Every hop of a downstream subtree names the tenant or no one: a gateway span for another tenant's request under one
// of the tenant's is not kept, nor anything under it.
func TestFilterTraceChecksTheCallerOnEveryDownstreamHop(t *testing.T) {
	var body map[string]any
	json.Unmarshal([]byte(`{"trace":{"resourceSpans":[
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"grif-test"}}]},"scopeSpans":[{"spans":[
			{"spanId":"c","name":"call"}]}]},
		{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"halo-gateway"}}]},"scopeSpans":[{"spans":[
			{"spanId":"h1","parentSpanId":"c","name":"for me","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-test"}}]},
			{"spanId":"h1a","parentSpanId":"h1","name":"inside for me"},
			{"spanId":"h2","parentSpanId":"h1","name":"prod's secret","attributes":[{"key":"grunt.api_key","value":{"stringValue":"grif-prod"}}]},
			{"spanId":"h2a","parentSpanId":"h2","name":"under prod's secret"}]}]}]}}`), &body)
	FilterTrace(body, "grif-test", Related{Downstream: map[string]bool{"halo-gateway": true}, Caller: "grunt.api_key"}, nil)
	out, _ := json.Marshal(body)
	if !strings.Contains(string(out), `"inside for me"`) || strings.Contains(string(out), "secret") {
		t.Errorf("got %s", out)
	}
}
