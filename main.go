// Command telemetry-gate stands between an application and Loki, Prometheus and Tempo, and lets each caller read back
// only its own telemetry.
//
// Who the caller is comes from the cluster, not from the request: the source address is looked up among the pods
// (one matching -pod-selector, in a namespace matching -namespaces), and the pod's namespace is its tenant. Every
// query is then rewritten so it can only match that tenant: -label="<tenant>" on each PromQL selector and on the
// LogQL stream selector, resource.service.name="<tenant>" around the TraceQL filter. A trace fetched by id keeps
// only the tenant's spans. Anything else (other endpoints, metric LogQL, trace-level TraceQL) is refused.
//
// Each backend has its own port, so a client needs only its base URL changed.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		lokiURL       = flag.String("loki-url", env("LOKI_URL", ""), "Loki (or its gateway)")
		prometheusURL = flag.String("prometheus-url", env("PROMETHEUS_URL", ""), "Prometheus")
		tempoURL      = flag.String("tempo-url", env("TEMPO_URL", ""), "Tempo's HTTP API")
		lokiAddr      = flag.String("loki-listen", ":3100", "where the Loki side listens")
		promAddr      = flag.String("prometheus-listen", ":9090", "where the Prometheus side listens")
		tempoAddr     = flag.String("tempo-listen", ":3200", "where the Tempo side listens")
		healthAddr    = flag.String("health-listen", ":8081", "liveness and readiness (/healthz)")
		podSelector   = flag.String("pod-selector", env("POD_SELECTOR", "app=grif-backend"), "label selector a caller's pod must match")
		namespaces    = flag.String("namespaces", env("NAMESPACES", `^grif-(prod|staging|test|pr-[0-9]+)$`), "regexp a caller's namespace must match")
		label         = flag.String("label", env("TENANT_LABEL", "service_name"), "the Prometheus and Loki label that carries the tenant")
		edgeServices  = flag.String("edge-services", env("EDGE_SERVICES", ""), "comma-separated service.names in front of the tenants (ingress, CDN) whose spans a trace keeps where the tenant's sit under them")
		apiServer     = flag.String("api-server", env("KUBERNETES_API", "https://kubernetes.default.svc"), "the Kubernetes API")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	pattern, err := regexp.Compile(*namespaces)
	if err != nil {
		log.Error("bad -namespaces", "error", err)
		os.Exit(2)
	}
	pods, err := NewPodResolver(*apiServer, *podSelector, pattern)
	if err != nil {
		log.Error("no Kubernetes API", "error", err)
		os.Exit(2)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	type side struct {
		addr     string
		upstream string
		build    func(*url.URL) http.Handler
	}
	g := func(u *url.URL) Gate { return Gate{Upstream: u, Client: client, Tenants: pods, Log: log} }
	sides := []side{
		{*lokiAddr, *lokiURL, func(u *url.URL) http.Handler { return &Loki{Gate: g(u), Label: *label} }},
		{*promAddr, *prometheusURL, func(u *url.URL) http.Handler { return &Prometheus{Gate: g(u), Label: *label} }},
		{*tempoAddr, *tempoURL, func(u *url.URL) http.Handler { return &Tempo{Gate: g(u), Edge: setOf(*edgeServices)} }},
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var servers []*http.Server
	health := http.NewServeMux()
	health.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	servers = append(servers, &http.Server{Addr: *healthAddr, Handler: health, ReadHeaderTimeout: 10 * time.Second})
	for _, s := range sides {
		if s.upstream == "" {
			continue
		}
		u, err := url.Parse(s.upstream)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			log.Error("bad upstream URL", "url", s.upstream)
			os.Exit(2)
		}
		servers = append(servers, &http.Server{Addr: s.addr, Handler: s.build(u), ReadHeaderTimeout: 10 * time.Second})
		log.Info("gating", "listen", s.addr, "upstream", s.upstream)
	}

	for _, s := range servers {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("listen", "addr", s.Addr, "error", err)
				stop()
			}
		}(s)
	}
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(shutdown)
	}
}

func env(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

// setOf reads a comma-separated list, blanks dropped.
func setOf(list string) map[string]bool {
	set := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		if item = strings.TrimSpace(item); item != "" {
			set[item] = true
		}
	}
	return set
}
