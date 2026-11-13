# telemetry-gate

Stands between an application and Loki, Prometheus and Tempo, and lets each caller read back only its own
telemetry. Built for GrifballWebApp's Telemetry page: if the app (or a PR preview running unreviewed code) were
compromised, it still couldn't read anything but its own logs, metrics and traces.

**Who's calling** comes from the cluster, not the request: the source IP is looked up among running pods matching
`-pod-selector` (default `app=grif-backend`) in a namespace matching `-namespaces`, never a host-network pod. The
pod's namespace is the tenant; the app's `service.name` must equal it.

| Port | Backend | Allowed | Enforced |
|---|---|---|---|
| 9090 | Prometheus | `/api/v1/query`, `/api/v1/query_range` | `service_name="<tenant>"` added to every selector (parsed with Prometheus' own parser) |
| 3100 | Loki | `/loki/api/v1/query`, `/loki/api/v1/query_range`, log queries only | `service_name="<tenant>"` first in the stream selector; no second selector, range or metric query can follow |
| 3200 | Tempo | `/api/search`, `/api/v2/traces/{id}` | the filter becomes `{resource.service.name="<tenant>" && (...)}`: one spanset, no `trace:` or `parent.`, only `\| select(...)` after it. Other services' roots and service stats are removed from search results; a trace keeps the tenant's spans (404 when none), and of the edge and downstream services' spans those of the tenant's own requests (below) |

Everything else is a 404, a query that can't be narrowed a 400, an unknown caller a 403. `/healthz` is on 8081.

Settings (flag or environment): `LOKI_URL`, `PROMETHEUS_URL`, `TEMPO_URL` (each unset turns its port off),
`POD_SELECTOR`, `NAMESPACES`, `TENANT_LABEL` (default `service_name`), `EDGE_SERVICES`, `DOWNSTREAM_SERVICES`, `DOWNSTREAM_CALLER_ATTRIBUTE`. It needs `get` and `list` on pods,
cluster-wide (and on `ingressroutes.traefik.io` with `EDGE_SERVICES`).

**Edge services** (`EDGE_SERVICES`, comma-separated, ex. `traefik,edge_processing,origin_fetch`): the ingress and the CDN in
front of the tenants. A trace fetched by id also keeps, every field, the chain of edge spans a tenant's span sits
under, only when:

- its top (the request's own root: Cloudflare's request, or Traefik's router without Cloudflare) names one of the
  tenant's hosts in `server.address` (port and trailing dot aside). That is the evidence it is the tenant's request,
  and a tenant can't forge a span above it;
- that top starts the trace or sits under the tenant's own span (its browser's): not under another service's span,
  nor one missing from the trace (sampled out, not ingested, forged);
- none of it names another host or leads to another app: through edge spans, no other service's span, no other
  host, no shared id, no cycle, nothing deeper than 64, and no client call whose callee isn't in the trace;
- it is at most 32 spans long.

Then their edge descendants that lead to no other app and name no other host (Cloudflare's firewall and response).

A tenant's hosts are the `Host(...)` matchers' quoted arguments of the Traefik IngressRoutes in its namespace
(read as Traefik reads rules: quoted text with Go escapes; a rule with a `!` or a comment outside quoted text,
anywhere in it, or unterminated quoted text, gives no hosts, and neither does an argument that is an address or holds
`:`, `[`, `]`, `@` or an escape. Such a rule still claims every quoted string in it, so a host it might route is no
one's), read cluster-wide from the Kubernetes
API on a context of the gate's own (kept 15s, a failed read 5s from when it ends, one read at a time). A host more
than one namespace claims is no one's (so a namespace can hide another's edge spans by claiming its host, never show
its own). An IP address in `server.address` is no host: on a client call (Traefik's proxying) it is ignored, on any
other edge span it is another origin's. When the hosts can't be read, or the trace has no edge span or none of the
tenant's, nothing is read and no edge span kept. Needs `get` and `list` on `ingressroutes.traefik.io`, cluster-wide. Startup refuses a service in both
lists or named like a tenant.

**Downstream services** (`DOWNSTREAM_SERVICES`, comma-separated, ex. `halo-gateway`): services the tenants call. A
trace fetched by id also keeps their spans under the tenant's, through downstream spans only, from one whose caller
attribute (`DOWNSTREAM_CALLER_ATTRIBUTE`, ex. `grunt.api_key`: the gateway's record of the API key it was called
with) names the tenant, and each hop below it names the tenant or no one. A tenant writes its own span ids and could copy another's to sit over that one's calls; it
can't make the downstream service name it. Without the attribute no downstream span is kept, and startup refuses
downstream services without one. The Halo gateway's key names are grif-prod, grif-staging and grif-test; the PR
previews share one key (grif-previews, not their namespace), so a preview sees no gateway spans.

Spans come from every service in a trace, a tenant's included, so a span id two spans share links nothing: one
could otherwise reuse another's id to sit under or over its spans. With neither setting, a trace keeps only the
tenant's spans.
