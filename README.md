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
| 3200 | Tempo | `/api/search`, `/api/v2/traces/{id}` | the filter becomes `{resource.service.name="<tenant>" && (...)}`: one spanset, no `trace:` or `parent.`, only `\| select(...)` after it. Other services' roots and service stats are removed from search results (the edge services' kept); a trace keeps the tenant's spans (404 when none), the edge spans they sit under and the downstream spans under them |

Everything else is a 404, a query that can't be narrowed a 400, an unknown caller a 403. `/healthz` is on 8081.

Settings (flag or environment): `LOKI_URL`, `PROMETHEUS_URL`, `TEMPO_URL` (each unset turns its port off),
`POD_SELECTOR`, `NAMESPACES`, `TENANT_LABEL` (default `service_name`), `EDGE_SERVICES`, `DOWNSTREAM_SERVICES`. It needs `get` and `list` on pods,
cluster-wide.

**Edge services** (`EDGE_SERVICES`, comma-separated, ex. `traefik,edge_processing,origin_fetch`): the ingress and the CDN in
front of the tenants. A trace fetched by id also keeps their spans that the tenant's spans sit under (Cloudflare's
request, Traefik's router) and those spans' own edge spans (Cloudflare's firewall and response), every field. Not
an edge span under the tenant's (the ingress the app calls another app through), and not another request's.

**Downstream services** (`DOWNSTREAM_SERVICES`, comma-separated, ex. `halo-gateway`): services the tenants call. A
trace fetched by id also keeps their spans under the tenant's (through downstream spans only), every field; not one
of another tenant's request in the same trace.
