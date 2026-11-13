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
`POD_SELECTOR`, `NAMESPACES`, `TENANT_LABEL` (default `service_name`), `EDGE_SERVICES`, `DOWNSTREAM_SERVICES`. It needs `get` and `list` on pods,
cluster-wide (and on `ingressroutes.traefik.io` with `EDGE_SERVICES`).

**Edge services** (`EDGE_SERVICES`, comma-separated, ex. `traefik,edge_processing,origin_fetch`): the ingress and the CDN in
front of the tenants. A trace fetched by id also keeps, every field, the edge spans a tenant's span sits under, from
the tenant's span up, while each leads to no other app (through edge spans: no other service's span, no other
host, no shared id, no cycle, nothing deeper than 64, and no client call whose callee isn't in the trace) and
names no host but the tenant's, and only when one of them names one of the tenant's hosts (`server.address` on
Cloudflare's request and Traefik's router): the evidence that it is the tenant's own request. A tenant's hosts
are the `Host(...)` rules of the Traefik IngressRoutes in its namespace, read from the Kubernetes API (kept 15s);
when they can't be read, no edge span is kept. Then their edge descendants that lead to no other app and name no
other host (Cloudflare's firewall and response). Not a chain under another service's span, nor one with a cycle or
longer than 32 spans. Needs `get` and `list` on `ingressroutes.traefik.io` too. Startup refuses a service in both
lists or named like a tenant.

**Downstream services** (`DOWNSTREAM_SERVICES`, comma-separated, ex. `halo-gateway`): services the tenants call. A
trace fetched by id also keeps their spans under the tenant's, through downstream spans only (a gateway reached
through the ingress is not kept).

Spans come from every service in a trace, a tenant's included, so a span id two spans share links nothing: one
could otherwise reuse another's id to sit under or over its spans. With neither setting, a trace keeps only the
tenant's spans.
