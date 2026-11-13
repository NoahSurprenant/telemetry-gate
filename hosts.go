package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Hosts says which hosts a tenant serves: the evidence that an edge span (Cloudflare's request, Traefik's router) is
// one of the tenant's own requests (FilterTrace).
type Hosts interface {
	Hosts(ctx context.Context, tenant string) (map[string]bool, error)
}

// IngressRouteHosts reads the tenants' hosts from the Traefik IngressRoutes, cluster-wide: every Host(...) of their
// routes' rules (not a negated !Host, nor text inside another matcher's argument), as the IngressRoute's namespace's
// (the tenant's). A host more than one namespace claims is no one's: a tenant can't claim another's host as its own.
// One read serves every tenant for a few seconds, a failed one for less; reads are one at a time.
type IngressRouteHosts struct {
	api    string
	client *http.Client
	token  func() (string, error)

	mu       sync.Mutex
	byTenant map[string]map[string]bool
	err      error
	until    time.Time
}

// failedTTL keeps a failed read for a while (from when it ends), so a failing API isn't asked again on every trace.
var failedTTL = 5 * time.Second

// readTimeout bounds one read, which runs on a context of its own: every tenant shares it, so a caller that goes
// away mustn't cut it short.
const readTimeout = 10 * time.Second

func newIngressRouteHosts(api string, client *http.Client, token func() (string, error)) *IngressRouteHosts {
	return &IngressRouteHosts{api: api, client: client, token: token}
}

type ingressRouteList struct {
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Routes []struct {
				Match string `json:"match"`
			} `json:"routes"`
		} `json:"spec"`
	} `json:"items"`
}

func (h *IngressRouteHosts) Hosts(_ context.Context, tenant string) (map[string]bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if time.Now().After(h.until) {
		ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		h.byTenant, h.err = h.lookup(ctx)
		cancel()
		ttl := cacheTTL
		if h.err != nil {
			ttl = failedTTL
		}
		h.until = time.Now().Add(ttl)
	}
	if h.err != nil {
		return nil, h.err
	}
	return h.byTenant[tenant], nil
}

func (h *IngressRouteHosts) lookup(ctx context.Context) (map[string]map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.api+"/apis/traefik.io/v1alpha1/ingressroutes", nil)
	if err != nil {
		return nil, err
	}
	token, err := h.token()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ingressroutes: %s", resp.Status)
	}
	var list ingressRouteList
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&list); err != nil {
		return nil, err
	}
	claims := map[string]map[string]bool{}
	for _, item := range list.Items {
		for _, route := range item.Spec.Routes {
			for _, host := range routeHosts(route.Match) {
				if claims[host] == nil {
					claims[host] = map[string]bool{}
				}
				claims[host][item.Metadata.Namespace] = true
			}
		}
	}
	byTenant := map[string]map[string]bool{}
	for host, namespaces := range claims {
		if len(namespaces) != 1 {
			continue
		}
		for namespace := range namespaces {
			if byTenant[namespace] == nil {
				byTenant[namespace] = map[string]bool{}
			}
			byTenant[namespace][host] = true
		}
	}
	return byTenant, nil
}

// routeHosts reads a rule's Host(...) hosts, lower case, without a port or a trailing dot: each Host matcher's
// quoted arguments, outside any quoted text (another matcher's argument). A rule with a negation (!) anywhere outside
// quoted text claims nothing: what a negated Host covers isn't the tenant's.
func routeHosts(match string) []string {
	var hosts []string
	var quote byte
	for i := 0; i < len(match); i++ {
		c := match[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '`' || c == '"':
			quote = c
		case c == '!':
			return nil
		case strings.HasPrefix(match[i:], "Host(") && (i == 0 || !isIdent(match[i-1])):
			args, end := quotedArgs(match, i+len("Host("))
			for _, arg := range args {
				if host := normalHost(arg); host != "" {
					hosts = append(hosts, host)
				}
			}
			i = end
		}
	}
	return hosts
}

// quotedArgs reads a matcher's quoted arguments from start up to its closing parenthesis, and where that is.
func quotedArgs(match string, start int) ([]string, int) {
	var args []string
	for i := start; i < len(match); i++ {
		switch c := match[i]; c {
		case '`', '"':
			end := strings.IndexByte(match[i+1:], c)
			if end < 0 {
				return args, len(match)
			}
			args = append(args, match[i+1:i+1+end])
			i += end + 1
		case ')':
			return args, i
		}
	}
	return args, len(match)
}

func isIdent(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// normalHost is a host as hosts are compared: lower case, without a port or a trailing dot.
func normalHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
