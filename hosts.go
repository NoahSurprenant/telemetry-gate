package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
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

// failedTTL keeps a failed read for a while, so a failing API isn't asked again on every trace.
const failedTTL = 5 * time.Second

var (
	// hostCall is a router rule's Host(...) matcher, not a negated one nor one inside another's quoted argument; its
	// arguments in the first group.
	hostCall = regexp.MustCompile("(?:^|[\\s(&|])Host\\(([^)]*)\\)")
	// hostArg is one of its arguments, backticked or double-quoted.
	hostArg = regexp.MustCompile("`([^`]*)`|\"([^\"]*)\"")
)

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

func (h *IngressRouteHosts) Hosts(ctx context.Context, tenant string) (map[string]bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if now := time.Now(); now.After(h.until) {
		h.byTenant, h.err = h.lookup(ctx)
		ttl := cacheTTL
		if h.err != nil {
			ttl = failedTTL
		}
		h.until = now.Add(ttl)
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

// routeHosts reads a rule's Host(...) hosts, lower case, without a trailing dot.
func routeHosts(match string) []string {
	var hosts []string
	for _, call := range hostCall.FindAllStringSubmatch(match, -1) {
		for _, arg := range hostArg.FindAllStringSubmatch(call[1], -1) {
			if host := normalHost(arg[1] + arg[2]); host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

// normalHost is a host as hosts are compared: lower case, without a port or a trailing dot.
func normalHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
