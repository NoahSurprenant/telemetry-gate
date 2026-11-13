package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// IngressRouteHosts reads a tenant's hosts from the Traefik IngressRoutes in its namespace (the tenant): every
// Host(`...`) of their routes' rules. Answers are kept for a few seconds; a failed read is not.
type IngressRouteHosts struct {
	api    string
	client *http.Client
	token  func() (string, error)

	mu    sync.Mutex
	cache map[string]cachedHosts
}

type cachedHosts struct {
	hosts map[string]bool
	until time.Time
}

// hostRule matches a router rule's Host(`name`), the name in the first group.
var hostRule = regexp.MustCompile("Host\\(`([^`]+)`\\)")

func NewIngressRouteHosts(api string) (*IngressRouteHosts, error) {
	client, token, err := kubeClient()
	if err != nil {
		return nil, err
	}
	return newIngressRouteHosts(api, client, token), nil
}

func newIngressRouteHosts(api string, client *http.Client, token func() (string, error)) *IngressRouteHosts {
	return &IngressRouteHosts{api: api, client: client, token: token, cache: map[string]cachedHosts{}}
}

type ingressRouteList struct {
	Items []struct {
		Spec struct {
			Routes []struct {
				Match string `json:"match"`
			} `json:"routes"`
		} `json:"spec"`
	} `json:"items"`
}

func (h *IngressRouteHosts) Hosts(ctx context.Context, tenant string) (map[string]bool, error) {
	h.mu.Lock()
	if c, ok := h.cache[tenant]; ok && time.Now().Before(c.until) {
		h.mu.Unlock()
		return c.hosts, nil
	}
	h.mu.Unlock()

	hosts, err := h.lookup(ctx, tenant)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.cache[tenant] = cachedHosts{hosts, time.Now().Add(cacheTTL)}
	for k, c := range h.cache {
		if time.Now().After(c.until) {
			delete(h.cache, k)
		}
	}
	h.mu.Unlock()
	return hosts, nil
}

func (h *IngressRouteHosts) lookup(ctx context.Context, tenant string) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.api+"/apis/traefik.io/v1alpha1/namespaces/"+url.PathEscape(tenant)+"/ingressroutes", nil)
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
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	hosts := map[string]bool{}
	for _, item := range list.Items {
		for _, route := range item.Spec.Routes {
			for _, m := range hostRule.FindAllStringSubmatch(route.Match, -1) {
				hosts[strings.ToLower(m[1])] = true
			}
		}
	}
	return hosts, nil
}
