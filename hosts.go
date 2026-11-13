package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

	// failedTTL keeps a failed read for a while (from when it ends), so a failing API isn't asked again on every trace.
	failedTTL time.Duration

	// turn is held by the one read at a time (and guards what follows); a caller waiting for it gives up with its
	// own context
	turn     chan struct{}
	byTenant map[string]map[string]bool
	err      error
	until    time.Time
}

// readTimeout bounds one read, which runs on a context of its own: every tenant shares it, so a caller that goes
// away mustn't cut it short.
const readTimeout = 10 * time.Second

func newIngressRouteHosts(api string, client *http.Client, token func() (string, error)) *IngressRouteHosts {
	return &IngressRouteHosts{api: api, client: client, token: token, failedTTL: 5 * time.Second, turn: make(chan struct{}, 1)}
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
	select {
	case h.turn <- struct{}{}:
	default:
		select {
		case h.turn <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer func() { <-h.turn }()
	if time.Now().After(h.until) {
		ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		h.byTenant, h.err = h.lookup(ctx)
		cancel()
		ttl := cacheTTL
		if h.err != nil {
			ttl = h.failedTTL
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
// quoted arguments, outside any quoted text (another matcher's argument), quoted text read as Traefik reads it (Go:
// backslash escapes in double quotes, none in backticks). A rule Traefik could read otherwise claims nothing: one
// with a negation (!) or a comment outside quoted text (what a negated Host covers isn't the tenant's), or with
// unterminated quoted text. Neither does an argument with an escape, or one that is an address or could be one of the
// gate's own address names (':', '[', ']', '@').
func routeHosts(match string) []string {
	var hosts []string
	for i := 0; i < len(match); i++ {
		switch c := match[i]; {
		case c == '`' || c == '"':
			_, end, ok := quoted(match, i)
			if !ok {
				return nil
			}
			i = end
		case c == '!' || strings.HasPrefix(match[i:], "/*") || strings.HasPrefix(match[i:], "//"):
			return nil
		case strings.HasPrefix(match[i:], "Host(") && (i == 0 || !isIdent(match[i-1])):
			args, end, ok := quotedArgs(match, i+len("Host("))
			if !ok {
				return nil
			}
			for _, arg := range args {
				if host := normalHost(arg); host != "" && !strings.ContainsAny(host, ":[]@\\") && net.ParseIP(host) == nil {
					hosts = append(hosts, host)
				}
			}
			i = end
		}
	}
	return hosts
}

// quoted reads the quoted text that starts at match[start] (a backtick or a double quote): its content and where it
// ends; not ok when it doesn't end.
func quoted(match string, start int) (string, int, bool) {
	q := match[start]
	for i := start + 1; i < len(match); i++ {
		switch match[i] {
		case '\\':
			if q == '"' {
				i++
			}
		case q:
			return match[start+1 : i], i, true
		}
	}
	return "", len(match), false
}

// quotedArgs reads a matcher's quoted arguments from start up to its closing parenthesis, and where that is; not ok
// when it doesn't close.
func quotedArgs(match string, start int) ([]string, int, bool) {
	var args []string
	for i := start; i < len(match); i++ {
		switch match[i] {
		case '`', '"':
			arg, end, ok := quoted(match, i)
			if !ok {
				return nil, len(match), false
			}
			args = append(args, arg)
			i = end
		case ')':
			return args, i, true
		}
	}
	return nil, len(match), false
}

// isIdent says whether c can be part of an identifier: a letter, a digit or '_', and any byte of a non-ASCII
// character (Go identifiers may have them).
func isIdent(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// normalHost is a host as hosts are compared: lower case, without a port or a trailing dot.
func normalHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
