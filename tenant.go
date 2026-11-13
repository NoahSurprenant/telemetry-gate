package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

const (
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	cacheTTL  = 15 * time.Second
)

// ErrUnknownCaller: the address is no pod the gate serves.
var ErrUnknownCaller = errors.New("not a pod this gate serves")

// Tenants says whose a source address is.
type Tenants interface {
	Tenant(ctx context.Context, ip string) (string, error)
}

// PodResolver finds the pod behind a source address with the Kubernetes API: a running pod with that IP, matching the
// label selector, in a namespace the pattern accepts, not on the host's network (whose address is the node's, shared).
// Its namespace is the tenant. Answers are kept for a few seconds.
type PodResolver struct {
	api        string
	selector   string
	namespaces *regexp.Regexp
	client     *http.Client
	token      func() (string, error)

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	tenant string
	err    error
	until  time.Time
}

func NewPodResolver(api, selector string, namespaces *regexp.Regexp) (*PodResolver, error) {
	client, token, err := kubeClient()
	if err != nil {
		return nil, err
	}
	return newPodResolver(api, selector, namespaces, client, token), nil
}

// kubeClient is a client for the Kubernetes API as the pod's service account: the cluster's CA, and its token.
func kubeClient() (*http.Client, func() (string, error), error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, nil, fmt.Errorf("no certificate in %s", caFile)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	return client, func() (string, error) {
		// Read each time: the kubelet rotates it.
		b, err := os.ReadFile(tokenFile)
		return string(b), err
	}, nil
}

func newPodResolver(api, selector string, namespaces *regexp.Regexp, client *http.Client, token func() (string, error)) *PodResolver {
	return &PodResolver{api: api, selector: selector, namespaces: namespaces, client: client, token: token, cache: map[string]cached{}}
}

type podList struct {
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
		} `json:"spec"`
	} `json:"items"`
}

func (r *PodResolver) Tenant(ctx context.Context, ip string) (string, error) {
	r.mu.Lock()
	if c, ok := r.cache[ip]; ok && time.Now().Before(c.until) {
		r.mu.Unlock()
		return c.tenant, c.err
	}
	r.mu.Unlock()

	tenant, err := r.lookup(ctx, ip)
	var transient *transientError
	if !errors.As(err, &transient) {
		r.mu.Lock()
		r.cache[ip] = cached{tenant, err, time.Now().Add(cacheTTL)}
		for k, c := range r.cache {
			if time.Now().After(c.until) {
				delete(r.cache, k)
			}
		}
		r.mu.Unlock()
	}
	return tenant, err
}

// transientError: the API couldn't answer; not cached.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func (r *PodResolver) lookup(ctx context.Context, ip string) (string, error) {
	q := url.Values{}
	q.Set("fieldSelector", "status.podIP="+ip+",status.phase=Running")
	q.Set("labelSelector", r.selector)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.api+"/api/v1/pods?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	token, err := r.token()
	if err != nil {
		return "", &transientError{err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.client.Do(req)
	if err != nil {
		return "", &transientError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &transientError{fmt.Errorf("pods: %s", resp.Status)}
	}
	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return "", &transientError{err}
	}

	tenant := ""
	for _, pod := range list.Items {
		if pod.Spec.HostNetwork || !r.namespaces.MatchString(pod.Metadata.Namespace) {
			continue
		}
		if tenant != "" && tenant != pod.Metadata.Namespace {
			return "", fmt.Errorf("%w: %s is in more than one namespace", ErrUnknownCaller, ip)
		}
		tenant = pod.Metadata.Namespace
	}
	if tenant == "" {
		return "", fmt.Errorf("%w: %s", ErrUnknownCaller, ip)
	}
	return tenant, nil
}
