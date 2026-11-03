package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxBody bounds what is read back from a backend to filter it (a trace by id, a search), and a request's form.
const maxBody = 64 << 20

// Gate is what the three sides share: the upstream, who the caller is, and passing a rewritten request on.
type Gate struct {
	Upstream *url.URL
	Client   *http.Client
	Tenants  Tenants
	Log      *slog.Logger
}

// tenant answers the caller's tenant, or writes the refusal and answers "".
func (g *Gate) tenant(w http.ResponseWriter, r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	tenant, err := g.Tenants.Tenant(r.Context(), host)
	if err != nil {
		if errors.Is(err, ErrUnknownCaller) {
			g.Log.Warn("refused: unknown caller", "remote", host, "path", r.URL.Path, "error", err)
			http.Error(w, "forbidden", http.StatusForbidden)
		} else {
			g.Log.Error("who is calling", "remote", host, "error", err)
			http.Error(w, "could not tell who is calling", http.StatusServiceUnavailable)
		}
		return ""
	}
	return tenant
}

// form reads GET and POST (form-encoded) parameters alike.
func form(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return nil, false
	}
	return r.Form, true
}

// only keeps the named parameters.
func only(values url.Values, names ...string) url.Values {
	kept := url.Values{}
	for _, n := range names {
		if v, ok := values[n]; ok {
			kept[n] = v
		}
	}
	return kept
}

func (g *Gate) refuse(w http.ResponseWriter, r *http.Request, tenant, why string) {
	g.Log.Warn("refused", "tenant", tenant, "path", r.URL.Path, "reason", why)
	http.Error(w, why, http.StatusBadRequest)
}

// fetch GETs the upstream path with the parameters.
func (g *Gate) fetch(r *http.Request, path string, query url.Values) (*http.Response, error) {
	u := *g.Upstream
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return g.Client.Do(req)
}

// pass sends the upstream's answer on as it is.
func (g *Gate) pass(w http.ResponseWriter, r *http.Request, tenant, path string, query url.Values) {
	resp, err := g.fetch(r, path, query)
	if err != nil {
		g.Log.Error("upstream", "tenant", tenant, "path", path, "error", err)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	g.Log.Info("passed", "tenant", tenant, "path", path, "status", resp.StatusCode)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// scanBraces finds, in s (which starts with '{'), the index of the '}' closing it. Inside it and up to it, braces
// appear only in string literals ("..." with backslash escapes, `...` raw); ok is false otherwise, or when a string or
// the brace is left open. A '#' outside strings (a LogQL comment) is refused too.
func scanBraces(s string) (end int, ok bool) {
	if !strings.HasPrefix(s, "{") {
		return 0, false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			j, ok := skipString(s, i)
			if !ok {
				return 0, false
			}
			i = j
		case '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				return 0, false
			}
			i += j + 1
		case '{', '#':
			return 0, false
		case '}':
			return i, true
		}
	}
	return 0, false
}

// outsideStrings is s without its string literals' contents, or ok false when one is left open.
func outsideStrings(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			j, ok := skipString(s, i)
			if !ok {
				return "", false
			}
			b.WriteString(`""`)
			i = j
		case '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				return "", false
			}
			b.WriteString("``")
			i += j + 1
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), true
}

// skipString: s[i] is '"'; the index of its closing quote.
func skipString(s string, i int) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j, true
		}
	}
	return 0, false
}

// quote is a double-quoted literal LogQL, PromQL and TraceQL all read back as value.
func quote(value string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(value) + `"`
}
