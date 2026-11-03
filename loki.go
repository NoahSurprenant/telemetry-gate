package main

import (
	"errors"
	"net/http"
	"strings"
)

// Loki allows log queries only (a stream selector and its pipeline: no metric queries, whose many selectors would
// each need narrowing), the selector narrowed to Label="<tenant>".
type Loki struct {
	Gate
	Label string
}

func (l *Loki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/loki/api/v1/query_range" && r.URL.Path != "/loki/api/v1/query" {
		http.NotFound(w, r)
		return
	}
	tenant := l.tenant(w, r)
	if tenant == "" {
		return
	}
	values, ok := form(w, r)
	if !ok {
		return
	}
	query, err := EnforceLogQL(values.Get("query"), l.Label, tenant)
	if err != nil {
		l.refuse(w, r, tenant, err.Error())
		return
	}
	kept := only(values, "start", "end", "since", "time", "limit", "direction", "step")
	kept.Set("query", query)
	l.pass(w, r, tenant, r.URL.Path, kept)
}

var errLogQuery = errors.New("only log queries: a stream selector {...} and its pipeline")

// EnforceLogQL puts label="value" first in the query's stream selector. The query must be a log query: it starts with
// the selector, and neither the selector nor the pipeline has a brace, bracket or comment outside string literals
// (so no second selector, range or metric query can follow).
func EnforceLogQL(query, label, value string) (string, error) {
	query = strings.TrimSpace(query)
	end, ok := scanBraces(query)
	if !ok {
		return "", errLogQuery
	}
	selector, pipeline := strings.TrimSpace(query[1:end]), query[end+1:]
	bare, ok := outsideStrings(pipeline)
	if !ok || strings.ContainsAny(bare, "{}[]#") {
		return "", errLogQuery
	}
	enforced := label + "=" + quote(value)
	if selector != "" {
		enforced += ", " + selector
	}
	return "{" + enforced + "}" + pipeline, nil
}
