package main

import (
	"net/http"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// Prometheus allows instant and range queries only, each selector in them narrowed to Label="<tenant>".
type Prometheus struct {
	Gate
	Label string
}

func (p *Prometheus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/query" && r.URL.Path != "/api/v1/query_range" {
		http.NotFound(w, r)
		return
	}
	tenant := p.tenant(w, r)
	if tenant == "" {
		return
	}
	values, ok := form(w, r)
	if !ok {
		return
	}
	query, err := EnforcePromQL(values.Get("query"), p.Label, tenant)
	if err != nil {
		p.refuse(w, r, tenant, err.Error())
		return
	}
	kept := only(values, "time", "start", "end", "step", "timeout")
	kept.Set("query", query)
	p.pass(w, r, tenant, r.URL.Path, kept)
}

// EnforcePromQL adds label="value" to every selector of the query (vector and range alike, in subqueries too). A
// selector's own matchers on the label stay, and both must hold.
func EnforcePromQL(query, label, value string) (string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}
	matcher := labels.MustNewMatcher(labels.MatchEqual, label, value)
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			vs.LabelMatchers = append(vs.LabelMatchers, matcher)
		}
		return nil
	})
	return expr.String(), nil
}
