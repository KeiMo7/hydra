// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"github.com/prometheus/client_golang/prometheus"
)

// MetricName is the single new series introduced by this package. It is
// intentionally distinct from the existing http_* metrics: the HTTP
// middleware's names, labels and semantics are untouched, and this vector only
// appears when the feature is explicitly enabled.
const MetricName = "hydra_login_attempts_total"

var metricLabels = []string{
	"entry_point",
	"outcome",
	"category",
	"reason",
	"grant_type",
	"account_bucket",
	"source_bucket",
}

// metricsSet wraps the Prometheus counter and tolerates a failed
// registration (e.g. a custom registry in tests or a duplicate registration)
// so recording degrades to the local aggregate without returning an error.
type metricsSet struct {
	counter *prometheus.CounterVec
	active  bool
}

func newMetrics() *metricsSet {
	return &metricsSet{
		counter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: MetricName,
			Help: "Login-related authentication attempts classified by a bounded failure taxonomy.",
		}, metricLabels),
	}
}

// mustRegister tries the default registerer and reports any failure through
// onError while keeping the recorder usable.
func (m *metricsSet) mustRegister(onError func(error)) {
	if err := prometheus.Register(m.counter); err != nil {
		m.active = false
		if onError != nil {
			onError(err)
		}
		return
	}
	m.active = true
}

// observe increments the counter for a computed result. Label values are all
// pre-bounded, so cardinality is finite by construction.
func (m *metricsSet) observe(c computed) {
	if !m.active {
		return
	}
	// WithLabelValues panics only on the number of labels, which is fixed in
	// lock-step with metricLabels; the recorder's outer recover still guards
	// the login path defensively.
	m.counter.WithLabelValues(
		c.EntryPoint,
		c.Outcome,
		c.Category,
		c.Reason,
		c.GrantType,
		c.Account,
		c.Source,
	).Inc()
}

// Collector exposes the underlying vector for tests that use a private
// registry instead of the default one.
func (m *metricsSet) Collector() prometheus.Collector { return m.counter }
