// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"context"
	"strings"
)

// RecorderShim is a read-only inspection helper over a [Recorder]. It relies
// only on the monotonic local aggregate every concrete recorder maintains, so
// it works regardless of whether Prometheus registration succeeded. It is
// intended for tests and operational diagnostics, never on the hot path.
type RecorderShim struct {
	rec Recorder
}

// NewRecorderShim wraps a recorder for snapshot inspection.
func NewRecorderShim(rec Recorder) *RecorderShim {
	return &RecorderShim{rec: rec}
}

// Total returns the number of attempts recorded so far. Counters are
// monotonic, so this value never decreases.
func (s *RecorderShim) Total() int64 {
	var total int64
	for _, v := range s.snapshot() {
		total += v
	}
	return total
}

// ByReason aggregates counts by reason label.
func (s *RecorderShim) ByReason() map[string]int64 {
	return s.aggregate(func(parts []string) string { return parts[3] })
}

// ByOutcome aggregates counts by outcome label.
func (s *RecorderShim) ByOutcome() map[string]int64 {
	return s.aggregate(func(parts []string) string { return parts[1] })
}

// AccountLabels returns every distinct account bucket currently present. It
// lets tests assert both the cardinality bound and the absence of plaintext.
func (s *RecorderShim) AccountLabels() []string {
	seen := map[string]struct{}{}
	for key := range s.snapshot() {
		parts := strings.Split(key, "/")
		if len(parts) >= 6 {
			seen[parts[5]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func (s *RecorderShim) snapshot() map[string]int64 {
	if r, ok := s.rec.(*recorder); ok {
		return r.Snapshot()
	}
	// A no-op recorder has no observations.
	return map[string]int64{}
}

func (s *RecorderShim) aggregate(pick func(parts []string) string) map[string]int64 {
	out := map[string]int64{}
	for key, count := range s.snapshot() {
		parts := strings.Split(key, "/")
		if len(parts) < 7 {
			continue
		}
		out[pick(parts)] += count
	}
	return out
}

// Compile-time guard that the shim itself satisfies Recorder for contexts that
// want to pass it through unchanged.
var _ Recorder = (*RecorderShim)(nil)

// Record forwards to the wrapped recorder so the shim remains a drop-in.
func (s *RecorderShim) Record(ctx context.Context, a Attempt) { s.rec.Record(ctx, a) }
