// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import "sync"

// Bounded labels shared by every bucketer. They keep the cardinality of
// exported series finite even when an attacker supplies arbitrary values:
// an empty value has its own bucket, an unparseable/unknown value has its own
// bucket, and every value that would exceed the cardinality cap collapses
// into a single overflow bucket.
const (
	// LabelEmpty is used when the bucketed value was absent.
	LabelEmpty = "empty"
	// LabelUnknown is used when a value was present but could not be parsed.
	LabelUnknown = "unknown"
	// LabelOverflow is the single bucket every value beyond the cap joins.
	LabelOverflow = "overflow"
)

// boundedMap is a concurrency-safe, insertion-ordered cache with a hard size
// cap. It is deliberately simpler than an LRU: the values it stores are
// deterministic derived labels, so recomputing an evicted entry is cheap, and
// FIFO eviction makes the overflow behaviour easy to reason about under load.
type boundedMap struct {
	mu    sync.Mutex
	cap   int
	order []string
	data  map[string]string
}

func newBoundedMap(capacity int) *boundedMap {
	if capacity < 4 {
		capacity = 4
	}
	return &boundedMap{cap: capacity, data: make(map[string]string, capacity)}
}

// lookupOrStore returns the stable label previously computed for raw, or
// computes it with derive, stores it and returns it. When the cache is full
// and raw was not already known, LabelOverflow is returned and nothing is
// stored, so the number of distinct labels never exceeds capacity+3 (the
// three fixed buckets are accounted for by callers when sizing the cap).
func (b *boundedMap) lookupOrStore(raw string, derive func(string) string) string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if label, ok := b.data[raw]; ok {
		return label
	}
	if len(b.order) >= b.cap {
		return LabelOverflow
	}
	label := derive(raw)
	b.data[raw] = label
	b.order = append(b.order, raw)
	return label
}

// len reports the number of cached entries. It is used by tests.
func (b *boundedMap) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.order)
}

// boundedSet is a concurrency-safe presence set with a hard cap. Add reports
// whether key was newly inserted. When the set is full, unknown keys are not
// stored but Add returns true so callers count rather than silently drop the
// attempt; duplicate detection remains exact for every key that fits.
type boundedSet struct {
	mu  sync.Mutex
	cap int
	set map[string]struct{}
}

func newBoundedSet(capacity int) *boundedSet {
	if capacity < 16 {
		capacity = 16
	}
	return &boundedSet{cap: capacity, set: make(map[string]struct{}, capacity)}
}

// Add returns (true, true) when the capacity was saturated (key not stored but
// should be treated as first-seen), (true, false) for a newly stored key, and
// (false, false) for a duplicate.
func (s *boundedSet) Add(key string) (firstSeen, saturated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.set[key]; ok {
		return false, false
	}
	if len(s.set) >= s.cap {
		return true, true
	}
	s.set[key] = struct{}{}
	return true, false
}

func (s *boundedSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.set)
}
