// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// fileSink is the degradation path used when Prometheus exposition is
// unavailable or as an always-on bounded audit copy. It appends one JSON
// object per attempt to a local file, throttled to a fixed number of lines per
// minute. Every operation is best-effort: a missing path, a full disk or a bad
// line is swallowed (and logged once) rather than propagated, because the sink
// sits on the authentication hot path.
type fileSink struct {
	path         string
	maxPerMinute int

	mu      sync.Mutex
	file    *os.File
	window  time.Time
	windowN int
}

func newFileSink(path string, maxPerMinute int) *fileSink {
	return &fileSink{path: path, maxPerMinute: maxPerMinute}
}

// append writes one JSONL line for the result when the sink is enabled and the
// per-minute budget has not been exhausted.
func (s *fileSink) append(c computed, logger Logger) {
	if s.path == "" || s.maxPerMinute <= 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if s.window.IsZero() || now.Sub(s.window) >= time.Minute {
		s.window = now
		s.windowN = 0
	}
	if s.windowN >= s.maxPerMinute {
		return
	}

	f, err := s.openLocked()
	if err != nil {
		if logger != nil {
			logger.Warnf("loginstats: fallback sink unavailable: %s", err)
		}
		return
	}

	line, err := json.Marshal(struct {
		TS         time.Time `json:"ts"`
		EntryPoint string    `json:"entry_point"`
		Outcome    string    `json:"outcome"`
		Category   string    `json:"category"`
		Reason     string    `json:"reason"`
		GrantType  string    `json:"grant_type"`
		Account    string    `json:"account_bucket"`
		Source     string    `json:"source_bucket"`
	}{
		TS:         now,
		EntryPoint: c.EntryPoint,
		Outcome:    c.Outcome,
		Category:   c.Category,
		Reason:     c.Reason,
		GrantType:  c.GrantType,
		Account:    c.Account,
		Source:     c.Source,
	})
	if err != nil {
		return
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil && logger != nil {
		logger.Warnf("loginstats: fallback sink write failed: %s", err)
		return
	}
	s.windowN++
}

// openLocked opens the file lazily. Caller must hold s.mu.
func (s *fileSink) openLocked() (*os.File, error) {
	if s.file != nil {
		return s.file, nil
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.file = f
	return f, nil
}

// close releases the underlying handle. Used by tests and on shutdown.
func (s *fileSink) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}
