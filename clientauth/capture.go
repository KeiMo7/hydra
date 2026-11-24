// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clientauth

import (
	"context"
	"sync"
)

// CaptureExporter is a concurrency-safe EventExporter for tests and embedded
// audit pipelines. It stores only sanitized Event values.
type CaptureExporter struct {
	mu     sync.RWMutex
	events []Event
}

// NewCaptureExporter creates an empty capture exporter.
func NewCaptureExporter() *CaptureExporter {
	return &CaptureExporter{}
}

// ExportClientAuthenticationEvent implements EventExporter.
func (e *CaptureExporter) ExportClientAuthenticationEvent(_ context.Context, event Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, event)
}

// Events returns a copy of all captured events.
func (e *CaptureExporter) Events() []Event {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Event(nil), e.events...)
}

// Len returns the current number of captured events.
func (e *CaptureExporter) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.events)
}

// Reset removes all captured events.
func (e *CaptureExporter) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = nil
}
