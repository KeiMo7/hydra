// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"context"

	otelattr "go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// EventName is the structured audit event emitted for every recorded attempt.
// It is additive: existing audit consumers keep their current events and may
// simply ignore this one. Its attributes carry the exact same bounded values
// that were used to increment the metric, which is what keeps the metric and
// event views consistent.
const EventName = "HydraLoginAttempt"

// Attribute keys. They never include a plaintext account or remote address.
const (
	AttrEntryPoint = "login.entry_point"
	AttrOutcome    = "login.outcome"
	AttrCategory   = "login.failure_category"
	AttrReason     = "login.failure_reason"
	AttrGrantType  = "login.grant_type"
	AttrAccount    = "login.account_bucket"
	AttrSource     = "login.source_bucket"
)

// emitEvent attaches the result to the request span. When there is no span
// (e.g. in some unit tests) this is a cheap no-op. It must never error.
func emitEvent(ctx context.Context, c computed) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}
	span.AddEvent(EventName, trace.WithAttributes(
		otelattr.String(AttrEntryPoint, c.EntryPoint),
		otelattr.String(AttrOutcome, c.Outcome),
		otelattr.String(AttrCategory, c.Category),
		otelattr.String(AttrReason, c.Reason),
		otelattr.String(AttrGrantType, c.GrantType),
		otelattr.String(AttrAccount, c.Account),
		otelattr.String(AttrSource, c.Source),
	))
}
