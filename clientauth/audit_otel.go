// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package clientauth

import (
	"context"

	"go.opentelemetry.io/otel/trace"

	"github.com/ory/hydra/v2/x/events"
)

// emitOTelEvent bridges the sanitized audit event into Hydra's existing
// OpenTelemetry event pipeline. If the request context has no recording span
// this is a no-op.
func emitOTelEvent(ctx context.Context, event Event) {
	opts := []trace.EventOption{
		trace.WithAttributes(
			events.ClientID(event.ClientID),
			events.ClientAuthMethod(event.Method),
			events.ClientAuthResult(event.Success),
			events.ClientAuthFailureCategory(string(event.Category)),
		),
	}
	events.Trace(ctx, events.ClientAuthentication, opts...)
}
