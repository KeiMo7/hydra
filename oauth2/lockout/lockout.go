// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package lockout implements concurrent failure counting and lockout with
// exponential backoff for OAuth 2.0 client credential verification.
//
// The Tracker is keyed by client identifier (optionally plus a hashed source
// dimension) and never sees or stores credential material. All state lives in
// the Store, which is shared across processes and survives restarts.
package lockout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/x/events"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
)

// Counting granularities for Config.CountBy.
const (
	// CountByClient counts failures per client identifier, merged across all
	// sources. This is the default.
	CountByClient = "client"
	// CountByClientAndSource counts failures per client identifier and
	// source (client IP) pair.
	CountByClientAndSource = "client_and_source"
)

// AuditActionUnlock is recorded when an operator manually clears a lockout.
const AuditActionUnlock = "unlock"

// Config configures the lockout behavior. All durations must be positive and
// Threshold at least 1 for the tracker to be effective.
type Config struct {
	// Enabled toggles the whole mechanism. When false every method is a
	// no-op and authentication behaves exactly as if the tracker was absent.
	Enabled bool
	// Threshold is the number of failures within Window that triggers a lockout.
	Threshold int64
	// Window is the sliding window in which failures are counted.
	Window time.Duration
	// BaseDuration is the lockout duration of the first lockout episode.
	BaseDuration time.Duration
	// BackoffMultiplier multiplies the lockout duration for every consecutive
	// lockout episode (must be >= 1).
	BackoffMultiplier float64
	// MaxDuration caps the lockout duration. It is also used to clamp
	// lockout timestamps that ended up implausibly far in the future (e.g.
	// after clock corrections), so a lockout can never exceed this duration.
	MaxDuration time.Duration
	// CountBy selects the counting granularity (CountByClient or
	// CountByClientAndSource).
	CountBy string
	// AllowOnStoreError is the explicit degradation switch: when true, a
	// failing state store lets requests through (fail open). When false
	// (default), requests are rejected as if locked (fail closed).
	AllowOnStoreError bool
}

// lockoutDuration computes the lockout duration for the given (zero-based)
// lockout round: BaseDuration * BackoffMultiplier^round, capped at MaxDuration.
func (c Config) lockoutDuration(round int64) time.Duration {
	if round < 0 {
		round = 0
	}
	d := c.BaseDuration
	for i := int64(0); i < round; i++ {
		// Multiply in float space and stop early at the cap to avoid
		// time.Duration overflow for large rounds.
		next := float64(d) * c.BackoffMultiplier
		if next >= float64(c.MaxDuration) {
			return c.MaxDuration
		}
		d = time.Duration(next)
	}
	if d > c.MaxDuration {
		return c.MaxDuration
	}
	return d
}

// Key identifies one failure counter. Source is empty when counting per
// client only, otherwise it holds a salted hash of the request source - never
// the source itself and never any credential material.
type Key struct {
	ClientID string
	Source   string
}

// Entry is the state of one failure counter.
type Entry struct {
	Key
	FailureCount    int64
	WindowStartedAt time.Time
	LockedUntil     *time.Time
	LockoutRound    int64
}

// Locked reports whether the entry is locked at the given time.
func (e Entry) Locked(now time.Time) bool {
	return e.LockedUntil != nil && e.LockedUntil.After(now)
}

// AuditEntry records an operator action on the lockout state.
type AuditEntry struct {
	ClientID string
	Action   string
	Actor    string
	At       time.Time
}

// Store persists lockout state. Implementations must guarantee that
// IncrementFailure is atomic: N concurrent calls for the same key must result
// in exactly N additional counted failures.
type Store interface {
	// IncrementFailure atomically records one failure for the key and returns
	// the resulting entry. The sliding window is applied inside the store:
	// when the stored window started before now-window (or lies in the
	// future, e.g. after a clock correction) the counter restarts at 1.
	// Failures arriving while the key is locked do not increase the counter.
	IncrementFailure(ctx context.Context, key Key, window time.Duration, now time.Time) (*Entry, error)
	// TriggerLock conditionally engages the lockout: it only takes effect
	// when the stored lockout round still equals expectedRound and no lock is
	// currently active, so concurrent triggers engage exactly one lockout
	// episode. It resets the failure counter and reports whether this call
	// engaged the lock.
	TriggerLock(ctx context.Context, key Key, expectedRound int64, lockedUntil, now time.Time) (engaged bool, err error)
	// ResetFailures clears the failure counter and backoff state for the key
	// after a successful authentication. It must not clear an active lock.
	ResetFailures(ctx context.Context, key Key, now time.Time) error
	// GetEntry returns the current state for the key, or nil when no state
	// exists.
	GetEntry(ctx context.Context, key Key) (*Entry, error)
	// ListEntries returns all counter states for a client identifier across
	// all source dimensions.
	ListEntries(ctx context.Context, clientID string) ([]Entry, error)
	// Clear removes all counter and lockout state for a client identifier
	// and returns the number of removed entries.
	Clear(ctx context.Context, clientID string) (int64, error)
	// ClampLockedUntil shortens an active lock to the given time. Used to
	// recover from lock timestamps that are implausibly far in the future.
	ClampLockedUntil(ctx context.Context, key Key, lockedUntil time.Time) error
	// InsertAudit records an operator action.
	InsertAudit(ctx context.Context, entry AuditEntry) error
}

// Tracker implements fosite.ClientCredentialsLockoutTracker on top of a Store.
type Tracker struct {
	store Store
	conf  func(ctx context.Context) Config
	l     *logrusx.Logger
	now   func() time.Time
}

// NewTracker creates a Tracker. The conf function is evaluated on every call
// so configuration changes take effect without a restart.
func NewTracker(store Store, conf func(ctx context.Context) Config, l *logrusx.Logger) *Tracker {
	if l == nil {
		l = logrusx.New("", "")
	}
	return &Tracker{
		store: store,
		conf:  conf,
		l:     l,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

// WithNow overrides the clock. Intended for tests.
func (t *Tracker) WithNow(now func() time.Time) *Tracker {
	t.now = now
	return t
}

var _ fosite.ClientCredentialsLockoutTracker = (*Tracker)(nil)

func (t *Tracker) keyFor(cfg Config, clientID string, r *http.Request) Key {
	k := Key{ClientID: clientID}
	if cfg.CountBy == CountByClientAndSource && r != nil {
		k.Source = hashSource(httpx.ClientIP(r))
	}
	return k
}

func hashSource(source string) string {
	sum := sha256.Sum256([]byte("hydra-client-lockout-source\x00" + source))
	return hex.EncodeToString(sum[:])
}

func lockedError(retryIn time.Duration) *fosite.RFC6749Error {
	return fosite.ErrInvalidClient.WithHintf(
		"The OAuth 2.0 Client is temporarily locked out due to too many failed authentication attempts. Please try again in %s.",
		retryIn.Round(time.Second))
}

// CheckLockout implements fosite.ClientCredentialsLockoutTracker.
func (t *Tracker) CheckLockout(ctx context.Context, clientID string, r *http.Request) error {
	cfg := t.conf(ctx)
	if !cfg.Enabled || clientID == "" {
		return nil
	}
	key := t.keyFor(cfg, clientID, r)
	entry, err := t.store.GetEntry(ctx, key)
	if err != nil {
		t.l.WithError(err).WithField("client_id", clientID).
			Error("Client credentials lockout state store is unavailable.")
		if cfg.AllowOnStoreError {
			return nil
		}
		// Fail closed: treat the request as locked.
		return fosite.ErrInvalidClient.WithHint(
			"Client authentication is temporarily unavailable. Please try again later.")
	}
	if entry == nil {
		return nil
	}
	now := t.now()
	if !entry.Locked(now) {
		return nil
	}
	remaining := entry.LockedUntil.Sub(now)
	if remaining > cfg.MaxDuration {
		// The stored lockout lies implausibly far in the future (e.g. the
		// clock jumped forward and back). Clamp it so a lockout can never
		// exceed the configured maximum instead of locking forever.
		if cerr := t.store.ClampLockedUntil(ctx, key, now.Add(cfg.MaxDuration)); cerr != nil {
			t.l.WithError(cerr).WithField("client_id", clientID).
				Warn("Unable to clamp implausible client lockout timestamp.")
		}
		remaining = cfg.MaxDuration
	}
	return lockedError(remaining)
}

// RecordFailure implements fosite.ClientCredentialsLockoutTracker.
func (t *Tracker) RecordFailure(ctx context.Context, clientID string, r *http.Request) {
	cfg := t.conf(ctx)
	if !cfg.Enabled || clientID == "" {
		return
	}
	key := t.keyFor(cfg, clientID, r)
	now := t.now()
	entry, err := t.store.IncrementFailure(ctx, key, cfg.Window, now)
	if err != nil {
		// Recording must never fail the request itself; the error is
		// locatable via the client_id field.
		t.l.WithError(err).WithField("client_id", clientID).
			Error("Unable to record failed client authentication attempt.")
		return
	}
	if entry.FailureCount < cfg.Threshold || entry.Locked(now) {
		return
	}
	duration := cfg.lockoutDuration(entry.LockoutRound)
	engaged, err := t.store.TriggerLock(ctx, key, entry.LockoutRound, now.Add(duration), now)
	if err != nil {
		t.l.WithError(err).WithField("client_id", clientID).
			Error("Unable to engage client credentials lockout.")
		return
	}
	if !engaged {
		// A concurrent request engaged the lockout already.
		return
	}
	t.l.WithField("client_id", clientID).
		WithField("lockout_round", entry.LockoutRound+1).
		WithField("locked_for", duration.String()).
		Warn("OAuth 2.0 Client locked out after too many failed authentication attempts.")
	events.Trace(ctx, events.ClientLockoutTriggered,
		events.WithClientID(clientID))
}

// RecordSuccess implements fosite.ClientCredentialsLockoutTracker.
func (t *Tracker) RecordSuccess(ctx context.Context, clientID string, r *http.Request) {
	cfg := t.conf(ctx)
	if !cfg.Enabled || clientID == "" {
		return
	}
	if err := t.store.ResetFailures(ctx, t.keyFor(cfg, clientID, r), t.now()); err != nil {
		t.l.WithError(err).WithField("client_id", clientID).
			Error("Unable to reset failed client authentication counter.")
	}
}

// Status returns the current counter states for a client identifier across
// all source dimensions. It is intended for operators and works regardless of
// whether the mechanism is enabled.
func (t *Tracker) Status(ctx context.Context, clientID string) ([]Entry, error) {
	return t.store.ListEntries(ctx, clientID)
}

// Unlock manually clears all counter and lockout state for a client
// identifier. The action is recorded in the audit trail before the state is
// cleared; if the audit record can not be written the state is left
// untouched.
func (t *Tracker) Unlock(ctx context.Context, clientID, actor string) error {
	if err := t.store.InsertAudit(ctx, AuditEntry{
		ClientID: clientID,
		Action:   AuditActionUnlock,
		Actor:    actor,
		At:       t.now(),
	}); err != nil {
		return err
	}
	_, err := t.store.Clear(ctx, clientID)
	if err != nil {
		return err
	}
	t.l.WithField("client_id", clientID).WithField("actor", actor).
		Info("OAuth 2.0 Client lockout manually cleared.")
	events.Trace(ctx, events.ClientLockoutReleased,
		events.WithClientID(clientID))
	return nil
}
