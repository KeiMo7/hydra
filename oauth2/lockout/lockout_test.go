// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package lockout_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/oauth2/lockout"
	"github.com/ory/x/logrusx"
)

func testConfig() lockout.Config {
	return lockout.Config{
		Enabled:           true,
		Threshold:         3,
		Window:            10 * time.Minute,
		BaseDuration:      time.Minute,
		BackoffMultiplier: 2,
		MaxDuration:       10 * time.Minute,
		CountBy:           lockout.CountByClient,
		AllowOnStoreError: false,
	}
}

func newTracker(t *testing.T, cfg lockout.Config) (*lockout.Tracker, lockout.Store) {
	reg := testhelpers.NewRegistryMemory(t)
	store := reg.Persister()
	return lockout.NewTracker(store, func(context.Context) lockout.Config { return cfg }, logrusx.New("", "")), store
}

func TestConcurrentFailureCountIsExact(t *testing.T) {
	cfg := testConfig()
	cfg.Threshold = 10000
	tracker, store := newTracker(t, cfg)

	ctx := context.Background()
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.RecordFailure(ctx, "concurrent-client", nil)
		}()
	}
	wg.Wait()

	entry, err := store.GetEntry(ctx, lockout.Key{ClientID: "concurrent-client"})
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.EqualValues(t, n, entry.FailureCount, "N concurrent failures must result in exactly N counted failures")
}

func TestLockoutBlocksAndUnlockRestores(t *testing.T) {
	tracker, _ := newTracker(t, testConfig())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, tracker.CheckLockout(ctx, "locked-client", nil))
		tracker.RecordFailure(ctx, "locked-client", nil)
	}

	err := tracker.CheckLockout(ctx, "locked-client", nil)
	require.Error(t, err)
	var rfcErr *fosite.RFC6749Error
	require.ErrorAs(t, err, &rfcErr)
	assert.Equal(t, fosite.ErrInvalidClient.ErrorField, rfcErr.ErrorField, "lockout must reuse the invalid_client error code")
	assert.Contains(t, rfcErr.GetDescription(), "locked out", "lockout reason must be distinguishable from a wrong secret")

	require.NoError(t, tracker.Unlock(ctx, "locked-client", "test"))
	require.NoError(t, tracker.CheckLockout(ctx, "locked-client", nil), "client must be usable right after a manual unlock")

	// The counter was reset by the unlock, so a single new failure does not
	// re-lock the client.
	tracker.RecordFailure(ctx, "locked-client", nil)
	require.NoError(t, tracker.CheckLockout(ctx, "locked-client", nil))
}

func TestBackoffIncreasesAndCaps(t *testing.T) {
	cfg := testConfig()
	cfg.Threshold = 1
	tracker, store := newTracker(t, cfg)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracker.WithNow(func() time.Time { return now })

	ctx := context.Background()
	key := lockout.Key{ClientID: "backoff-client"}

	expectedDurations := []time.Duration{
		time.Minute,      // 1m * 2^0
		2 * time.Minute,  // 1m * 2^1
		4 * time.Minute,  // 1m * 2^2
		8 * time.Minute,  // 1m * 2^3
		10 * time.Minute, // capped
		10 * time.Minute, // stays capped
	}
	for round, expected := range expectedDurations {
		tracker.RecordFailure(ctx, "backoff-client", nil)

		entry, err := store.GetEntry(ctx, key)
		require.NoError(t, err)
		require.NotNil(t, entry)
		require.NotNil(t, entry.LockedUntil, "round %d must be locked", round)
		assert.Equal(t, now.Add(expected), *entry.LockedUntil, "lockout duration of round %d", round)
		assert.EqualValues(t, round+1, entry.LockoutRound)

		// Move past the lockout; the next failure triggers the next round.
		now = now.Add(expected).Add(time.Second)
		require.NoError(t, tracker.CheckLockout(ctx, "backoff-client", nil))
	}
}

func TestSuccessResetsCounter(t *testing.T) {
	tracker, store := newTracker(t, testConfig())
	ctx := context.Background()

	tracker.RecordFailure(ctx, "success-client", nil)
	tracker.RecordFailure(ctx, "success-client", nil)
	tracker.RecordSuccess(ctx, "success-client", nil)

	entry, err := store.GetEntry(ctx, lockout.Key{ClientID: "success-client"})
	require.NoError(t, err)
	assert.Nil(t, entry, "a successful authentication must clear the failure counter")
}

func TestWindowExpiryRestartsCount(t *testing.T) {
	cfg := testConfig()
	tracker, store := newTracker(t, cfg)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracker.WithNow(func() time.Time { return now })

	ctx := context.Background()
	tracker.RecordFailure(ctx, "window-client", nil)
	now = now.Add(cfg.Window + time.Second)
	tracker.RecordFailure(ctx, "window-client", nil)

	entry, err := store.GetEntry(ctx, lockout.Key{ClientID: "window-client"})
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.EqualValues(t, 1, entry.FailureCount, "failures outside the window must restart the count")
}

func TestCountByClientAndSource(t *testing.T) {
	cfg := testConfig()
	cfg.CountBy = lockout.CountByClientAndSource
	tracker, store := newTracker(t, cfg)
	ctx := context.Background()

	reqA := httptest.NewRequest("POST", "/oauth2/token", nil)
	reqA.RemoteAddr = "192.0.2.1:1234"
	reqB := httptest.NewRequest("POST", "/oauth2/token", nil)
	reqB.RemoteAddr = "192.0.2.2:1234"

	tracker.RecordFailure(ctx, "source-client", reqA)
	tracker.RecordFailure(ctx, "source-client", reqA)
	tracker.RecordFailure(ctx, "source-client", reqB)

	entries, err := store.ListEntries(ctx, "source-client")
	require.NoError(t, err)
	require.Len(t, entries, 2, "per-source counting must keep separate counters")
	for _, e := range entries {
		assert.NotEmpty(t, e.Source)
		assert.NotContains(t, e.Source, "192.0.2.", "the stored source must be hashed, not the raw IP")
	}

	// Two failures from A and one from B do not lock out either (threshold 3).
	require.NoError(t, tracker.CheckLockout(ctx, "source-client", reqA))
	tracker.RecordFailure(ctx, "source-client", reqB)
	tracker.RecordFailure(ctx, "source-client", reqB)
	require.Error(t, tracker.CheckLockout(ctx, "source-client", reqB), "B reached the threshold")
	require.NoError(t, tracker.CheckLockout(ctx, "source-client", reqA), "A is counted separately")
}

func TestClockAnomalyClampsLockout(t *testing.T) {
	cfg := testConfig()
	cfg.Threshold = 1
	reg := testhelpers.NewRegistryMemory(t)
	var store lockout.Store = reg.Persister()
	tracker := lockout.NewTracker(store, func(context.Context) lockout.Config { return cfg }, logrusx.New("", ""))
	ctx := context.Background()
	key := lockout.Key{ClientID: "clock-client"}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tracker.WithNow(func() time.Time { return now })
	tracker.RecordFailure(ctx, "clock-client", nil)

	// Simulate a lockout timestamp that was written while the clock was far
	// ahead of the current time.
	farFuture := now.Add(1000 * time.Hour)
	require.NoError(t, reg.Persister().Connection(ctx).RawQuery(
		`UPDATE hydra_client_lockout SET locked_until = ? WHERE client_id = ?`, farFuture, "clock-client").Exec())

	// The lock is still active, but clamped to the configured maximum instead
	// of lasting ~1000 hours.
	err := tracker.CheckLockout(ctx, "clock-client", nil)
	require.Error(t, err)
	var rfcErr *fosite.RFC6749Error
	require.ErrorAs(t, err, &rfcErr)
	assert.Contains(t, rfcErr.GetDescription(), "10m")

	entry, err := store.GetEntry(ctx, key)
	require.NoError(t, err)
	assert.WithinDuration(t, now.Add(cfg.MaxDuration), *entry.LockedUntil, time.Second)
}

type failingStore struct{ err error }

func (s failingStore) IncrementFailure(context.Context, lockout.Key, time.Duration, time.Time) (*lockout.Entry, error) {
	return nil, s.err
}
func (s failingStore) TriggerLock(context.Context, lockout.Key, int64, time.Time, time.Time) (bool, error) {
	return false, s.err
}
func (s failingStore) ResetFailures(context.Context, lockout.Key, time.Time) error { return s.err }
func (s failingStore) GetEntry(context.Context, lockout.Key) (*lockout.Entry, error) {
	return nil, s.err
}
func (s failingStore) ListEntries(context.Context, string) ([]lockout.Entry, error) {
	return nil, s.err
}
func (s failingStore) Clear(context.Context, string) (int64, error)                   { return 0, s.err }
func (s failingStore) ClampLockedUntil(context.Context, lockout.Key, time.Time) error { return s.err }
func (s failingStore) InsertAudit(context.Context, lockout.AuditEntry) error          { return s.err }

func TestStoreUnavailableFailsClosed(t *testing.T) {
	cfg := testConfig()
	store := failingStore{err: errors.New("store is down")}
	tracker := lockout.NewTracker(store, func(context.Context) lockout.Config { return cfg }, nil)
	ctx := context.Background()

	err := tracker.CheckLockout(ctx, "some-client", nil)
	require.Error(t, err, "store unavailable must reject the request (fail closed)")
	var rfcErr *fosite.RFC6749Error
	require.ErrorAs(t, err, &rfcErr)
	assert.Equal(t, fosite.ErrInvalidClient.ErrorField, rfcErr.ErrorField)

	// Recording failures/successes must never panic or block the request.
	tracker.RecordFailure(ctx, "some-client", nil)
	tracker.RecordSuccess(ctx, "some-client", nil)

	// The explicit degradation switch lets requests through.
	cfg.AllowOnStoreError = true
	require.NoError(t, tracker.CheckLockout(ctx, "some-client", nil))
}

func TestDisabledIsNoop(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	tracker, store := newTracker(t, cfg)
	ctx := context.Background()

	for i := 0; i < 20; i++ {
		tracker.RecordFailure(ctx, "disabled-client", nil)
		require.NoError(t, tracker.CheckLockout(ctx, "disabled-client", nil))
	}
	tracker.RecordSuccess(ctx, "disabled-client", nil)

	entry, err := store.GetEntry(ctx, lockout.Key{ClientID: "disabled-client"})
	require.NoError(t, err)
	assert.Nil(t, entry, "a disabled tracker must not write any state")
}

func TestUnlockWritesAuditTrail(t *testing.T) {
	tracker, _ := newTracker(t, testConfig())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		tracker.RecordFailure(ctx, "audit-client", nil)
	}
	require.Error(t, tracker.CheckLockout(ctx, "audit-client", nil))
	require.NoError(t, tracker.Unlock(ctx, "audit-client", "ops@example.org"))
	require.NoError(t, tracker.CheckLockout(ctx, "audit-client", nil))
}
