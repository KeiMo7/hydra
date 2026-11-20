// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleSet(t *testing.T, kids ...string) *jose.JSONWebKeySet {
	t.Helper()
	set := &jose.JSONWebKeySet{}
	for _, kid := range kids {
		ks, err := GenerateJWK(jose.RS256, kid, "sig")
		require.NoError(t, err)
		set.Keys = append(set.Keys, ks.Keys[0])
	}
	return set
}

func TestLifecycleTransitions(t *testing.T) {
	require.NoError(t, assertTransition(KeyStatePending, KeyStateActive))
	require.NoError(t, assertTransition(KeyStateActive, KeyStateRetired))
	require.NoError(t, assertTransition(KeyStateRetired, KeyStateTombstoned))
	// Idempotent self-transitions keep retries safe.
	require.NoError(t, assertTransition(KeyStateTombstoned, KeyStateTombstoned))

	require.Error(t, assertTransition(KeyStatePending, KeyStateRetired))
	require.Error(t, assertTransition(KeyStateActive, KeyStateTombstoned))
	require.Error(t, assertTransition(KeyStateRetired, KeyStateActive))
	require.Error(t, assertTransition(KeyStateTombstoned, KeyStateActive))
}

func TestLifecycleVisibilityAndSigning(t *testing.T) {
	assert.True(t, KeyLifecycle{State: KeyStatePending}.IsPubliclyVisible())
	assert.True(t, KeyLifecycle{State: KeyStateActive}.IsPubliclyVisible())
	assert.True(t, KeyLifecycle{State: KeyStateRetired}.IsPubliclyVisible())
	assert.False(t, KeyLifecycle{State: KeyStateTombstoned}.IsPubliclyVisible())

	assert.True(t, KeyLifecycle{State: KeyStateActive}.CanSign())
	for _, s := range []KeyState{KeyStatePending, KeyStateRetired, KeyStateTombstoned} {
		assert.False(t, KeyLifecycle{State: s}.CanSign())
	}
}

func TestPlanRotation(t *testing.T) {
	now := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	ttl := time.Hour
	skew := time.Minute
	meta := []KeyLifecycle{{Set: "s", Kid: "old", State: KeyStateActive, Generation: 1, ActivatedAt: now.Add(-time.Hour)}}

	planned, deltas, _ := PlanRotation(meta, "new", now, ttl, skew, 2)
	require.Len(t, planned, 2)

	var old, new *KeyLifecycle
	for i := range planned {
		switch planned[i].Kid {
		case "old":
			old = &planned[i]
		case "new":
			new = &planned[i]
		}
	}
	require.Equal(t, KeyStateRetired, old.State)
	require.Equal(t, now, old.RetiredAt)
	require.Equal(t, now.Add(ttl).Add(skew), old.CleanupAfter)
	require.Equal(t, KeyStateActive, new.State)
	require.Equal(t, int64(2), new.Generation)

	require.Len(t, deltas, 2)
	assert.Equal(t, KeyStateRetired, deltas[0].To)
	assert.Equal(t, KeyStateActive, deltas[1].To)
	// The old key remains publicly visible after rotation.
	assert.True(t, old.IsPubliclyVisible())
	assert.True(t, new.IsPubliclyVisible())
}

func TestCleanupBoundaryOneSecondEachSide(t *testing.T) {
	boundary := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	meta := []KeyLifecycle{{
		Set: "s", Kid: "old", State: KeyStateRetired, CleanupAfter: boundary,
	}}

	// One second before the boundary: not eligible.
	assert.Empty(t, CleanupCandidates(meta, boundary.Add(-time.Second)))
	// Exactly at the boundary: eligible (inclusive).
	assert.Equal(t, []string{"old"}, CleanupCandidates(meta, boundary))
	// One second after: eligible.
	assert.Equal(t, []string{"old"}, CleanupCandidates(meta, boundary.Add(time.Second)))
}

func TestCleanupSkipsReactivatedKey(t *testing.T) {
	boundary := time.Now().Add(-time.Hour)
	meta := []KeyLifecycle{
		{Kid: "promoted", State: KeyStateActive, CleanupAfter: boundary},
		{Kid: "gone", State: KeyStateRetired, CleanupAfter: boundary},
	}
	got := CleanupCandidates(meta, time.Now())
	assert.Equal(t, []string{"gone"}, got)
}

func TestNextGeneration(t *testing.T) {
	assert.Equal(t, int64(1), NextGeneration(nil))
	assert.Equal(t, int64(4), NextGeneration([]KeyLifecycle{{Generation: 3}, {Generation: 1}}))
}

func TestBuildView(t *testing.T) {
	meta := []KeyLifecycle{
		{Set: "s", Kid: "b", State: KeyStateRetired, Generation: 1, CleanupAfter: time.Unix(200, 0)},
		{Set: "s", Kid: "a", State: KeyStateActive, Generation: 2},
		{Set: "s", Kid: "c", State: KeyStateRetired, Generation: 3, CleanupAfter: time.Unix(100, 0)},
	}
	view := BuildView("s", meta)
	assert.Equal(t, "a", view.SigningKID)
	// Sorted by generation ascending.
	require.Len(t, view.Keys, 3)
	assert.Equal(t, "b", view.Keys[0].Kid)
	// Earliest cleanup boundary among retired keys.
	assert.Equal(t, time.Unix(100, 0), view.NextCleanupAt)
}

func TestSigningKeyPicksActiveByID(t *testing.T) {
	set := sampleSet(t, "k1", "k2")
	meta := []KeyLifecycle{{Kid: "k2", State: KeyStateActive, Generation: 2}}
	key, err := signingKey(meta, set)
	require.NoError(t, err)
	assert.Equal(t, "k2", key.KeyID)
}

func TestSigningKeyLegacyFallback(t *testing.T) {
	set := sampleSet(t, "legacy")
	// No metadata: historic first-private-key behavior.
	key, err := signingKey(nil, set)
	require.NoError(t, err)
	assert.Equal(t, "legacy", key.KeyID)
}

func TestSelectVerificationKeyByKid(t *testing.T) {
	set := sampleSet(t, "k1", "k2")
	pub := ExcludePrivateKeys(set)
	got, err := SelectVerificationKey(pub, nil, "k2", "", "")
	require.NoError(t, err)
	assert.Equal(t, "k2", got.KeyID)

	_, err = SelectVerificationKey(pub, nil, "missing", "", "")
	require.Error(t, err)
}

func TestSelectVerificationKeyFallbackOrder(t *testing.T) {
	set := sampleSet(t, "active", "pending", "retired", "legacy")
	pub := ExcludePrivateKeys(set)
	meta := []KeyLifecycle{
		{Kid: "retired", State: KeyStateRetired, Generation: 1},
		{Kid: "pending", State: KeyStatePending, Generation: 2},
		{Kid: "active", State: KeyStateActive, Generation: 3},
	}
	// No kid: active wins over pending and retired.
	got, err := SelectVerificationKey(pub, meta, "", "RS256", "sig")
	require.NoError(t, err)
	assert.Equal(t, "active", got.KeyID)
}

func TestVerifyNoKeyIDConflict(t *testing.T) {
	a := sampleSet(t, "shared")
	b := sampleSet(t, "shared") // same kid, different key
	require.Error(t, VerifyNoKeyIDConflict(a, b))

	// Identical material under the same kid is accepted (idempotent re-import).
	require.NoError(t, VerifyNoKeyIDConflict(a, a))
}

func TestPublicKIDsExcludesTombstoned(t *testing.T) {
	meta := []KeyLifecycle{
		{Kid: "a", State: KeyStateActive},
		{Kid: "b", State: KeyStateRetired},
		{Kid: "c", State: KeyStateTombstoned},
	}
	assert.Equal(t, []string{"a", "b"}, PublicKIDs(meta))
}

// TestPlanRotationRecordsPendingOrigin documents that every new key enters the
// lifecycle through the pending state before its in-transaction promotion to
// active: the rotation delta's From value is always KeyStatePending, so the
// pending -> active transition is auditable even though promotion commits in
// the same transaction.
func TestPlanRotationRecordsPendingOrigin(t *testing.T) {
	now := time.Now().UTC()
	_, deltas, _ := PlanRotation(nil, "fresh", now, time.Hour, time.Minute, 1)
	require.Len(t, deltas, 1)
	assert.Equal(t, KeyStatePending, deltas[0].From)
	assert.Equal(t, KeyStateActive, deltas[0].To)
}
