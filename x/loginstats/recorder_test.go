// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/fosite"
)

func TestAccountBucketer(t *testing.T) {
	t.Parallel()

	salt := []byte("current-salt-0001")
	b := NewAccountBucketer([][]byte{salt}, 100)

	t.Run("empty gets dedicated bucket", func(t *testing.T) {
		assert.Equal(t, LabelEmpty, b.Bucket(""))
	})

	t.Run("never emits plaintext", func(t *testing.T) {
		label := b.Bucket("alice@example.com")
		assert.NotContains(t, label, "alice")
		assert.NotEqual(t, "alice@example.com", label)
		assert.True(t, strings.HasPrefix(label, "v0_"))
	})

	t.Run("stable across calls", func(t *testing.T) {
		assert.Equal(t, b.Bucket("bob"), b.Bucket("bob"))
	})

	t.Run("different accounts differ", func(t *testing.T) {
		assert.NotEqual(t, b.Bucket("carol"), b.Bucket("dave"))
	})

	t.Run("missing salt degrades to unknown, never plaintext", func(t *testing.T) {
		noSalt := NewAccountBucketer(nil, 100)
		assert.Equal(t, LabelUnknown, noSalt.Bucket("alice"))
	})

	t.Run("salt rotation keeps old label aligned then stabilises", func(t *testing.T) {
		old := []byte("old-salt-0002")
		cur := []byte("new-salt-0003")
		// Before rotation: only the old salt is configured.
		before := NewAccountBucketer([][]byte{old}, 100)
		oldLabel := before.Bucket("erin")
		require.Contains(t, oldLabel, "v0_")

		// After rotation: current salt first, old salt second. A first-time
		// sighting under the new config gets the current-salt label.
		after := NewAccountBucketer([][]byte{cur, old}, 100)
		newLabel := after.Bucket("erin")
		assert.Contains(t, newLabel, "v0_")
		assert.NotEqual(t, oldLabel, newLabel)

		// The old label remains reproducible when the old salt is first, so
		// historical data stays attributable.
		legacy := NewAccountBucketer([][]byte{old, cur}, 100)
		assert.Equal(t, oldLabel, legacy.Bucket("erin"))
	})

	t.Run("cardinality is bounded with overflow", func(t *testing.T) {
		small := NewAccountBucketer([][]byte{salt}, 3)
		labels := map[string]struct{}{}
		for i := 0; i < 50; i++ {
			labels[small.Bucket("user-"+string(rune('a'+i%26))+string(rune('a'+i/26))+string(rune('0'+i%10)))] = struct{}{}
		}
		// Fixed overflow bucket plus at most the (floored) cap of distinct
		// hashed labels.
		assert.LessOrEqual(t, len(labels), small.cache.cap+1)
		assert.Contains(t, labels, LabelOverflow)
	})

	t.Run("oversized input is handled", func(t *testing.T) {
		long := strings.Repeat("x", 5000)
		label := b.Bucket(long)
		assert.NotContains(t, label, "xxx")
		assert.Less(t, len(label), 64)
	})
}

func TestSourceBucketer(t *testing.T) {
	t.Parallel()

	b := NewSourceBucketer(SourceConfig{IPv4Prefix: 24, IPv6Prefix: 48, Cardinality: 100})

	t.Run("empty and unknown", func(t *testing.T) {
		assert.Equal(t, LabelEmpty, b.Bucket(""))
		assert.Equal(t, LabelUnknown, b.Bucket("not-an-ip"))
	})

	t.Run("ipv4 folds to /24", func(t *testing.T) {
		assert.Equal(t, "10.20.30.0/24", b.Bucket("10.20.30.77"))
		assert.Equal(t, b.Bucket("10.20.30.77"), b.Bucket("10.20.30.190"))
		assert.NotEqual(t, b.Bucket("10.20.30.1"), b.Bucket("10.20.31.1"))
	})

	t.Run("ipv4 with port", func(t *testing.T) {
		assert.Equal(t, "192.168.1.0/24", b.Bucket("192.168.1.5:51234"))
	})

	t.Run("ipv6 folds to /48", func(t *testing.T) {
		assert.Equal(t, "2001:db8:1234::/48", b.Bucket("2001:db8:1234:5678::abcd"))
		assert.Equal(t, b.Bucket("2001:db8:1234:5678::abcd"), b.Bucket("[2001:db8:1234:9abc::1]:443"))
	})

	t.Run("proxy chain last hop still parses", func(t *testing.T) {
		// X-Forwarded-For chains are resolved to a single peer by httpx before
		// reaching us; a comma-laden raw value degrades to unknown rather than
		// exploding cardinality.
		assert.Equal(t, LabelUnknown, b.Bucket("1.1.1.1, 2.2.2.2, 3.3.3.3"))
	})

	t.Run("cardinality bounded", func(t *testing.T) {
		small := NewSourceBucketer(SourceConfig{IPv4Prefix: 32, Cardinality: 2})
		labels := map[string]struct{}{}
		for i := 1; i < 40; i++ {
			labels[small.Bucket("172.16.0."+string(rune('0'+i/10))+string(rune('0'+i%10)))] = struct{}{}
		}
		assert.LessOrEqual(t, len(labels), small.cache.cap+1)
		assert.Contains(t, labels, LabelOverflow)
	})
}

type testLogger struct{ warns, errs int }

func (l *testLogger) Warnf(string, ...interface{})  { l.warns++ }
func (l *testLogger) Errorf(string, ...interface{}) { l.errs++ }

func newTestRecorder(t *testing.T, cfg Config) *recorder {
	t.Helper()
	r := NewRecorder(cfg, &testLogger{}).(*recorder)
	t.Cleanup(func() { r.sink.close() })
	return r
}

func TestRecorderSameSourceMetricAndEvent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "attempts.jsonl")
	r := newTestRecorder(t, Config{
		Enabled:                   true,
		Salts:                     [][]byte{[]byte("salt-1234567890")},
		AccountCardinality:        50,
		Source:                    SourceConfig{Cardinality: 50},
		FallbackPath:              sinkPath,
		FallbackMaxLinesPerMinute: 1000,
	})

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		r.Record(ctx, Attempt{EntryPoint: EntryPointToken, Account: "alice", Remote: "10.0.0.1", GrantType: "password", Err: fosite.ErrInvalidGrant.WithWrap(ErrCredentialPasswordBad)})
	}
	// One success and one different failure to exercise more labels.
	r.Record(ctx, Attempt{EntryPoint: EntryPointToken, Account: "alice", Remote: "10.0.0.2", GrantType: "password"})
	r.Record(ctx, Attempt{EntryPoint: EntryPointAuthorize, Account: "bob", Remote: "10.0.1.5", Err: fosite.ErrInvalidScope})

	snap := r.Snapshot()
	var total int64
	for _, v := range snap {
		total += v
	}
	assert.Equal(t, int64(5), total)

	// The spool file must contain the same five attempts (same-source check).
	f, err := os.Open(sinkPath)
	require.NoError(t, err)
	defer f.Close()
	var lines int
	var sawPlaintext bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines++
		var row map[string]string
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &row))
		assert.NotEmpty(t, row["reason"])
		assert.NotEmpty(t, row["account_bucket"])
		if row["account_bucket"] == "alice" || row["account_bucket"] == "bob" {
			sawPlaintext = true
		}
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, 5, lines)
	assert.False(t, sawPlaintext, "plaintext account must never be spooled")
}

func TestRecorderDedup(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, Config{Enabled: true, Salts: [][]byte{[]byte("s")}, DedupCardinality: 100})
	ctx := context.Background()

	a := Attempt{EntryPoint: EntryPointToken, Account: "u", DedupKey: "attempt-1", Err: fosite.ErrInvalidClient}
	r.Record(ctx, a)
	r.Record(ctx, a) // duplicate, must be ignored
	r.Record(ctx, Attempt{EntryPoint: EntryPointToken, Account: "u", DedupKey: "attempt-2", Err: fosite.ErrInvalidClient})

	var total int64
	for _, v := range r.Snapshot() {
		total += v
	}
	assert.Equal(t, int64(2), total)
}

func TestRecorderDisabledIsNoop(t *testing.T) {
	t.Parallel()

	r := NewRecorder(Config{Enabled: false}, nil)
	assert.IsType(t, NoopRecorder{}, r)
	// Must not panic and must not record anything.
	r.Record(context.Background(), Attempt{Account: "x", Err: fosite.ErrInvalidRequest})
}

func TestRecorderNeverPanics(t *testing.T) {
	t.Parallel()

	// A recorder with no salt still returns bounded labels instead of panicking.
	r := newTestRecorder(t, Config{Enabled: true, Salts: nil})
	assert.NotPanics(t, func() {
		r.Record(context.Background(), Attempt{EntryPoint: EntryPointToken, Account: "anything", Remote: "garbage"})
	})
}

func TestFallbackSinkRateLimited(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "rate.jsonl")
	r := newTestRecorder(t, Config{
		Enabled:                   true,
		Salts:                     [][]byte{[]byte("s")},
		FallbackPath:              sinkPath,
		FallbackMaxLinesPerMinute: 5,
	})

	ctx := context.Background()
	for i := 0; i < 50; i++ {
		r.Record(ctx, Attempt{EntryPoint: EntryPointToken, Account: "u", Err: fosite.ErrInvalidGrant})
	}
	f, err := os.Open(sinkPath)
	require.NoError(t, err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var lines int
	for scanner.Scan() {
		lines++
	}
	assert.LessOrEqual(t, lines, 5)
}
