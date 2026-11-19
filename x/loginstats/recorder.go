// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package loginstats

import (
	"context"
	"path/filepath"
	"sync"
)

// EntryPoint identifies which login-related entry point processed an
// attempt. It is a closed enum, so it cannot inflate label cardinality.
type EntryPoint string

const (
	EntryPointToken     EntryPoint = "token"
	EntryPointAuthorize EntryPoint = "authorize"
	EntryPointDevice    EntryPoint = "device"
	EntryPointAdmin     EntryPoint = "admin"
)

// Grant-type label values, kept in a closed set. They mirror the OAuth2 grant
// type identifiers used on the wire.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantClientCredentials = "client_credentials"
	GrantPassword          = "password"
	GrantRefreshToken      = "refresh_token"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Attempt is one observed try at a login-related endpoint. The same struct is
// the only input to both metric and structured-event emission, which
// guarantees the two can never diverge.
//
// Account and Remote are raw, caller-supplied values held only for the
// duration of the call: they are immediately passed through the bucketers and
// are never stored, logged or emitted in clear text.
type Attempt struct {
	EntryPoint EntryPoint
	Account    string
	Remote     string
	GrantType  string

	// Err is the terminal error of the attempt, or nil on success.
	Err error
	// Hint optionally carries entry-layer classification knowledge.
	Hint Hint

	// DedupKey, when set, identifies the logical attempt across duplicate
	// reports (entry layer and protocol layer observing the same request).
	// Re-using a key makes the second Record a no-op.
	DedupKey string
}

// Recorder consumes classified attempts. All implementations must be safe
// for concurrent use and must never return an error or panic into the login
// path: observability cannot block authentication.
type Recorder interface {
	Record(ctx context.Context, attempt Attempt)
}

// NoopRecorder is the zero-configuration default. It performs no work and is
// used whenever the feature is disabled, so no high-cardinality dimensions are
// introduced unless an operator explicitly opts in.
type NoopRecorder struct{}

func (NoopRecorder) Record(context.Context, Attempt) {}

// Config configures the default [Recorder].
type Config struct {
	// Enabled gates the whole feature. When false, registries return the
	// [NoopRecorder].
	Enabled bool

	// Salts for account label hashing, current salt first.
	Salts [][]byte
	// AccountCardinality bounds distinct account labels.
	AccountCardinality int
	// Source configures source-segment bucketing.
	Source SourceConfig

	// FallbackPath, when set, enables rate-limited JSONL spooling of
	// aggregated results as a degradation path when metric exposition fails.
	FallbackPath string
	// FallbackMaxLinesPerMinute caps how many JSONL lines are written per
	// minute. Zero disables spooling.
	FallbackMaxLinesPerMinute int

	// DedupCardinality bounds the duplicate-detection set.
	DedupCardinality int
}

// NewRecorder builds the default recorder or, when disabled, a no-op.
func NewRecorder(cfg Config, logger Logger) Recorder {
	if !cfg.Enabled {
		return NoopRecorder{}
	}
	if cfg.AccountCardinality <= 0 {
		cfg.AccountCardinality = 1000
	}
	if cfg.FallbackMaxLinesPerMinute <= 0 {
		cfg.FallbackMaxLinesPerMinute = 60
	}
	if cfg.DedupCardinality <= 0 {
		cfg.DedupCardinality = 10000
	}

	r := &recorder{
		cfg:      cfg,
		logger:   logger,
		accounts: NewAccountBucketer(cfg.Salts, cfg.AccountCardinality),
		sources:  NewSourceBucketer(cfg.Source),
		seen:     newBoundedSet(cfg.DedupCardinality),
		metrics:  newMetrics(),
		sink:     newFileSink(cfg.FallbackPath, cfg.FallbackMaxLinesPerMinute),
		// Local bounded aggregate that stays correct even if the Prometheus
		// registry is unavailable; counters only ever move upwards.
		local: map[string]int64{},
	}
	r.metrics.mustRegister(r.onRegisterError)
	return r
}

// Logger is the minimal logging surface the recorder needs. logrusx.Logger
// satisfies it. Keeping the interface local avoids a hard dependency.
type Logger interface {
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type recorder struct {
	cfg      Config
	logger   Logger
	accounts *AccountBucketer
	sources  *SourceBucketer
	seen     *boundedSet
	metrics  *metricsSet
	sink     *fileSink

	mu    sync.Mutex
	local map[string]int64
}

// onRegisterError is invoked if the Prometheus registry rejects the
// collector. Recording keeps working against the local aggregate and the
// spool sink instead of failing the login path.
func (r *recorder) onRegisterError(err error) {
	if r.logger != nil {
		r.logger.Warnf("loginstats: Prometheus registration failed, falling back to local aggregation: %s", err)
	}
}

// Record classifies the attempt once and fans the single computed result out
// to the metric and event sinks. It is idempotent per [Attempt.DedupKey].
func (r *recorder) Record(ctx context.Context, a Attempt) {
	// Recovery first: an observability bug must never take down login.
	defer func() {
		if rec := recover(); rec != nil && r.logger != nil {
			r.logger.Errorf("loginstats: recovered from recorder panic: %v", rec)
		}
	}()

	if a.DedupKey != "" {
		firstSeen, _ := r.seen.Add(a.DedupKey)
		if !firstSeen {
			return // duplicate report of the same logical attempt
		}
		// On saturation the set reports firstSeen=true so the attempt is
		// still counted; only the duplicate guarantee is relaxed.
	}

	reason := Classify(a.Err, a.Hint)
	result := computed{
		EntryPoint: string(a.EntryPoint),
		Outcome:    string(reason.Outcome()),
		Category:   string(reason.Category()),
		Reason:     string(reason),
		GrantType:  boundedGrant(a.GrantType),
		Account:    r.accounts.Bucket(a.Account),
		Source:     r.sources.Bucket(a.Remote),
	}

	// 1. Monotonic local aggregate. Counters only increase, so late or
	//    out-of-order reports can never roll a published number backwards.
	r.accumulateLocal(result)

	// 2. Prometheus counter (no-op if registration failed).
	r.metrics.observe(result)

	// 3. Structured audit event from the exact same computed result.
	emitEvent(ctx, result)

	// 4. Degradation spool, rate-limited and best-effort.
	r.sink.append(result, r.logger)
}

func (r *recorder) accumulateLocal(c computed) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.local[c.localKey()]++
}

// Snapshot returns a copy of the monotonic local aggregate. The map is part
// of the degradation contract and is safe to read concurrently.
func (r *recorder) Snapshot() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int64, len(r.local))
	for k, v := range r.local {
		out[k] = v
	}
	return out
}

// computed is the fully resolved, bounded label set for one attempt.
type computed struct {
	EntryPoint string
	Outcome    string
	Category   string
	Reason     string
	GrantType  string
	Account    string
	Source     string
}

func (c computed) localKey() string {
	return filepath.Join(c.EntryPoint, c.Outcome, c.Category, c.Reason, c.GrantType, c.Account, c.Source)
}

// grantAllowList keeps the grant_type label in a closed set. Anything outside
// the known grants (including empty/garbage) collapses to fixed buckets.
var grantAllowList = map[string]struct{}{
	"authorization_code": {},
	"client_credentials": {},
	"password":           {},
	"refresh_token":      {},
	"urn:ietf:params:oauth:grant-type:device_code": {},
	"urn:ietf:params:oauth:grant-type:jwt-bearer":  {},
}

func boundedGrant(grant string) string {
	if grant == "" {
		return LabelEmpty
	}
	if _, ok := grantAllowList[grant]; ok {
		return grant
	}
	return LabelUnknown
}
