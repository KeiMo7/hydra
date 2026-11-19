// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"

	"github.com/ory/hydra/v2/x"
	"github.com/ory/hydra/v2/x/loginstats"
)

// LoginAttemptStatsConfig returns the configuration for the bounded login
// attempt classification feature. The feature is opt-in: when disabled the
// registry returns a no-op recorder and no new metric series or labels are
// created.
func (p *DefaultProvider) LoginAttemptStatsConfig(ctx context.Context) loginstats.Config {
	prov := p.getProvider(ctx)
	cfg := loginstats.Config{
		Enabled:                   prov.Bool(KeyLoginAttemptStatsEnabled),
		AccountCardinality:        prov.IntF(KeyLoginAttemptStatsAccountCardinality, 1000),
		FallbackPath:              prov.String(KeyLoginAttemptStatsFallbackPath),
		FallbackMaxLinesPerMinute: prov.IntF(KeyLoginAttemptStatsFallbackRateLimit, 60),
		DedupCardinality:          prov.IntF(KeyLoginAttemptStatsDedupCardinality, 10000),
		Salts:                     p.loginAttemptSalts(ctx),
		Source: loginstats.SourceConfig{
			IPv4Prefix:  prov.IntF(KeyLoginAttemptStatsSourceIPv4Prefix, 24),
			IPv6Prefix:  prov.IntF(KeyLoginAttemptStatsSourceIPv6Prefix, 48),
			Cardinality: prov.IntF(KeyLoginAttemptStatsSourceCardinality, 256),
		},
	}
	return cfg
}

// loginAttemptSalts resolves the hashing salts, current salt first. Dedicated
// salts win; otherwise the system secrets are reused so the feature works with
// zero extra secret configuration. When neither is available the returned
// slice is empty and the bucketer degrades to the unattributable bucket rather
// than ever emitting a plaintext account.
func (p *DefaultProvider) loginAttemptSalts(ctx context.Context) [][]byte {
	raw := p.getProvider(ctx).Strings(KeyLoginAttemptStatsSalt)
	if len(raw) == 0 {
		raw = p.getProvider(ctx).Strings(KeyGetSystemSecret)
	}

	salts := make([][]byte, 0, len(raw))
	for _, s := range raw {
		if len(s) >= 16 {
			salts = append(salts, x.HashStringSecret(s))
		}
	}
	return salts
}
