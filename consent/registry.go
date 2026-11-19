// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package consent

import (
	"github.com/ory/hydra/v2/aead"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/internal/kratos"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/hydra/v2/x/loginstats"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
)

type InternalRegistry interface {
	httpx.WriterProvider
	x.RegistryCookieStore
	logrusx.Provider
	httpx.ClientProvider
	otelx.Provider
	x.NetworkProvider
	kratos.Provider
	Registry
	client.Registry
	loginstatsRecorder

	FlowCipher() *aead.XChaCha20Poly1305
	OAuth2Storage() x.FositeStorer
	OpenIDConnectRequestValidator() *openid.OpenIDConnectRequestValidator
}

// loginstatsRecorder is the small surface the consent package needs from the
// driver registry. It is satisfied by the same recorder used by the OAuth2
// entry points, so admin-side and protocol-side outcomes share one taxonomy.
type loginstatsRecorder interface {
	LoginAttemptRecorder() loginstats.Recorder
}

type Registry interface {
	ManagerProvider
	ObfuscatedSubjectManagerProvider
	LoginManagerProvider
	LogoutManagerProvider

	ConsentStrategy() Strategy
}
