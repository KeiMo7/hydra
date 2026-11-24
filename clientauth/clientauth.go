// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package clientauth is the single registry and policy layer for OAuth 2.0
// client authentication methods.
//
// A method contributes its declaration (identifier, credential class and
// capabilities) plus credential parsing/verification. Discovery, client
// metadata validation, endpoint authentication, rotation eligibility and
// audit classification are all derived from the registry's request-scoped
// Snapshot.
package clientauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/ory/hydra/v2/fosite"
)

// CredentialKind classifies the credential material used by a method.
type CredentialKind string

const (
	// CredentialNone is used by public clients and methods that present no
	// credential.
	CredentialNone CredentialKind = "none"
	// CredentialSharedSecret covers client_secret_basic, client_secret_post and
	// custom symmetric-secret methods.
	CredentialSharedSecret CredentialKind = "shared_secret"
	// CredentialPublicKey covers private_key_jwt and other key-based methods.
	CredentialPublicKey CredentialKind = "public_key"
	// CredentialCustom is used by methods with bespoke material.
	CredentialCustom CredentialKind = "custom"
)

// Stable method identifiers used by Hydra's built-in methods.
const (
	MethodClientSecretBasic = "client_secret_basic"
	MethodClientSecretPost  = "client_secret_post"
	MethodPrivateKeyJWT     = "private_key_jwt"
	MethodNone              = "none"
)

// FailureCategory is the internal, auditable classification of an
// authentication result. These values are intentionally stable and must never
// contain credential material.
type FailureCategory string

const (
	CategorySuccess             FailureCategory = "success"
	CategoryNoCredentials       FailureCategory = "no_credentials"
	CategoryAmbiguousCredential FailureCategory = "ambiguous_credentials"
	CategoryMalformedCredential FailureCategory = "malformed_credentials"
	CategoryClientNotFound      FailureCategory = "client_not_found"
	CategoryClientLookupFailed  FailureCategory = "client_lookup_failed"
	CategoryUnknownMethod       FailureCategory = "unknown_method"
	CategoryMethodDisabled      FailureCategory = "method_disabled"
	CategoryMethodMismatch      FailureCategory = "method_mismatch"
	CategoryInvalidSecret       FailureCategory = "invalid_secret"
	CategoryInvalidAssertion    FailureCategory = "invalid_assertion"
	CategoryReplayDetected      FailureCategory = "replay_detected"
	CategoryVerificationFailed  FailureCategory = "verification_failed"
	CategoryMethodError         FailureCategory = "method_error"
	CategoryMethodPanic         FailureCategory = "method_panic"
	CategoryConfigurationError  FailureCategory = "configuration_error"
	CategoryInvalidRequest      FailureCategory = "invalid_request"
	CategoryInvalidClient       FailureCategory = "invalid_client"
)

// Descriptor is the declarative part of a client authentication method.
type Descriptor struct {
	// ID is the token_endpoint_auth_method identifier.
	ID string `json:"id"`
	// CredentialType is the coarse credential class.
	CredentialType CredentialKind `json:"credential_type"`
	// Discoverable controls whether the method is advertised in discovery
	// documents when enabled.
	Discoverable bool `json:"discoverable"`
	// Rotatable reports whether the method's shared secret supports rotation.
	Rotatable bool `json:"rotatable"`
	// Materials describes the registrable material names, for example
	// "client_secret", "jwks" and "jwks_uri".
	Materials []string `json:"materials,omitempty"`
}

// RegistrationMaterials contains the subset of client metadata relevant to
// registration validation. Raw carries the concrete client for external
// MaterialValidators.
type RegistrationMaterials struct {
	Method     string
	HasSecret  bool
	HasJWKS    bool
	HasJWKSURI bool
	Raw        any
}

// MaterialValidator is an optional extension for methods with registration
// material rules beyond the built-in public-key check.
type MaterialValidator interface {
	ValidateRegistration(RegistrationMaterials) error
}

// AuthenticationInput is passed to a Method implementation.
type AuthenticationInput struct {
	// HTTPRequest is the original endpoint request. Implementations must not
	// log its Authorization header, cookies, request body or assertion.
	HTTPRequest *http.Request
	// Form is the already parsed request form.
	Form url.Values
	// Client is the framework-resolved client. It may be nil when the
	// identifier could not be resolved before invoking a custom method.
	Client fosite.Client
	// Snapshot is the request-scoped effective method set.
	Snapshot *Snapshot
	// Clients allows custom methods to resolve a client using their own
	// identifier location.
	Clients ClientLookup
}

// Method is the only interface a new authentication method must implement:
// declare itself and parse/verify its credentials. Discovery, registration
// validation, endpoint dispatch, rotation and audit are handled by Registry.
type Method interface {
	Descriptor() Descriptor
	Authenticate(ctx context.Context, in *AuthenticationInput) (fosite.Client, error)
}

// ClientLookup resolves a stored client by ID.
type ClientLookup interface {
	GetClient(ctx context.Context, id string) (fosite.Client, error)
}

// ClientLookupFunc adapts a function to ClientLookup.
type ClientLookupFunc func(ctx context.Context, id string) (fosite.Client, error)

func (f ClientLookupFunc) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return f(ctx, id)
}

// ConfigSource returns the configured effective identifiers. A false explicit
// value means that no allowlist was configured and every registered method is
// effective. An explicit empty slice intentionally disables all methods.
type ConfigSource func(ctx context.Context) (ids []string, explicit bool, err error)

// LegacyAuthenticator runs Hydra/Fosite's existing built-in verification
// logic without changing its cryptographic and replay behavior.
type LegacyAuthenticator func(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error)

// Logger is the minimal logging surface used by the registry.
type Logger interface {
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Event is the sanitized audit record for one authentication attempt. It must
// never be extended with secrets, assertions, raw headers or tokens.
type Event struct {
	Time     time.Time       `json:"time"`
	Endpoint string          `json:"endpoint,omitempty"`
	ClientID string          `json:"client_id,omitempty"`
	Method   string          `json:"method,omitempty"`
	Success  bool            `json:"success"`
	Category FailureCategory `json:"category"`
}

// EventExporter receives sanitized audit events.
type EventExporter interface {
	ExportClientAuthenticationEvent(context.Context, Event)
}

// EventExporterFunc adapts a function to EventExporter.
type EventExporterFunc func(context.Context, Event)

func (f EventExporterFunc) ExportClientAuthenticationEvent(ctx context.Context, e Event) {
	f(ctx, e)
}

// Registry stores all registered methods and builds effective snapshots.
type Registry struct {
	mu        sync.RWMutex
	methods   map[string]Method
	exporters []EventExporter

	config  ConfigSource
	clients ClientLookup
	legacy  LegacyAuthenticator
	logger  Logger
}

// Option configures a Registry.
type Option func(*Registry)

func WithConfigSource(src ConfigSource) Option {
	return func(r *Registry) { r.config = src }
}

func WithClientLookup(lookup ClientLookup) Option {
	return func(r *Registry) { r.clients = lookup }
}

func WithLegacyAuthenticator(auth LegacyAuthenticator) Option {
	return func(r *Registry) { r.legacy = auth }
}

func WithLogger(logger Logger) Option {
	return func(r *Registry) { r.logger = logger }
}

func WithEventExporter(exporter EventExporter) Option {
	return func(r *Registry) {
		if exporter != nil {
			r.exporters = append(r.exporters, exporter)
		}
	}
}

// NewRegistry creates an empty registry. Call Register to add methods.
func NewRegistry(opts ...Option) *Registry {
	r := &Registry{
		methods: make(map[string]Method),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// AddExporter appends an audit event exporter.
func (r *Registry) AddExporter(exporter EventExporter) {
	if exporter == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exporters = append(r.exporters, exporter)
}

// SetLegacyAuthenticator installs the compatibility authenticator.
func (r *Registry) SetLegacyAuthenticator(auth LegacyAuthenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.legacy = auth
}

// SetClientLookup installs the client lookup used during authentication.
func (r *Registry) SetClientLookup(lookup ClientLookup) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients = lookup
}

// Register adds a method. Duplicate and incomplete declarations return a
// locatable error instead of panicking.
func (r *Registry) Register(method Method) error {
	if method == nil {
		return errors.New("clientauth: cannot register a nil authentication method")
	}
	d := method.Descriptor()
	if d.ID == "" {
		return &RegistrationError{Field: "descriptor.id", Message: "authentication method identifier must not be empty"}
	}
	if !validCredentialKind(d.CredentialType) {
		return &RegistrationError{Method: d.ID, Field: "descriptor.credential_type", Message: fmt.Sprintf("invalid credential type %q", d.CredentialType)}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.methods[d.ID]; exists {
		return &RegistrationError{Method: d.ID, Field: "descriptor.id", Message: "authentication method is already registered"}
	}
	r.methods[d.ID] = method
	return nil
}

func validCredentialKind(k CredentialKind) bool {
	switch k {
	case CredentialNone, CredentialSharedSecret, CredentialPublicKey, CredentialCustom:
		return true
	}
	return false
}

// MustRegister registers a method and panics on a programming error. It is
// intended for fixed built-in registration and tests.
func (r *Registry) MustRegister(method Method) {
	if err := r.Register(method); err != nil {
		panic(err)
	}
}

// Method returns a registered method regardless of whether it is enabled.
func (r *Registry) Method(id string) (Method, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.methods[id]
	return m, ok
}

// Descriptor returns a registered descriptor.
func (r *Registry) Descriptor(id string) (Descriptor, bool) {
	m, ok := r.Method(id)
	if !ok {
		return Descriptor{}, false
	}
	return m.Descriptor(), true
}

// RegistrationError points at a malformed method registration or config entry.
type RegistrationError struct {
	Method  string
	Field   string
	Message string
}

func (e *RegistrationError) Error() string {
	if e.Method != "" {
		return fmt.Sprintf("clientauth: method %q: %s: %s", e.Method, e.Field, e.Message)
	}
	return fmt.Sprintf("clientauth: %s: %s", e.Field, e.Message)
}

// ConfigError describes a locatable effective-set configuration problem.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("clientauth: configuration error at %s: %s", e.Field, e.Message)
}

// Snapshot is an immutable request-scoped view of the effective method set.
type Snapshot struct {
	registry    *Registry
	all         map[string]Method
	enabled     map[string]Method
	enabledIDs  []string
	configError error
}

type snapshotContextKey struct{}

// WithSnapshot binds a snapshot to a context so one request shares one view.
func WithSnapshot(ctx context.Context, snap *Snapshot) context.Context {
	return context.WithValue(ctx, snapshotContextKey{}, snap)
}

// Snapshot returns the request-bound snapshot if present, otherwise builds a
// new one from the current configuration.
func (r *Registry) Snapshot(ctx context.Context) *Snapshot {
	if snap, ok := ctx.Value(snapshotContextKey{}).(*Snapshot); ok && snap != nil && snap.registry == r {
		return snap
	}

	r.mu.RLock()
	all := make(map[string]Method, len(r.methods))
	for id, m := range r.methods {
		all[id] = m
	}
	src := r.config
	r.mu.RUnlock()

	snap := &Snapshot{registry: r, all: all, enabled: map[string]Method{}}
	if src == nil {
		for id, m := range all {
			snap.enabled[id] = m
		}
	} else {
		ids, explicit, err := src(ctx)
		switch {
		case err != nil:
			snap.configError = &ConfigError{Field: "oauth2.client_authentication.enabled_methods", Message: err.Error()}
		case !explicit:
			for id, m := range all {
				snap.enabled[id] = m
			}
		default:
			seen := map[string]struct{}{}
			for _, id := range ids {
				if id == "" {
					snap.configError = &ConfigError{Field: "oauth2.client_authentication.enabled_methods", Message: "method identifier must not be empty"}
					snap.enabled = map[string]Method{}
					break
				}
				if _, dup := seen[id]; dup {
					snap.configError = &ConfigError{Field: "oauth2.client_authentication.enabled_methods", Message: fmt.Sprintf("method %q is listed more than once", id)}
					snap.enabled = map[string]Method{}
					break
				}
				seen[id] = struct{}{}
				m, ok := all[id]
				if !ok {
					snap.configError = &ConfigError{Field: "oauth2.client_authentication.enabled_methods", Message: fmt.Sprintf("method %q is enabled but not registered", id)}
					snap.enabled = map[string]Method{}
					break
				}
				snap.enabled[id] = m
			}
			if snap.configError == nil && len(ids) == 0 {
				snap.configError = &ConfigError{Field: "oauth2.client_authentication.enabled_methods", Message: "enabled method set is empty"}
			}
		}
	}

	for id := range snap.enabled {
		snap.enabledIDs = append(snap.enabledIDs, id)
	}
	sort.Strings(snap.enabledIDs)
	return snap
}

// ConfigError returns the locatable configuration error, if any.
func (s *Snapshot) ConfigError() error { return s.configError }

// Has reports whether id is in the effective set.
func (s *Snapshot) Has(id string) bool {
	_, ok := s.enabled[id]
	return ok
}

// Get returns an effective method.
func (s *Snapshot) Get(id string) (Method, bool) {
	m, ok := s.enabled[id]
	return m, ok
}

// IDs returns the deduplicated, sorted effective identifiers.
func (s *Snapshot) IDs() []string {
	return append([]string(nil), s.enabledIDs...)
}

// DiscoveryIDs returns deduplicated, sorted and discoverable effective IDs.
func (s *Snapshot) DiscoveryIDs() []string {
	var ids []string
	for _, id := range s.enabledIDs {
		if s.enabled[id].Descriptor().Discoverable {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// RotationEligible reports whether id is both effective and declares secret
// rotation support.
func (s *Snapshot) RotationEligible(id string) bool {
	m, ok := s.Get(id)
	return ok && m.Descriptor().Rotatable
}

// ValidateRegistration checks an incoming client against the effective set.
func (r *Registry) ValidateRegistration(ctx context.Context, materials RegistrationMaterials) error {
	snap := r.Snapshot(ctx)
	if snap.configError != nil {
		// An invalid allow-list fails closed for authentication. Client writes
		// still receive a 400 metadata error with a locatable message.
		return snap.configError
	}

	id := materials.Method
	m, registered := r.Method(id)
	if !registered {
		return &RegistrationError{Method: id, Field: "token_endpoint_auth_method", Message: "authentication method is not registered"}
	}
	if !snap.Has(id) {
		return &RegistrationError{Method: id, Field: "token_endpoint_auth_method", Message: "authentication method is disabled"}
	}

	d := m.Descriptor()
	if d.CredentialType == CredentialPublicKey && !materials.HasJWKS && !materials.HasJWKSURI {
		return &RegistrationError{Method: id, Field: "jwks|jwks_uri", Message: "either jwks or jwks_uri must be set"}
	}
	if v, ok := m.(MaterialValidator); ok {
		if err := v.ValidateRegistration(materials); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) emit(ctx context.Context, event Event) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	r.mu.RLock()
	exporters := append([]EventExporter(nil), r.exporters...)
	logger := r.logger
	r.mu.RUnlock()

	for _, exporter := range exporters {
		func() {
			defer func() { _ = recover() }()
			exporter.ExportClientAuthenticationEvent(ctx, event)
		}()
	}

	// The OpenTelemetry bridge is part of the existing Hydra event pipeline.
	emitOTelEvent(ctx, event)

	if logger != nil && !event.Success {
		// Fixed fields only. Never attach the method error because a third
		// party error could contain request credential material.
		logger.Warnf("client authentication failed: method=%s category=%s client_id=%s endpoint=%s",
			event.Method, event.Category, event.ClientID, event.Endpoint)
	}
}
