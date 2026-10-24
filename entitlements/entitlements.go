// Package entitlements verifies SaaS Central's signed entitlement tokens
// locally, so a product backend can decide feature access without calling
// Central on every request.
//
//	v, err := entitlements.NewValidator(
//		entitlements.WithIssuer("https://platform.nusakarya.id"),
//		entitlements.WithProduct("laundry"), // audience laundry-api
//		entitlements.WithJWKSURL("https://platform.nusakarya.id/.well-known/jwks.json"),
//	)
//	claims, err := v.Verify(ctx, token, entitlements.ForOrganization(orgOfThisRequest))
//	if err := claims.Require("advanced_reports"); err != nil { … }
//	if err := claims.WithinLimit("outlets", outletsNow); err != nil { … } // before adding one
//
// The organization to check against must come from the product's own
// trusted context (the tenant of the signed-in user), never from the
// token: a valid token for organization A says nothing about a request
// for organization B. ForOrganization is how that is checked.
//
// A token is bounded staleness, not revocation: it is valid until it
// expires (minutes). To act on changes sooner, poll Central's change feed
// and pass the newest known version with MinVersion.
package entitlements

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Arif9878/saas-central-go/jwks"
	"github.com/Arif9878/saas-central-go/scerrors"
	"github.com/Arif9878/saas-central-go/token"
)

// Limit is a feature's limit: mode "none", "limited" (Value) or
// "unlimited". Never -1.
type Limit struct {
	Mode  string `json:"mode"`
	Value *int64 `json:"value,omitempty"`
}

// Feature is one entitlement.
type Feature struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	Limit   *Limit `json:"limit,omitempty"`
	Overage string `json:"overage,omitempty"`
}

// Claims are a verified entitlement token's claims.
type Claims struct {
	token.Registered
	Product            string `json:"product"`
	SubscriptionID     string `json:"subscription_id,omitempty"`
	SubscriptionStatus string `json:"subscription_status"`
	// Basis is "subscription", "fallback" (the product's free plan) or "none".
	Basis              string             `json:"basis"`
	Plan               string             `json:"plan,omitempty"`
	PlanVersion        int                `json:"plan_version,omitempty"`
	EntitlementVersion int64              `json:"entitlement_version"`
	Features           map[string]Feature `json:"features"`
	// The subscription's dates, for what a product shows ("trial ends …",
	// "renew before …"), in Unix seconds; 0 when it has none. Use the
	// methods for times.
	TrialEndsAtUnix      int64 `json:"trial_ends_at,omitempty"`
	CurrentPeriodEndUnix int64 `json:"current_period_end,omitempty"`
	GraceEndsAtUnix      int64 `json:"grace_ends_at,omitempty"`
	CancelAtPeriodEnd    bool  `json:"cancel_at_period_end,omitempty"`
}

func unixTime(s int64) *time.Time {
	if s == 0 {
		return nil
	}
	t := time.Unix(s, 0).UTC()
	return &t
}

// TrialEndsAt is when the trial ends (a trialing subscription), or nil.
func (c *Claims) TrialEndsAt() *time.Time { return unixTime(c.TrialEndsAtUnix) }

// CurrentPeriodEnd is when the paid period ends or renews, or nil.
func (c *Claims) CurrentPeriodEnd() *time.Time { return unixTime(c.CurrentPeriodEndUnix) }

// GraceEndsAt is when a past-due subscription loses its features, or nil.
func (c *Claims) GraceEndsAt() *time.Time { return unixTime(c.GraceEndsAtUnix) }

// Organization is the organization the token is for (its sub).
func (c *Claims) Organization() string { return c.Subject }

// HasFeature reports whether feature is enabled.
func (c *Claims) HasFeature(feature string) bool {
	f, ok := c.Features[feature]
	return ok && f.Enabled
}

// Require returns nil if feature is enabled, else an error wrapping
// scerrors.ErrSubscriptionInactive (no usable subscription) or
// scerrors.ErrFeatureNotAllowed.
func (c *Claims) Require(feature string) error {
	if c.Basis == "none" {
		return fmt.Errorf("%w: %s", scerrors.ErrSubscriptionInactive, c.SubscriptionStatus)
	}
	if !c.HasFeature(feature) {
		return fmt.Errorf("%w: %s", scerrors.ErrFeatureNotAllowed, feature)
	}
	return nil
}

// Limit returns feature's limit: unlimited, or the value. ok is false when
// the feature is not enabled or has no limit (a boolean feature).
func (c *Claims) Limit(feature string) (value int64, unlimited, ok bool) {
	f, found := c.Features[feature]
	if !found || !f.Enabled || f.Limit == nil {
		return 0, false, false
	}
	switch f.Limit.Mode {
	case "unlimited":
		return 0, true, true
	case "limited":
		if f.Limit.Value != nil {
			return *f.Limit.Value, false, true
		}
	}
	return 0, false, false
}

// WithinLimit is for "may I create one more?": current is the product's
// own authoritative count (its outlets, its doctors). It returns an error
// wrapping scerrors.ErrQuotaExceeded when current has reached the limit,
// or the errors of Require. The token cannot know current: the product
// must count.
func (c *Claims) WithinLimit(feature string, current int64) error {
	if err := c.Require(feature); err != nil {
		return err
	}
	limit, unlimited, ok := c.Limit(feature)
	if !ok {
		return fmt.Errorf("%w: %s has no limit", scerrors.ErrFeatureNotAllowed, feature)
	}
	if !unlimited && current >= limit {
		return fmt.Errorf("%w: %s %d of %d", scerrors.ErrQuotaExceeded, feature, current, limit)
	}
	return nil
}

// Validator verifies entitlement tokens for one product.
type Validator struct {
	verifier *token.Verifier
	product  string
}

type config struct {
	issuer, audience, product string
	jwksURL                   string
	jwksOpts                  []jwks.Option
	source                    jwks.Source
	leeway                    time.Duration
	now                       func() time.Time
}

// Option configures NewValidator.
type Option func(*config)

// WithIssuer sets the trusted issuer (Central's public URL). Required.
func WithIssuer(iss string) Option { return func(c *config) { c.issuer = iss } }

// WithProduct sets the product code tokens must be for. Required. The
// audience defaults to "<product>-api".
func WithProduct(p string) Option { return func(c *config) { c.product = p } }

// WithAudience overrides the expected audience.
func WithAudience(aud string) Option { return func(c *config) { c.audience = aud } }

// WithJWKSURL fetches keys from Central's JWKS (configured, never taken
// from a token).
func WithJWKSURL(url string, opts ...jwks.Option) Option {
	return func(c *config) { c.jwksURL, c.jwksOpts = url, opts }
}

// WithKeySource uses an existing key source (a shared jwks.Cache, or
// jwks.Static in tests).
func WithKeySource(s jwks.Source) Option { return func(c *config) { c.source = s } }

// WithLeeway tolerates clock skew (default 30 s).
func WithLeeway(d time.Duration) Option { return func(c *config) { c.leeway = d } }

// WithClock sets the clock, for tests.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// NewValidator returns a Validator. Issuer, product and a key source are
// required.
func NewValidator(opts ...Option) (*Validator, error) {
	var c config
	for _, o := range opts {
		o(&c)
	}
	if c.issuer == "" || c.product == "" {
		return nil, errors.New("saascentral/entitlements: WithIssuer and WithProduct are required")
	}
	if c.audience == "" {
		c.audience = c.product + "-api"
	}
	src := c.source
	if src == nil {
		if c.jwksURL == "" {
			return nil, errors.New("saascentral/entitlements: WithJWKSURL or WithKeySource is required")
		}
		cache, err := jwks.New(c.jwksURL, c.jwksOpts...)
		if err != nil {
			return nil, err
		}
		src = cache
	}
	v, err := token.New(src, token.Policy{Issuer: c.issuer, Audience: c.audience, Type: token.TypeEntitlement,
		KeyIDPrefix: token.KeyPrefixEntitlement, Leeway: c.leeway, Now: c.now})
	if err != nil {
		return nil, err
	}
	return &Validator{verifier: v, product: c.product}, nil
}

type verifyOptions struct {
	org        string
	minVersion int64
}

// VerifyOption adds a check to Verify.
type VerifyOption func(*verifyOptions)

// ForOrganization requires the token to be for orgID, the organization of
// the request from the product's own trusted context.
func ForOrganization(orgID string) VerifyOption { return func(o *verifyOptions) { o.org = orgID } }

// MinVersion refuses tokens older than an entitlement version the product
// already learned from the change feed.
func MinVersion(v int64) VerifyOption { return func(o *verifyOptions) { o.minVersion = v } }

// Verify checks the signature and claims of raw, its product, and the
// options' organization and version. Errors wrap scerrors values.
func (v *Validator) Verify(ctx context.Context, raw string, opts ...VerifyOption) (*Claims, error) {
	var o verifyOptions
	for _, opt := range opts {
		opt(&o)
	}
	var c Claims
	if err := v.verifier.Verify(ctx, raw, &c); err != nil {
		return nil, err
	}
	if c.Product != v.product {
		return nil, fmt.Errorf("%w: token for %q", scerrors.ErrUnauthorizedProduct, c.Product)
	}
	if o.org != "" && c.Subject != o.org {
		return nil, fmt.Errorf("%w: token for another organization", scerrors.ErrUnauthorizedOrganization)
	}
	if c.EntitlementVersion < o.minVersion {
		return nil, fmt.Errorf("%w: version %d < %d", scerrors.ErrStaleToken, c.EntitlementVersion, o.minVersion)
	}
	if c.Features == nil {
		c.Features = map[string]Feature{}
	}
	return &c, nil
}
