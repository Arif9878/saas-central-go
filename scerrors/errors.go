// Package scerrors defines the errors of the SaaS Central SDK. Every
// failure the SDK returns wraps one of these, so callers branch with
// errors.Is and still see the detail in the message:
//
//	if errors.Is(err, scerrors.ErrExpiredToken) { … }
//
// Token failures (signature, claims, keys) all mean "do not trust this
// token"; the distinction is for logs and metrics, not for telling the
// caller why — answer them with a plain 401.
package scerrors

import "errors"

// Token and key errors.
var (
	// ErrMalformedToken: not a compact JWS, bad base64 or JSON, or too large.
	ErrMalformedToken = errors.New("saascentral: malformed token")
	// ErrUnsupportedAlgorithm: alg is not the one the policy allows
	// (including "none"), or the key does not match it.
	ErrUnsupportedAlgorithm = errors.New("saascentral: unsupported algorithm")
	// ErrInvalidSignature: the signature does not verify.
	ErrInvalidSignature = errors.New("saascentral: invalid signature")
	// ErrUnknownKey: no trusted key has the token's kid, or the kid is not
	// one this policy accepts.
	ErrUnknownKey = errors.New("saascentral: unknown signing key")
	// ErrKeysUnavailable: the trusted JWKS could not be fetched and no
	// usable cached copy is left.
	ErrKeysUnavailable = errors.New("saascentral: signing keys unavailable")
	// ErrForbiddenHeader: the header names a key or key location (jwk,
	// jku, x5u, x5c) or critical extensions; keys only come from the
	// trusted JWKS.
	ErrForbiddenHeader = errors.New("saascentral: forbidden token header")
	ErrExpiredToken    = errors.New("saascentral: token expired")
	ErrNotYetValid     = errors.New("saascentral: token not valid yet")
	ErrInvalidIssuer   = errors.New("saascentral: invalid issuer")
	ErrInvalidAudience = errors.New("saascentral: invalid audience")
	// ErrInvalidTokenType: the typ header is not the policy's (an access
	// token offered as an entitlement token, or the reverse).
	ErrInvalidTokenType = errors.New("saascentral: invalid token type")
	// ErrMissingClaim: a claim the policy requires is absent.
	ErrMissingClaim = errors.New("saascentral: missing required claim")
)

// Authorization errors, used by the access-token and entitlement layers.
var (
	ErrInsufficientScope        = errors.New("saascentral: insufficient scope")
	ErrUnauthorizedProduct      = errors.New("saascentral: unauthorized product")
	ErrUnauthorizedOrganization = errors.New("saascentral: unauthorized organization")
	ErrSubscriptionInactive     = errors.New("saascentral: subscription inactive")
	ErrFeatureNotAllowed        = errors.New("saascentral: feature not allowed")
	ErrQuotaExceeded            = errors.New("saascentral: quota exceeded")
	// ErrStaleToken: the token's entitlement version is older than one the
	// product already knows (from the change feed).
	ErrStaleToken = errors.New("saascentral: stale entitlement token")
	// ErrInvalidClient: the client credentials were refused (unknown,
	// revoked, wrong secret or key).
	ErrInvalidClient = errors.New("saascentral: invalid client credentials")
	// ErrUnavailable: Central could not be reached or answered with a
	// server error, and nothing usable is cached.
	ErrUnavailable = errors.New("saascentral: central unavailable")
	// ErrNotFound: the tenant or resource is unknown (or not this client's).
	ErrNotFound = errors.New("saascentral: not found")
)
