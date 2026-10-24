// Package token verifies JWTs signed with Ed25519 (alg EdDSA) against
// keys from a trusted source, under a Policy that fixes everything a
// token could otherwise choose: the algorithm, the token type (typ), the
// key-ID prefix of the token class, the issuer, the audience and the
// required claims (RFC 8725, JWT best current practices).
//
// A verified token is authentic and current. It is not authorization:
// scopes, products, organizations and entitlements are checked by the
// layers above, with their own errors.
package token

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Arif9878/saas-central-go/jwks"
	"github.com/Arif9878/saas-central-go/scerrors"
)

// Token types (the typ header) of the tokens SaaS Central signs.
const (
	// TypeAccess is an OAuth 2.0 access token (RFC 9068).
	TypeAccess = "at+jwt"
	// TypeEntitlement is a signed subscription entitlement for one
	// organization and one product.
	TypeEntitlement = "entitlement+jwt"
	// TypeID is an OpenID Connect ID token ("Masuk dengan Nusa Karya"),
	// whose audience is the product's client_id.
	TypeID = "JWT"
)

// Key-ID prefixes: each token class has its own signing keys, so a key
// that signs one class can never verify a token of the other.
const (
	KeyPrefixAccess      = "at-"
	KeyPrefixEntitlement = "ent-"
	KeyPrefixID          = "id-"
)

// MaxTokenSize bounds what is parsed at all.
const MaxTokenSize = 8 << 10

// Policy is what a verified token must satisfy. Issuer, Audience, Type
// and KeyIDPrefix are required.
type Policy struct {
	// Issuer is the exact expected iss.
	Issuer string
	// Audience is the exact aud this verifier accepts (one of the token's).
	Audience string
	// Type is the expected typ header, such as TypeEntitlement. It is
	// compared case-insensitively, with or without "application/".
	Type string
	// KeyIDPrefix restricts the keys that may sign this token class.
	KeyIDPrefix string
	// Leeway tolerates clock skew in exp, nbf and iat (default 30 s, at
	// most 5 minutes).
	Leeway time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Verifier verifies tokens of one Policy.
type Verifier struct {
	keys   jwks.Source
	policy Policy
	parser *jwt.Parser
}

// New returns a Verifier for p with keys from src.
func New(src jwks.Source, p Policy) (*Verifier, error) {
	if src == nil || p.Issuer == "" || p.Audience == "" || p.Type == "" || p.KeyIDPrefix == "" {
		return nil, errors.New("saascentral/token: the policy needs a key source, Issuer, Audience, Type and KeyIDPrefix")
	}
	if p.Leeway == 0 {
		p.Leeway = 30 * time.Second
	}
	if p.Leeway < 0 || p.Leeway > 5*time.Minute {
		return nil, errors.New("saascentral/token: Leeway must be between 0 and 5 minutes")
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(p.Issuer),
		jwt.WithAudience(p.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(p.Leeway),
		jwt.WithStrictDecoding(),
	}
	if p.Now != nil {
		opts = append(opts, jwt.WithTimeFunc(p.Now))
	}
	return &Verifier{keys: src, policy: p, parser: jwt.NewParser(opts...)}, nil
}

// Claims is what Verify decodes into: a struct embedding
// jwt.RegisteredClaims, or RegisteredClaims itself.
type Claims interface {
	jwt.Claims
	registered() *jwt.RegisteredClaims
}

// Registered is jwt.RegisteredClaims satisfying Claims; embed it in
// claim structs.
type Registered struct {
	jwt.RegisteredClaims
}

func (r *Registered) registered() *jwt.RegisteredClaims { return &r.RegisteredClaims }

// Verify checks raw and decodes its claims into claims. Every error wraps
// one of the scerrors token errors.
func (v *Verifier) Verify(ctx context.Context, raw string, claims Claims) error {
	if len(raw) > MaxTokenSize || strings.Count(raw, ".") != 2 {
		return scerrors.ErrMalformedToken
	}
	var keyErr error
	_, err := v.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		k, err := v.key(ctx, t)
		keyErr = err
		return k, err
	})
	if keyErr != nil {
		return keyErr
	}
	if err != nil {
		return classify(err)
	}
	r := claims.registered()
	switch {
	case r.Subject == "":
		return fmt.Errorf("%w: sub", scerrors.ErrMissingClaim)
	case r.ID == "":
		return fmt.Errorf("%w: jti", scerrors.ErrMissingClaim)
	case r.IssuedAt == nil:
		return fmt.Errorf("%w: iat", scerrors.ErrMissingClaim)
	}
	return nil
}

// key checks the header, then returns the trusted key of its kid.
func (v *Verifier) key(ctx context.Context, t *jwt.Token) (ed25519.PublicKey, error) {
	// golang-jwt already refused algorithms other than EdDSA (WithValidMethods);
	// this keeps the check if that option ever changes.
	if alg, _ := t.Header["alg"].(string); alg != jwt.SigningMethodEdDSA.Alg() || t.Method != jwt.SigningMethodEdDSA {
		return nil, fmt.Errorf("%w: %v", scerrors.ErrUnsupportedAlgorithm, t.Header["alg"])
	}
	for _, h := range []string{"jwk", "jku", "x5u", "x5c", "crit"} {
		if _, ok := t.Header[h]; ok {
			return nil, fmt.Errorf("%w: %s", scerrors.ErrForbiddenHeader, h)
		}
	}
	typ, _ := t.Header["typ"].(string)
	if !sameType(typ, v.policy.Type) {
		return nil, fmt.Errorf("%w: %q", scerrors.ErrInvalidTokenType, typ)
	}
	kid, _ := t.Header["kid"].(string)
	if kid == "" || !strings.HasPrefix(kid, v.policy.KeyIDPrefix) {
		return nil, fmt.Errorf("%w: kid %q is not a %s key", scerrors.ErrUnknownKey, kid, v.policy.KeyIDPrefix)
	}
	return v.keys.Key(ctx, kid)
}

// sameType compares typ values as RFC 7515 §4.1.9 says: case-insensitive,
// "application/" optional.
func sameType(got, want string) bool {
	norm := func(s string) string { return strings.TrimPrefix(strings.ToLower(s), "application/") }
	return got != "" && norm(got) == norm(want)
}

// classify maps golang-jwt's errors to the SDK's.
func classify(err error) error {
	for _, m := range []struct{ lib, sdk error }{
		{jwt.ErrTokenMalformed, scerrors.ErrMalformedToken},
		{jwt.ErrTokenSignatureInvalid, scerrors.ErrInvalidSignature},
		{jwt.ErrTokenExpired, scerrors.ErrExpiredToken},
		{jwt.ErrTokenNotValidYet, scerrors.ErrNotYetValid},
		{jwt.ErrTokenUsedBeforeIssued, scerrors.ErrNotYetValid},
		{jwt.ErrTokenInvalidIssuer, scerrors.ErrInvalidIssuer},
		{jwt.ErrTokenInvalidAudience, scerrors.ErrInvalidAudience},
		{jwt.ErrTokenRequiredClaimMissing, scerrors.ErrMissingClaim},
		{jwt.ErrTokenInvalidClaims, scerrors.ErrMissingClaim},
		// An alg golang-jwt does not know, or none at all (key errors
		// are returned before this).
		{jwt.ErrTokenUnverifiable, scerrors.ErrUnsupportedAlgorithm},
	} {
		if errors.Is(err, m.lib) {
			// The signing-method refusal is reported as an invalid
			// signature by golang-jwt; name it.
			if errors.Is(m.lib, jwt.ErrTokenSignatureInvalid) && strings.Contains(err.Error(), "signing method") {
				return fmt.Errorf("%w: %w", scerrors.ErrUnsupportedAlgorithm, err)
			}
			return fmt.Errorf("%w: %w", m.sdk, err)
		}
	}
	return fmt.Errorf("%w: %w", scerrors.ErrMalformedToken, err)
}
