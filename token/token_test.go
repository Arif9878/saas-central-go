package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Arif9878/saas-central-go/jwks"
	"github.com/Arif9878/saas-central-go/scerrors"
)

const (
	issuer = "https://platform.example.com"
	kidEnt = "ent-test-1"
	kidAt  = "at-test-1"
)

var now = time.Unix(1_800_000_000, 0)

type fixture struct {
	entKey, atKey, otherKey ed25519.PrivateKey
	keys                    jwks.Static
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	gen := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	f := fixture{entKey: gen(), atKey: gen(), otherKey: gen()}
	f.keys = jwks.Static{kidEnt: f.entKey.Public().(ed25519.PublicKey), kidAt: f.atKey.Public().(ed25519.PublicKey)}
	return f
}

func claimsAt(t time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": issuer, "sub": "org_1", "aud": "laundry-api", "jti": "j1",
		"iat": t.Unix(), "nbf": t.Unix(), "exp": t.Add(5 * time.Minute).Unix(),
	}
}

func sign(t testing.TB, key any, method jwt.SigningMethod, header map[string]any, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["typ"] = TypeEntitlement
	tok.Header["kid"] = kidEnt
	for k, v := range header {
		if v == nil {
			delete(tok.Header, k)
		} else {
			tok.Header[k] = v
		}
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f fixture) verifier(t testing.TB) *Verifier {
	t.Helper()
	v, err := New(f.keys, Policy{Issuer: issuer, Audience: "laundry-api", Type: TypeEntitlement,
		KeyIDPrefix: KeyPrefixEntitlement, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// rawSegments builds a token from a header and claims as given, with the
// signature of key over them (nil key: an empty signature).
func rawSegments(t *testing.T, header, claims map[string]any, key ed25519.PrivateKey) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	sig := ""
	if key != nil {
		sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(signing)))
	}
	return signing + "." + sig
}

func TestVerify(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	valid := sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, claimsAt(now))
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := f.keys[kidEnt]
	parts := strings.Split(valid, ".")

	with := func(mod func(jwt.MapClaims)) jwt.MapClaims {
		c := claimsAt(now)
		mod(c)
		return c
	}
	hmacWithPublicKey, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsAt(now)).SignedString([]byte(pub))
	noneToken := rawSegments(t, map[string]any{"alg": "none", "typ": TypeEntitlement, "kid": kidEnt}, claimsAt(now), nil)
	// Another organization's claims under the original signature.
	forged, _ := json.Marshal(with(func(c jwt.MapClaims) { c["sub"] = "org_2" }))
	payload := base64.RawURLEncoding.EncodeToString(forged)
	tamperedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"ent-test-1","typ":"at+jwt"}`))

	for _, tc := range []struct {
		name  string
		token string
		want  error
	}{
		{"valid", valid, nil},
		{"application/ prefix and case in typ", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"typ": "application/Entitlement+JWT"}, claimsAt(now)), nil},
		{"invalid signature (other key, same kid)", sign(t, f.otherKey, jwt.SigningMethodEdDSA, nil, claimsAt(now)), scerrors.ErrInvalidSignature},
		{"modified payload", parts[0] + "." + payload + "." + parts[2], scerrors.ErrInvalidSignature},
		{"modified header", tamperedHeader + "." + parts[1] + "." + parts[2], scerrors.ErrInvalidTokenType},
		{"modified header, same typ", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"ent-test-1","typ":"entitlement+jwt","x":1}`)) + "." + parts[1] + "." + parts[2], scerrors.ErrInvalidSignature},
		{"truncated signature", parts[0] + "." + parts[1] + "." + parts[2][:20], scerrors.ErrInvalidSignature},
		{"unknown kid", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"kid": "ent-unknown"}, claimsAt(now)), scerrors.ErrUnknownKey},
		{"missing kid", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"kid": nil}, claimsAt(now)), scerrors.ErrUnknownKey},
		{"access-token key (token class confusion)", sign(t, f.atKey, jwt.SigningMethodEdDSA, map[string]any{"kid": kidAt}, claimsAt(now)), scerrors.ErrUnknownKey},
		{"alg none", noneToken, scerrors.ErrUnsupportedAlgorithm},
		{"HS256 keyed with the public key", hmacWithPublicKey, scerrors.ErrUnsupportedAlgorithm},
		{"RS256", sign(t, rsaKey, jwt.SigningMethodRS256, nil, claimsAt(now)), scerrors.ErrUnsupportedAlgorithm},
		{"ES256", sign(t, ecKey, jwt.SigningMethodES256, nil, claimsAt(now)), scerrors.ErrUnsupportedAlgorithm},
		{"unknown alg", rawSegments(t, map[string]any{"alg": "Ed448", "typ": TypeEntitlement, "kid": kidEnt}, claimsAt(now), f.entKey), scerrors.ErrUnsupportedAlgorithm},
		{"embedded jwk", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"jwk": map[string]string{"kty": "OKP"}}, claimsAt(now)), scerrors.ErrForbiddenHeader},
		{"jku", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"jku": "https://evil.example/jwks.json"}, claimsAt(now)), scerrors.ErrForbiddenHeader},
		{"x5u", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"x5u": "https://evil.example/cert"}, claimsAt(now)), scerrors.ErrForbiddenHeader},
		{"crit", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"crit": []string{"exp"}}, claimsAt(now)), scerrors.ErrForbiddenHeader},
		{"malformed", "not.a.jwt", scerrors.ErrMalformedToken},
		{"two segments", parts[0] + "." + parts[1], scerrors.ErrMalformedToken},
		{"oversized", strings.Repeat("a", MaxTokenSize) + ".b.c", scerrors.ErrMalformedToken},
		{"expired", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, claimsAt(now.Add(-10*time.Minute))), scerrors.ErrExpiredToken},
		{"expired within leeway", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["exp"] = now.Add(-20 * time.Second).Unix() })), nil},
		{"not yet valid", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Minute).Unix() })), scerrors.ErrNotYetValid},
		{"issued in the future", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["iat"] = now.Add(time.Hour).Unix() })), scerrors.ErrNotYetValid},
		{"wrong issuer", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["iss"] = "https://platform.example.com.evil" })), scerrors.ErrInvalidIssuer},
		{"wrong audience (another product)", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["aud"] = "clinic-api" })), scerrors.ErrInvalidAudience},
		{"audience substring", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["aud"] = "laundry-api-staging" })), scerrors.ErrInvalidAudience},
		{"one of several audiences", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { c["aud"] = []string{"clinic-api", "laundry-api"} })), nil},
		{"missing audience", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { delete(c, "aud") })), scerrors.ErrMissingClaim},
		{"missing exp", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { delete(c, "exp") })), scerrors.ErrMissingClaim},
		{"missing sub", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { delete(c, "sub") })), scerrors.ErrMissingClaim},
		{"missing jti", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { delete(c, "jti") })), scerrors.ErrMissingClaim},
		{"missing iat", sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, with(func(c jwt.MapClaims) { delete(c, "iat") })), scerrors.ErrMissingClaim},
		{"wrong typ (access token)", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"typ": TypeAccess}, claimsAt(now)), scerrors.ErrInvalidTokenType},
		{"generic JWT typ", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"typ": "JWT"}, claimsAt(now)), scerrors.ErrInvalidTokenType},
		{"missing typ", sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"typ": nil}, claimsAt(now)), scerrors.ErrInvalidTokenType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Registered
			err := v.Verify(context.Background(), tc.token, &c)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Verify = %v", err)
				}
				if c.Subject != "org_1" || c.ID != "j1" {
					t.Errorf("claims = %+v", c)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestTokenSeparation: the access-token verifier refuses entitlement
// tokens and the other way round, even when every other claim matches.
func TestTokenSeparation(t *testing.T) {
	f := newFixture(t)
	access, err := New(f.keys, Policy{Issuer: issuer, Audience: "laundry-api", Type: TypeAccess, KeyIDPrefix: KeyPrefixAccess,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ent := f.verifier(t)
	entTok := sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, claimsAt(now))
	atTok := sign(t, f.atKey, jwt.SigningMethodEdDSA, map[string]any{"typ": TypeAccess, "kid": kidAt}, claimsAt(now))
	var c Registered
	if err := access.Verify(context.Background(), atTok, &c); err != nil {
		t.Fatalf("access token: %v", err)
	}
	if err := ent.Verify(context.Background(), atTok, &c); !errors.Is(err, scerrors.ErrInvalidTokenType) {
		t.Errorf("access token accepted as entitlement: %v", err)
	}
	if err := access.Verify(context.Background(), entTok, &c); !errors.Is(err, scerrors.ErrInvalidTokenType) {
		t.Errorf("entitlement accepted as access token: %v", err)
	}
	// Even relabelled, a token signed with the other class's key is refused.
	relabelled := sign(t, f.entKey, jwt.SigningMethodEdDSA, map[string]any{"typ": TypeAccess}, claimsAt(now))
	if err := access.Verify(context.Background(), relabelled, &c); !errors.Is(err, scerrors.ErrUnknownKey) {
		t.Errorf("an entitlement key signed an access token: %v", err)
	}
}

func TestPolicyRequired(t *testing.T) {
	f := newFixture(t)
	for _, p := range []Policy{
		{Audience: "a", Type: TypeAccess, KeyIDPrefix: "at-"},
		{Issuer: issuer, Type: TypeAccess, KeyIDPrefix: "at-"},
		{Issuer: issuer, Audience: "a", KeyIDPrefix: "at-"},
		{Issuer: issuer, Audience: "a", Type: TypeAccess},
		{Issuer: issuer, Audience: "a", Type: TypeAccess, KeyIDPrefix: "at-", Leeway: time.Hour},
	} {
		if _, err := New(f.keys, p); err == nil {
			t.Errorf("New(%+v) accepted an incomplete policy", p)
		}
	}
}

func TestConcurrentVerify(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	tok := sign(t, f.entKey, jwt.SigningMethodEdDSA, nil, claimsAt(now))
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 50 {
				var c Registered
				if err := v.Verify(context.Background(), tok, &c); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkVerify(b *testing.B) {
	f := newFixture(b)
	v := f.verifier(b)
	tok := sign(b, f.entKey, jwt.SigningMethodEdDSA, nil, claimsAt(now))
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		var c Registered
		if err := v.Verify(ctx, tok, &c); err != nil {
			b.Fatal(err)
		}
	}
}
