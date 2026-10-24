package entitlements

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Arif9878/saas-central-go/jwks"
	"github.com/Arif9878/saas-central-go/scerrors"
	"github.com/Arif9878/saas-central-go/token"
)

const iss = "https://platform.example.com"

var now = time.Unix(1_800_000_000, 0)

func setup(t *testing.T) (ed25519.PrivateKey, *Validator, func(map[string]any, map[string]any) string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	v, err := NewValidator(WithIssuer(iss), WithProduct("laundry"), WithKeySource(jwks.Static{"ent-1": pub}),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	sign := func(header, override map[string]any) string {
		c := jwt.MapClaims{"iss": iss, "sub": "org-a", "aud": "laundry-api", "jti": "j", "iat": now.Unix(), "nbf": now.Unix(),
			"exp": now.Add(5 * time.Minute).Unix(), "product": "laundry", "subscription_status": "active", "basis": "subscription",
			"plan": "pro", "entitlement_version": 7, "features": map[string]any{
				"outlets": map[string]any{"kind": "limit", "enabled": true, "limit": map[string]any{"mode": "limited", "value": 5}},
				"tx":      map[string]any{"kind": "metered", "enabled": true, "limit": map[string]any{"mode": "unlimited"}, "overage": "block"},
				"reports": map[string]any{"kind": "boolean", "enabled": false},
			}}
		for k, v := range override {
			c[k] = v
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
		tok.Header["typ"], tok.Header["kid"] = token.TypeEntitlement, "ent-1"
		for k, v := range header {
			tok.Header[k] = v
		}
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return key, v, sign
}

func TestVerify(t *testing.T) {
	_, v, sign := setup(t)
	ctx := context.Background()
	c, err := v.Verify(ctx, sign(nil, nil), ForOrganization("org-a"), MinVersion(7))
	if err != nil {
		t.Fatal(err)
	}
	if c.Organization() != "org-a" || c.Plan != "pro" || !c.HasFeature("outlets") || c.HasFeature("reports") || c.HasFeature("nope") {
		t.Errorf("claims = %+v", c)
	}
	if n, unl, ok := c.Limit("outlets"); n != 5 || unl || !ok {
		t.Errorf("Limit(outlets) = %d %v %v", n, unl, ok)
	}
	if _, unl, ok := c.Limit("tx"); !unl || !ok {
		t.Error("tx should be unlimited")
	}
	if err := c.WithinLimit("outlets", 4); err != nil {
		t.Errorf("4 of 5: %v", err)
	}
	if err := c.WithinLimit("outlets", 5); !errors.Is(err, scerrors.ErrQuotaExceeded) {
		t.Errorf("5 of 5: %v", err)
	}
	if err := c.WithinLimit("tx", 1_000_000); err != nil {
		t.Errorf("unlimited: %v", err)
	}
	if err := c.Require("reports"); !errors.Is(err, scerrors.ErrFeatureNotAllowed) {
		t.Errorf("disabled: %v", err)
	}

	for name, tc := range map[string]struct {
		tok  string
		opts []VerifyOption
		want error
	}{
		"another organization":  {sign(nil, nil), []VerifyOption{ForOrganization("org-b")}, scerrors.ErrUnauthorizedOrganization},
		"another product claim": {sign(nil, map[string]any{"product": "clinic"}), nil, scerrors.ErrUnauthorizedProduct},
		"another audience":      {sign(nil, map[string]any{"aud": "clinic-api"}), nil, scerrors.ErrInvalidAudience},
		"stale version":         {sign(nil, nil), []VerifyOption{MinVersion(8)}, scerrors.ErrStaleToken},
		"access token":          {sign(map[string]any{"typ": token.TypeAccess}, nil), nil, scerrors.ErrInvalidTokenType},
		"access key":            {sign(map[string]any{"kid": "at-1"}, nil), nil, scerrors.ErrUnknownKey},
		"expired":               {sign(nil, map[string]any{"exp": now.Add(-time.Minute).Unix()}), nil, scerrors.ErrExpiredToken},
		"other issuer":          {sign(nil, map[string]any{"iss": "https://evil.example"}), nil, scerrors.ErrInvalidIssuer},
	} {
		if _, err := v.Verify(ctx, tc.tok, tc.opts...); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	none, err := v.Verify(ctx, sign(nil, map[string]any{"basis": "none", "subscription_status": "expired", "features": map[string]any{}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := none.Require("outlets"); !errors.Is(err, scerrors.ErrSubscriptionInactive) {
		t.Errorf("no basis: %v", err)
	}
}

func TestNewValidatorRequires(t *testing.T) {
	for _, opts := range [][]Option{
		{WithProduct("laundry"), WithKeySource(jwks.Static{})},
		{WithIssuer(iss), WithKeySource(jwks.Static{})},
		{WithIssuer(iss), WithProduct("laundry")},
		{WithIssuer(iss), WithProduct("laundry"), WithJWKSURL("http://insecure.example/jwks.json")},
	} {
		if _, err := NewValidator(opts...); err == nil {
			t.Error("an incomplete validator was built")
		}
	}
}
