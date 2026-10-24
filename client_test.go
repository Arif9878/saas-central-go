package saascentral

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Arif9878/saas-central-go/jwks"
	"github.com/Arif9878/saas-central-go/scerrors"
	"github.com/Arif9878/saas-central-go/token"
)

// central is a fake of SaaS Central's token endpoint and service API.
type central struct {
	t        *testing.T
	srv      *httptest.Server
	key      ed25519.PrivateKey
	tokens   atomic.Int64 // token requests
	calls    atomic.Int64 // entitlement token requests
	down     atomic.Bool
	failNext atomic.Int64 // 503s to answer before succeeding
	ttl      int
	reject   atomic.Bool // answer 401 to the next service call
	version  atomic.Int64
	plan     atomic.Value
	lastForm atomic.Value
	mu       sync.Mutex
	changes  []Change
}

func newCentral(t *testing.T) *central {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	c := &central{t: t, key: key, ttl: 600}
	c.version.Store(1)
	c.plan.Store("basic")
	c.srv = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *central) serve(w http.ResponseWriter, r *http.Request) {
	if c.down.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if c.failNext.Load() > 0 {
		c.failNext.Add(-1)
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/oauth/token":
		c.tokens.Add(1)
		_ = r.ParseForm()
		c.lastForm.Store(r.PostForm)
		id, secret, basic := r.BasicAuth()
		if basic && (id != "laundry-backend" || secret != "scs_secret") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"Client authentication failed"}`))
			return
		}
		if strings.Contains(r.PostForm.Get("scope"), "invoice:read") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_scope"}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":"at-%d","token_type":"bearer","expires_in":%d}`, c.tokens.Load(), c.ttl)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at-") || c.reject.Swap(false) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"unauthorized"}`))
		return
	}
	switch r.URL.Path {
	case "/api/v1/service/whoami":
		_, _ = w.Write([]byte(`{"client_id":"laundry-backend","scopes":["entitlement:read"],"products":["laundry"]}`))
	case "/api/v1/service/tenants/resolve":
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["external_tenant_id"] != "outlet-a" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found","detail":"No organization is known for this tenant."}`))
			return
		}
		_, _ = w.Write([]byte(`{"organization_id":"org-a"}`))
	case "/api/v1/service/entitlements/token":
		c.calls.Add(1)
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["organization_id"] == "org-b" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"forbidden","errors":[{"field":"authorization","message":"unauthorized_organization"}]}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"token":%q,"expires_at":"%s","entitlement_version":%d}`, c.sign(req["organization_id"], 5*time.Minute),
			time.Now().Add(5*time.Minute).Format(time.RFC3339), c.version.Load())
	case "/api/v1/service/entitlements/check":
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="entitlement:read"`)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"forbidden"}`))
	case "/api/v1/service/entitlements/changes":
		c.mu.Lock()
		defer c.mu.Unlock()
		var after int64
		_, _ = fmt.Sscan(r.URL.Query().Get("after"), &after)
		out := []Change{}
		next := after
		for _, ch := range c.changes {
			if ch.Seq > after {
				out = append(out, ch)
				next = ch.Seq
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": out, "next_after": next})
	default:
		http.NotFound(w, r)
	}
}

func (c *central) sign(org string, ttl time.Duration) string {
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": c.srv.URL, "sub": org, "aud": "laundry-api", "jti": fmt.Sprint(now.UnixNano()), "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(ttl).Unix(), "product": "laundry", "basis": "subscription", "subscription_status": "active",
		"plan": c.plan.Load(), "entitlement_version": c.version.Load(),
		"features": map[string]any{"reports": map[string]any{"kind": "boolean", "enabled": c.plan.Load() == "pro"}},
	})
	t.Header["kid"], t.Header["typ"] = "ent-1", token.TypeEntitlement
	s, err := t.SignedString(c.key)
	if err != nil {
		c.t.Fatal(err)
	}
	return s
}

func (c *central) client(t *testing.T, opts ...Option) *Client {
	t.Helper()
	cl, err := NewClient(append([]Option{WithInsecureBaseURL(c.srv.URL), WithClientCredentials("laundry-backend", "scs_secret"),
		WithScopes("organization:read", "entitlement:read")}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func TestTokenCaching(t *testing.T) {
	c := newCentral(t)
	cl := c.client(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if _, err := cl.WhoAmI(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := c.tokens.Load(); n != 1 {
		t.Errorf("50 concurrent calls made %d token requests, want 1", n)
	}
	if f := c.lastForm.Load().(url.Values); f["grant_type"][0] != "client_credentials" || f["scope"][0] != "organization:read entitlement:read" {
		t.Errorf("token form = %v", f)
	}
	// Refreshed before it expires.
	now := time.Now()
	cl.now = func() time.Time { return now.Add(9*time.Minute + 30*time.Second) }
	if _, err := cl.WhoAmI(ctx); err != nil {
		t.Fatal(err)
	}
	if n := c.tokens.Load(); n != 2 {
		t.Errorf("token requests after the refresh margin = %d", n)
	}
	// A token Central refuses is replaced once.
	c.reject.Store(true)
	if _, err := cl.WhoAmI(ctx); err != nil {
		t.Errorf("after a refused token: %v", err)
	}
	if n := c.tokens.Load(); n != 3 {
		t.Errorf("token requests after a 401 = %d", n)
	}
}

func TestClientErrors(t *testing.T) {
	c := newCentral(t)
	ctx := context.Background()
	bad, _ := NewClient(WithInsecureBaseURL(c.srv.URL), WithClientCredentials("laundry-backend", "wrong-secret"), WithScopes("entitlement:read"))
	_, err := bad.WhoAmI(ctx)
	var apiErr *APIError
	if !errors.Is(err, scerrors.ErrInvalidClient) || !errors.As(err, &apiErr) || apiErr.Code != "invalid_client" {
		t.Errorf("wrong secret: %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "wrong-secret") || strings.Contains(fmt.Sprintf("%v %+v", bad, bad), "wrong-secret") {
		t.Error("the secret appears in an error or the client's formatting")
	}
	scoped, _ := NewClient(WithInsecureBaseURL(c.srv.URL), WithClientCredentials("laundry-backend", "scs_secret"), WithScopes("invoice:read"))
	if _, err := scoped.WhoAmI(ctx); !errors.Is(err, scerrors.ErrInsufficientScope) {
		t.Errorf("unassigned scope: %v", err)
	}
	cl := c.client(t)
	if _, err := cl.ResolveTenant(ctx, "laundry", "outlet-z"); !errors.Is(err, scerrors.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	if org, err := cl.ResolveTenant(ctx, "laundry", "outlet-a"); err != nil || org != "org-a" {
		t.Errorf("resolve = %q %v", org, err)
	}
	if _, err := cl.EntitlementToken(ctx, "org-b", "laundry"); !errors.Is(err, scerrors.ErrUnauthorizedOrganization) {
		t.Errorf("ungranted organization: %v", err)
	}
	if _, err := cl.CheckEntitlements(ctx, "org-a", "laundry", "reports"); !errors.Is(err, scerrors.ErrInsufficientScope) {
		t.Errorf("missing scope: %v", err)
	}
	// Retries: two 503s, then success.
	c.failNext.Store(2)
	if _, err := cl.ResolveTenant(ctx, "laundry", "outlet-a"); err != nil {
		t.Errorf("after transient 503s: %v", err)
	}
	c.down.Store(true)
	if _, err := cl.ResolveTenant(ctx, "laundry", "outlet-a"); !errors.Is(err, scerrors.ErrUnavailable) {
		t.Errorf("Central down: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.client(t).Token(cctx); !errors.Is(err, scerrors.ErrUnavailable) {
		t.Errorf("cancelled context: %v", err)
	}
}

func TestNewClientChecks(t *testing.T) {
	for name, opts := range map[string][]Option{
		"no base URL":    {WithClientCredentials("a", "b"), WithScopes("x:y")},
		"http base URL":  {WithBaseURL("http://central.example"), WithClientCredentials("a", "b"), WithScopes("x:y")},
		"no credentials": {WithBaseURL("https://central.example"), WithScopes("x:y")},
		"no scopes":      {WithBaseURL("https://central.example"), WithClientCredentials("a", "b")},
	} {
		if _, err := NewClient(opts...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewClient(WithBaseURL("http://localhost:8080"), WithClientCredentials("a", "b"), WithScopes("x:y")); err != nil {
		t.Errorf("localhost over http: %v", err)
	}
}

func TestPrivateKeyJWT(t *testing.T) {
	c := newCentral(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cl, err := NewClient(WithInsecureBaseURL(c.srv.URL), WithPrivateKeyJWT("laundry-backend", "k1", key), WithScopes("entitlement:read"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := c.lastForm.Load().(url.Values)
	if f["client_assertion_type"][0] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("form = %v", f)
	}
	parsed, err := jwt.Parse(f["client_assertion"][0], func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatal(err)
	}
	cl2 := parsed.Claims.(jwt.MapClaims)
	if cl2["iss"] != "laundry-backend" || cl2["sub"] != "laundry-backend" || cl2["aud"].([]any)[0] != c.srv.URL+"/oauth/token" || cl2["jti"] == "" || parsed.Header["kid"] != "k1" {
		t.Errorf("assertion = %v %v", parsed.Header, cl2)
	}
	if exp, _ := cl2.GetExpirationTime(); time.Until(exp.Time) > 2*time.Minute+time.Second {
		t.Error("the assertion lives longer than 2 minutes")
	}
	// An assertion is never resent: a 503 is not retried.
	c.failNext.Store(1)
	cl.forget(cl.token)
	cl.mu.Lock()
	cl.token = ""
	cl.mu.Unlock()
	before := c.tokens.Load()
	if _, err := cl.Token(context.Background()); !errors.Is(err, scerrors.ErrUnavailable) {
		t.Errorf("503 with an assertion: %v", err)
	}
	if c.tokens.Load() != before {
		t.Error("an assertion was resent")
	}
}

func TestEntitlementsCache(t *testing.T) {
	c := newCentral(t)
	cl := c.client(t)
	ents, err := NewEntitlements(cl, "laundry", WithKeySource(jwks.Static{"ent-1": c.key.Public().(ed25519.PublicKey)}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := ents.Get(ctx, "org-a"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := c.calls.Load(); n != 1 {
		t.Errorf("20 concurrent Gets fetched %d tokens, want 1", n)
	}
	claims, _ := ents.Get(ctx, "org-a")
	if claims.Organization() != "org-a" || claims.HasFeature("reports") {
		t.Errorf("claims = %+v", claims)
	}
	if _, err := ents.Get(ctx, "org-b"); !errors.Is(err, scerrors.ErrUnauthorizedOrganization) {
		t.Errorf("ungranted organization: %v", err)
	}

	// A change in the feed drops the cached token and demands the new version.
	c.plan.Store("pro")
	c.version.Store(2)
	c.mu.Lock()
	c.changes = append(c.changes, Change{Seq: 1, OrganizationID: "org-a", EntitlementVersion: 2, Event: "plan_changed"})
	c.mu.Unlock()
	if err := ents.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	claims, err = ents.Get(ctx, "org-a")
	if err != nil || !claims.HasFeature("reports") || claims.EntitlementVersion != 2 {
		t.Fatalf("after the change: %v %+v", err, claims)
	}
	// A token older than the feed's version is refused, not cached.
	c.version.Store(1)
	c.mu.Lock()
	c.changes = append(c.changes, Change{Seq: 2, OrganizationID: "org-a", EntitlementVersion: 3, Event: "extended"})
	c.mu.Unlock()
	_ = ents.Poll(ctx)
	if _, err := ents.Get(ctx, "org-a"); !errors.Is(err, scerrors.ErrStaleToken) {
		t.Errorf("stale token from Central: %v", err)
	}
	c.version.Store(3)

	// Central down: the cached token serves until it expires, then Get fails.
	if _, err := ents.Get(ctx, "org-a"); err != nil {
		t.Fatal(err)
	}
	c.down.Store(true)
	start := time.Now()
	ents.now = func() time.Time { return start.Add(4*time.Minute + 45*time.Second) } // inside the refresh margin
	if _, err := ents.Get(ctx, "org-a"); err != nil {
		t.Errorf("outage with a valid cached token: %v", err)
	}
	ents.now = func() time.Time { return start.Add(6 * time.Minute) }
	if _, err := ents.Get(ctx, "org-a"); !errors.Is(err, scerrors.ErrUnavailable) {
		t.Errorf("outage after expiry: %v", err)
	}
}
