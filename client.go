// Package saascentral is the Go SDK for product backends (Bilas, the
// clinic app, the security APIs) integrating with SaaS Central.
//
//	client, err := saascentral.NewClient(
//		saascentral.WithBaseURL("https://platform.nusakarya.id"),
//		saascentral.WithClientCredentials(os.Getenv("CENTRAL_CLIENT_ID"), os.Getenv("CENTRAL_CLIENT_SECRET")),
//		saascentral.WithScopes("organization:read", "entitlement:read"),
//	)
//	org, err := client.ResolveTenant(ctx, "laundry", outletID)
//	ents, err := saascentral.NewEntitlements(client, "laundry")
//	go ents.Run(ctx) // follows the change feed
//	claims, err := ents.Get(ctx, org)
//	if err := claims.Require("reports"); err != nil { … }
//
// The client gets OAuth 2.0 access tokens with the client credentials
// grant and keeps them in memory until shortly before they expire;
// concurrent callers share one token request. Credentials stay in the
// process: they are never logged, never in error messages, and never sent
// anywhere but the configured token endpoint. Keep them server-side.
//
// Every error wraps a value of package scerrors, so callers branch with
// errors.Is; *APIError carries Central's status, code and request ID.
package saascentral

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Arif9878/saas-central-go/scerrors"
)

// Client calls SaaS Central's service API with an access token.
type Client struct {
	base       *url.URL
	http       *http.Client
	clientID   string
	secret     string
	key        *ecdsa.PrivateKey
	keyID      string
	scopes     []string
	refreshAt  time.Duration
	maxRetries int
	now        func() time.Time

	mu       sync.Mutex
	token    string
	expires  time.Time
	inflight *tokenCall
}

type tokenCall struct {
	done  chan struct{}
	token string
	err   error
}

// Option configures NewClient.
type Option func(*Client) error

// WithBaseURL is Central's URL (https; http only for localhost).
func WithBaseURL(raw string) Option {
	return func(c *Client) error {
		u, err := url.Parse(strings.TrimSuffix(raw, "/"))
		if err != nil || u.Host == "" {
			return fmt.Errorf("saascentral: invalid base URL %q", raw)
		}
		local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
		if u.Scheme != "https" && (u.Scheme != "http" || !local) {
			return errors.New("saascentral: the base URL must be https (credentials travel to it)")
		}
		c.base = u
		return nil
	}
}

// WithInsecureBaseURL allows any http URL, for tests only.
func WithInsecureBaseURL(raw string) Option {
	return func(c *Client) error {
		u, err := url.Parse(strings.TrimSuffix(raw, "/"))
		if err != nil || u.Host == "" {
			return fmt.Errorf("saascentral: invalid base URL %q", raw)
		}
		c.base = u
		return nil
	}
}

// WithClientCredentials authenticates with a client secret
// (client_secret_basic).
func WithClientCredentials(clientID, secret string) Option {
	return func(c *Client) error { c.clientID, c.secret = clientID, secret; return nil }
}

// WithPrivateKeyJWT authenticates with an ES256 key (private_key_jwt,
// RFC 7523); Central holds the public key under keyID.
func WithPrivateKeyJWT(clientID, keyID string, key *ecdsa.PrivateKey) Option {
	return func(c *Client) error { c.clientID, c.keyID, c.key = clientID, keyID, key; return nil }
}

// WithScopes are the scopes requested (all must be assigned to the client).
func WithScopes(scopes ...string) Option {
	return func(c *Client) error { c.scopes = scopes; return nil }
}

// WithHTTPClient sets the HTTP client (default: 10 s timeout).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) error { c.http = h; return nil } }

// WithRefreshBefore renews a token this long before it expires (default 60 s).
func WithRefreshBefore(d time.Duration) Option {
	return func(c *Client) error { c.refreshAt = d; return nil }
}

// WithRetries retries network errors and 5xx answers this many times
// (default 2), with a short backoff.
func WithRetries(n int) Option { return func(c *Client) error { c.maxRetries = n; return nil } }

// WithClock sets the clock, for tests.
func WithClock(now func() time.Time) Option { return func(c *Client) error { c.now = now; return nil } }

// NewClient returns a Client.
func NewClient(opts ...Option) (*Client, error) {
	c := &Client{http: &http.Client{Timeout: 10 * time.Second}, refreshAt: time.Minute, maxRetries: 2, now: time.Now}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	switch {
	case c.base == nil:
		return nil, errors.New("saascentral: WithBaseURL is required")
	case c.clientID == "" || (c.secret == "" && c.key == nil):
		return nil, errors.New("saascentral: WithClientCredentials or WithPrivateKeyJWT is required")
	case len(c.scopes) == 0:
		return nil, errors.New("saascentral: WithScopes is required (Central grants no default scope)")
	}
	return c, nil
}

// String keeps credentials out of logs and %v.
func (c *Client) String() string { return "saascentral.Client(" + c.clientID + ")" }

// Token returns a valid access token, requesting one when none is cached
// or the cached one expires within the refresh margin.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && c.now().Add(c.refreshAt).Before(c.expires) {
		t := c.token
		c.mu.Unlock()
		return t, nil
	}
	call := c.inflight
	if call == nil {
		call = &tokenCall{done: make(chan struct{})}
		c.inflight = call
		go func() {
			// Detached from the first caller's cancellation: others wait for it.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			tok, exp, err := c.requestToken(ctx)
			c.mu.Lock()
			if err == nil {
				c.token, c.expires = tok, exp
			}
			call.token, call.err = tok, err
			c.inflight = nil
			c.mu.Unlock()
			close(call.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.token, call.err
	case <-ctx.Done():
		return "", fmt.Errorf("%w: %w", scerrors.ErrUnavailable, ctx.Err())
	}
}

// forget drops the cached token (after Central refused it).
func (c *Client) forget(tok string) {
	c.mu.Lock()
	if c.token == tok {
		c.token = ""
	}
	c.mu.Unlock()
}

func (c *Client) requestToken(ctx context.Context) (string, time.Time, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {strings.Join(c.scopes, " ")}}
	endpoint := c.base.String() + "/oauth/token"
	if c.key != nil {
		assertion, err := c.assertion(endpoint)
		if err != nil {
			return "", time.Time{}, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}
	body := form.Encode()
	res, err := c.send(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		if c.key == nil {
			req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.secret))
		}
		return req, nil
	}, c.key == nil) // an assertion is single use: never resent
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &tr)
	if res.StatusCode != http.StatusOK || tr.AccessToken == "" {
		e := &APIError{Status: res.StatusCode, Code: tr.Error, Detail: tr.Description, RequestID: res.Header.Get("X-Request-Id")}
		switch tr.Error {
		case "invalid_client", "unauthorized_client":
			e.kind = scerrors.ErrInvalidClient
		case "invalid_scope":
			e.kind = scerrors.ErrInsufficientScope
		default:
			e.kind = scerrors.ErrUnavailable
		}
		return "", time.Time{}, e
	}
	return tr.AccessToken, c.now().Add(time.Duration(tr.ExpiresIn) * time.Second), nil
}

// assertion signs a private_key_jwt client assertion, valid 2 minutes.
func (c *Client) assertion(audience string) (string, error) {
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := c.now()
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer: c.clientID, Subject: c.clientID, Audience: jwt.ClaimStrings{audience}, ID: base64.RawURLEncoding.EncodeToString(jti),
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
	})
	t.Header["kid"] = c.keyID
	s, err := t.SignedString(c.key)
	if err != nil {
		return "", fmt.Errorf("saascentral: sign client assertion: %w", err)
	}
	return s, nil
}

// send performs a request, retrying network errors and 5xx answers when
// retry is true (the request is safe to repeat).
func (c *Client) send(ctx context.Context, build func() (*http.Request, error), retry bool) (*http.Response, error) {
	attempts := 1
	if retry {
		attempts += c.maxRetries
	}
	var last error
	for i := range attempts {
		if i > 0 {
			select {
			case <-time.After(time.Duration(i*i) * 200 * time.Millisecond):
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %w", scerrors.ErrUnavailable, ctx.Err())
			}
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		res, err := c.http.Do(req)
		if err != nil {
			last = fmt.Errorf("%w: %w", scerrors.ErrUnavailable, err)
			continue
		}
		if res.StatusCode >= 500 && i < attempts-1 {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			_ = res.Body.Close()
			last = fmt.Errorf("%w: status %d", scerrors.ErrUnavailable, res.StatusCode)
			continue
		}
		return res, nil
	}
	return nil, last
}

// APIError is an error answer from Central.
type APIError struct {
	Status    int
	Code      string // the problem code or OAuth error, such as unauthorized_organization
	Detail    string
	RequestID string
	kind      error
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("saascentral: %d %s", e.Status, e.Code)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.RequestID != "" {
		s += " (request " + e.RequestID + ")"
	}
	return s
}

// Unwrap returns the scerrors value of the error.
func (e *APIError) Unwrap() error { return e.kind }

// call sends method path with the access token and decodes the JSON
// answer into out. A token Central refuses is dropped and the call made
// once more with a new one.
func (c *Client) call(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.Token(ctx)
		if err != nil {
			return err
		}
		res, err := c.send(ctx, func() (*http.Request, error) {
			var rd io.Reader
			if payload != nil {
				rd = bytes.NewReader(payload)
			}
			req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, rd)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Accept", "application/json")
			if payload != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			return req, nil
		}, true) // the service API's calls are reads or idempotent
		if err != nil {
			return err
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		_ = res.Body.Close()
		if res.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.forget(tok)
			continue
		}
		if res.StatusCode >= 300 {
			return apiError(res, raw)
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%w: decode answer: %w", scerrors.ErrUnavailable, err)
		}
		return nil
	}
}

func apiError(res *http.Response, raw []byte) error {
	var p struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(raw, &p)
	e := &APIError{Status: res.StatusCode, Code: p.Code, Detail: p.Detail, RequestID: res.Header.Get("X-Request-Id")}
	for _, f := range p.Errors {
		if f.Field == "authorization" {
			e.Code = f.Message
		}
	}
	www := res.Header.Get("WWW-Authenticate")
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		e.kind = scerrors.ErrInvalidClient
	case strings.Contains(www, "insufficient_scope"):
		e.Code, e.kind = "insufficient_scope", scerrors.ErrInsufficientScope
	case e.Code == "unauthorized_product":
		e.kind = scerrors.ErrUnauthorizedProduct
	case e.Code == "unauthorized_organization":
		e.kind = scerrors.ErrUnauthorizedOrganization
	case res.StatusCode == http.StatusNotFound:
		e.kind = scerrors.ErrNotFound
	case res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests:
		e.kind = scerrors.ErrUnavailable
	default:
		e.kind = errors.New("saascentral: request refused")
	}
	return e
}

// --- service API ------------------------------------------------------------

// Identity is the calling client as Central sees it.
type Identity struct {
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	Products  []string  `json:"products"`
	ExpiresAt time.Time `json:"expires_at"`
}

// WhoAmI returns the client's effective scopes and products.
func (c *Client) WhoAmI(ctx context.Context) (Identity, error) {
	var id Identity
	return id, c.call(ctx, http.MethodGet, "/api/v1/service/whoami", nil, &id)
}

// ResolveTenant returns the organization of one of the product's own
// tenants (a Bilas outlet ID), if this client is granted it
// (organization:read). Unknown and ungranted tenants are scerrors.ErrNotFound.
func (c *Client) ResolveTenant(ctx context.Context, product, externalTenantID string) (string, error) {
	var out struct {
		OrganizationID string `json:"organization_id"`
	}
	err := c.call(ctx, http.MethodPost, "/api/v1/service/tenants/resolve", map[string]string{"product": product, "external_tenant_id": externalTenantID}, &out)
	return out.OrganizationID, err
}

// Decision is Central's answer for one feature.
type Decision struct {
	Feature string  `json:"feature"`
	Allowed bool    `json:"allowed"`
	Reason  *string `json:"reason"`
	Limit   *struct {
		Mode  string `json:"mode"`
		Value *int64 `json:"value,omitempty"`
	} `json:"limit,omitempty"`
	Overage string `json:"overage,omitempty"`
}

// CheckEntitlements asks Central online (entitlement:read): for sensitive
// operations, or when no entitlement token can be used.
func (c *Client) CheckEntitlements(ctx context.Context, orgID, product string, features ...string) ([]Decision, error) {
	var out struct {
		Results []Decision `json:"results"`
	}
	err := c.call(ctx, http.MethodPost, "/api/v1/service/entitlements/check",
		map[string]any{"organization_id": orgID, "product": product, "features": features}, &out)
	return out.Results, err
}

// EntitlementToken is a signed entitlement token and its expiry.
type EntitlementToken struct {
	Token              string    `json:"token"`
	ExpiresAt          time.Time `json:"expires_at"`
	EntitlementVersion int64     `json:"entitlement_version"`
	Audience           string    `json:"audience"`
}

// EntitlementToken requests a token for orgID in product (entitlement:read).
// Verify it with entitlements.Validator (or use Entitlements, which does).
func (c *Client) EntitlementToken(ctx context.Context, orgID, product string) (EntitlementToken, error) {
	var t EntitlementToken
	err := c.call(ctx, http.MethodPost, "/api/v1/service/entitlements/token", map[string]string{"organization_id": orgID, "product": product}, &t)
	return t, err
}

// Change is one entry of the entitlement change feed.
type Change struct {
	Seq                int64     `json:"seq"`
	OrganizationID     string    `json:"organization_id"`
	EntitlementVersion int64     `json:"entitlement_version"`
	Event              string    `json:"event"`
	CreatedAt          time.Time `json:"created_at"`
}

// Changes returns entitlement changes after seq for product, and the seq
// to continue after.
func (c *Client) Changes(ctx context.Context, product string, after int64) ([]Change, int64, error) {
	var out struct {
		Items     []Change `json:"items"`
		NextAfter int64    `json:"next_after"`
	}
	q := url.Values{"product": {product}, "after": {fmt.Sprint(after)}}
	err := c.call(ctx, http.MethodGet, "/api/v1/service/entitlements/changes?"+q.Encode(), nil, &out)
	return out.Items, out.NextAfter, err
}
