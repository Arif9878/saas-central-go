// Package jwks keeps the public keys of a trusted JSON Web Key Set, for
// verifying tokens locally. The set's URL is configured by the service,
// never taken from a token.
//
// Only Ed25519 signing keys (kty OKP, crv Ed25519) are used; other keys in
// the set are ignored, and a set that contains private key material is
// refused. Keys are cached for the set's Cache-Control max-age (bounded by
// MinTTL and MaxTTL) and fetched again with If-None-Match. A token with an
// unknown kid triggers a refresh at most once per MinRefreshInterval, and
// concurrent refreshes share one request, so made-up kids cannot flood
// the issuer. When a refresh fails, the cached keys stay in use for
// MaxStale after they expire, then lookups fail closed.
package jwks

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Arif9878/saas-central-go/scerrors"
)

// Source returns the trusted public key with a key ID.
type Source interface {
	Key(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

// Static is a fixed set of keys, for tests and pinned deployments.
type Static map[string]ed25519.PublicKey

// Key implements Source.
func (s Static) Key(_ context.Context, kid string) (ed25519.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %q", scerrors.ErrUnknownKey, kid)
}

// Cache is a Source backed by a JWKS URL. It is safe for concurrent use.
type Cache struct {
	url    string
	client *http.Client
	o      options

	mu          sync.Mutex
	keys        map[string]ed25519.PublicKey
	etag        string
	expiresAt   time.Time
	lastAttempt time.Time
	inflight    *refresh
}

type refresh struct {
	done chan struct{}
	err  error
}

type options struct {
	client             *http.Client
	defaultTTL         time.Duration
	minTTL, maxTTL     time.Duration
	minRefreshInterval time.Duration
	maxStale           time.Duration
	fetchTimeout       time.Duration
	insecureHTTP       bool
	now                func() time.Time
}

// Option configures New.
type Option func(*options)

// WithHTTPClient sets the client for fetching the set.
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.client = c } }

// WithTTL bounds how long a fetched set is used before it is fetched
// again: the response's max-age, clamped to [min, max]; def without one.
// Defaults: 5 minutes, between 1 minute and 1 hour.
func WithTTL(def, minTTL, maxTTL time.Duration) Option {
	return func(o *options) { o.defaultTTL, o.minTTL, o.maxTTL = def, minTTL, maxTTL }
}

// WithMinRefreshInterval is the least time between refreshes caused by
// unknown kids (default 30 seconds).
func WithMinRefreshInterval(d time.Duration) Option {
	return func(o *options) { o.minRefreshInterval = d }
}

// WithMaxStale is how long expired keys stay in use while the set cannot
// be fetched (default 1 hour). Longer keeps verification working through
// longer outages of the issuer, but also keeps trusting a key the issuer
// has revoked for as long.
func WithMaxStale(d time.Duration) Option { return func(o *options) { o.maxStale = d } }

// WithInsecureHTTP allows an http:// URL, for local development and tests.
func WithInsecureHTTP() Option { return func(o *options) { o.insecureHTTP = true } }

// WithClock sets the clock, for tests.
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// New returns a Cache for the set at rawURL, which must be https. Keys are
// fetched on first use.
func New(rawURL string, opts ...Option) (*Cache, error) {
	o := options{
		defaultTTL: 5 * time.Minute, minTTL: time.Minute, maxTTL: time.Hour,
		minRefreshInterval: 30 * time.Second, maxStale: time.Hour, fetchTimeout: 10 * time.Second,
		now: time.Now,
	}
	for _, opt := range opts {
		opt(&o)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !o.insecureHTTP)) {
		return nil, fmt.Errorf("saascentral/jwks: the JWKS URL must be an absolute https URL, got %q", rawURL)
	}
	if o.client == nil {
		o.client = &http.Client{Timeout: o.fetchTimeout}
	}
	return &Cache{url: rawURL, client: o.client, o: o}, nil
}

// Key implements Source.
func (c *Cache) Key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	c.mu.Lock()
	now := c.o.now()
	k, found := c.keys[kid]
	fresh := c.keys != nil && now.Before(c.expiresAt)
	switch {
	case found && fresh:
		c.mu.Unlock()
		return k, nil
	case fresh && c.inflight == nil && now.Sub(c.lastAttempt) < c.o.minRefreshInterval:
		// A kid the current set lacks, refreshed recently: unknown. (While
		// a refresh runs, wait for it: it may bring the kid.)
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %q", scerrors.ErrUnknownKey, kid)
	}
	r := c.start()
	c.mu.Unlock()

	select {
	case <-r.done:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", scerrors.ErrKeysUnavailable, ctx.Err())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now = c.o.now()
	k, found = c.keys[kid]
	usable := c.keys != nil && now.Before(c.expiresAt.Add(c.o.maxStale))
	switch {
	case found && (r.err == nil || usable):
		return k, nil
	case r.err != nil && !usable:
		return nil, fmt.Errorf("%w: %w", scerrors.ErrKeysUnavailable, r.err)
	default:
		return nil, fmt.Errorf("%w: %q", scerrors.ErrUnknownKey, kid)
	}
}

// Refresh fetches the set now (sharing a refresh already in progress), for
// example when the issuer announces a revoked key.
func (c *Cache) Refresh(ctx context.Context) error {
	c.mu.Lock()
	r := c.start()
	c.mu.Unlock()
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// start begins a refresh unless one is running; c.mu is held.
func (c *Cache) start() *refresh {
	if c.inflight != nil {
		return c.inflight
	}
	r := &refresh{done: make(chan struct{})}
	c.inflight = r
	c.lastAttempt = c.o.now()
	etag := c.etag
	go func() {
		// Not the caller's context: one cancelled request must not fail
		// the refresh the others wait for.
		ctx, cancel := context.WithTimeout(context.Background(), c.o.fetchTimeout)
		defer cancel()
		keys, newETag, ttl, err := c.fetch(ctx, etag)
		c.mu.Lock()
		if err == nil {
			if keys != nil { // nil: 304, the cached keys are current
				c.keys, c.etag = keys, newETag
			}
			c.expiresAt = c.o.now().Add(ttl)
		}
		r.err = err
		c.inflight = nil
		c.mu.Unlock()
		close(r.done)
	}()
	return r
}

const maxBody = 1 << 20

func (c *Cache) fetch(ctx context.Context, etag string) (map[string]ed25519.PublicKey, string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	ttl := c.ttl(res.Header.Get("Cache-Control"))
	if res.StatusCode == http.StatusNotModified && etag != "" {
		return nil, etag, ttl, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("fetch JWKS: status %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, "", 0, fmt.Errorf("read JWKS: %w", err)
	}
	if len(body) > maxBody {
		return nil, "", 0, errors.New("JWKS larger than 1 MiB")
	}
	keys, err := Parse(body)
	if err != nil {
		return nil, "", 0, err
	}
	return keys, res.Header.Get("ETag"), ttl, nil
}

func (c *Cache) ttl(cacheControl string) time.Duration {
	ttl := c.o.defaultTTL
	for _, d := range strings.Split(cacheControl, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(strings.ToLower(d)), "max-age="); ok {
			if s, err := strconv.Atoi(v); err == nil && s >= 0 {
				ttl = time.Duration(s) * time.Second
			}
		}
	}
	return min(max(ttl, c.o.minTTL), c.o.maxTTL)
}

// JWK is the subset of a JSON Web Key this package reads.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	X   string `json:"x,omitempty"`
	// D is the private key: present means the set is misconfigured.
	D string `json:"d,omitempty"`
}

// Parse reads a JWK Set and returns its Ed25519 signing keys by kid. It
// refuses sets with private key material, duplicate kids, malformed
// Ed25519 keys, or no usable key.
func Parse(body []byte) (map[string]ed25519.PublicKey, error) {
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.D != "" {
			return nil, fmt.Errorf("JWKS key %q contains private key material", k.Kid)
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Alg != "" && k.Alg != "EdDSA") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if k.Kid == "" || len(k.Kid) > 128 {
			return nil, errors.New("JWKS Ed25519 key without a valid kid")
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("JWKS key %q: invalid Ed25519 public key", k.Kid)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, fmt.Errorf("JWKS has two keys with kid %q", k.Kid)
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no Ed25519 signing key")
	}
	return keys, nil
}
