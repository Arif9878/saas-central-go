package saascentral

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Arif9878/saas-central-go/entitlements"
	"github.com/Arif9878/saas-central-go/jwks"
	"github.com/Arif9878/saas-central-go/scerrors"
)

// Entitlements keeps verified entitlement tokens per organization for one
// product, so feature checks are local:
//
//   - Get returns cached claims while the token has more than the refresh
//     margin left, else fetches and verifies a new token (one request per
//     organization at a time).
//   - Run follows Central's change feed: a change drops the organization's
//     cached token and raises the version a new token must have.
//   - If Central cannot be reached, a cached token is still used until it
//     expires; after that Get fails with scerrors.ErrUnavailable and the
//     product applies its own fail mode (for Bilas and Clinic: their free
//     features, never locking a shop's data). An expired token is never used.
type Entitlements struct {
	client    *Client
	product   string
	validator *entitlements.Validator
	refresh   time.Duration
	poll      time.Duration
	max       int
	onError   func(error)
	now       func() time.Time

	mu       sync.Mutex
	cache    map[string]*entry
	min      map[string]int64
	inflight map[string]*fetch
	after    int64
}

type entry struct {
	claims *entitlements.Claims
	exp    time.Time
}

type fetch struct {
	done   chan struct{}
	claims *entitlements.Claims
	err    error
}

// EntitlementsOption configures NewEntitlements.
type EntitlementsOption func(*entOptions)

type entOptions struct {
	issuer  string
	source  jwks.Source
	refresh time.Duration
	poll    time.Duration
	max     int
	onError func(error)
}

// WithIssuer sets the expected issuer (default: the client's base URL).
func WithIssuer(iss string) EntitlementsOption { return func(o *entOptions) { o.issuer = iss } }

// WithKeySource shares a key source (default: the base URL's JWKS).
func WithKeySource(s jwks.Source) EntitlementsOption { return func(o *entOptions) { o.source = s } }

// WithTokenRefresh fetches a new token when the cached one has less than
// d left (default 30 s).
func WithTokenRefresh(d time.Duration) EntitlementsOption {
	return func(o *entOptions) { o.refresh = d }
}

// WithPollInterval is how often Run reads the change feed (default 30 s).
func WithPollInterval(d time.Duration) EntitlementsOption { return func(o *entOptions) { o.poll = d } }

// WithMaxEntries bounds the cache (default 10 000 organizations).
func WithMaxEntries(n int) EntitlementsOption { return func(o *entOptions) { o.max = n } }

// OnPollError is told of change-feed failures (Run keeps going).
func OnPollError(f func(error)) EntitlementsOption { return func(o *entOptions) { o.onError = f } }

// NewEntitlements returns an Entitlements for product. The client needs
// the entitlement:read scope.
func NewEntitlements(c *Client, product string, opts ...EntitlementsOption) (*Entitlements, error) {
	o := entOptions{issuer: c.base.String(), refresh: 30 * time.Second, poll: 30 * time.Second, max: 10_000, onError: func(error) {}}
	for _, opt := range opts {
		opt(&o)
	}
	vopts := []entitlements.Option{entitlements.WithIssuer(o.issuer), entitlements.WithProduct(product), entitlements.WithClock(c.now)}
	if o.source != nil {
		vopts = append(vopts, entitlements.WithKeySource(o.source))
	} else {
		var jo []jwks.Option
		if c.base.Scheme == "http" {
			jo = append(jo, jwks.WithInsecureHTTP())
		}
		vopts = append(vopts, entitlements.WithJWKSURL(c.base.String()+"/.well-known/jwks.json", jo...))
	}
	v, err := entitlements.NewValidator(vopts...)
	if err != nil {
		return nil, err
	}
	return &Entitlements{client: c, product: product, validator: v, refresh: o.refresh, poll: o.poll, max: o.max, onError: o.onError,
		now: c.now, cache: map[string]*entry{}, min: map[string]int64{}, inflight: map[string]*fetch{}}, nil
}

// Get returns the verified entitlements of orgID, the organization of the
// request from the product's own trusted context.
func (e *Entitlements) Get(ctx context.Context, orgID string) (*entitlements.Claims, error) {
	e.mu.Lock()
	now := e.now()
	cached := e.cache[orgID]
	if cached != nil && now.Add(e.refresh).Before(cached.exp) {
		e.mu.Unlock()
		return cached.claims, nil
	}
	f := e.inflight[orgID]
	if f == nil {
		f = &fetch{done: make(chan struct{})}
		e.inflight[orgID] = f
		min := e.min[orgID]
		go e.fetch(context.WithoutCancel(ctx), orgID, min, f)
	}
	e.mu.Unlock()

	select {
	case <-f.done:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", scerrors.ErrUnavailable, ctx.Err())
	}
	if f.err == nil {
		return f.claims, nil
	}
	// Central refused or failed: a still-valid cached token stands in only
	// when the failure is availability, never an authorization refusal.
	if unavailable(f.err) && cached != nil && e.now().Before(cached.exp) {
		e.mu.Lock()
		stillCurrent := e.cache[orgID] == cached
		e.mu.Unlock()
		if stillCurrent {
			return cached.claims, nil
		}
	}
	return nil, f.err
}

func (e *Entitlements) fetch(parent context.Context, orgID string, min int64, f *fetch) {
	// Not cancelled with the first caller: others wait for this fetch.
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	t, err := e.client.EntitlementToken(ctx, orgID, e.product)
	var claims *entitlements.Claims
	if err == nil {
		claims, err = e.validator.Verify(ctx, t.Token, entitlements.ForOrganization(orgID), entitlements.MinVersion(min))
	}
	e.mu.Lock()
	if err == nil && claims.EntitlementVersion >= e.min[orgID] { // a change may have arrived meanwhile
		if len(e.cache) >= e.max {
			clear(e.cache)
		}
		e.cache[orgID] = &entry{claims: claims, exp: claims.ExpiresAt.Time}
	} else if err != nil && !unavailable(err) {
		delete(e.cache, orgID) // refused: no stale token stands in
	}
	f.claims, f.err = claims, err
	delete(e.inflight, orgID)
	e.mu.Unlock()
	close(f.done)
}

// Invalidate drops the cached token of orgID.
func (e *Entitlements) Invalidate(orgID string) {
	e.mu.Lock()
	delete(e.cache, orgID)
	e.mu.Unlock()
}

// Poll reads the change feed once: every change drops the organization's
// cached token and raises the minimum version.
func (e *Entitlements) Poll(ctx context.Context) error {
	for {
		e.mu.Lock()
		after := e.after
		e.mu.Unlock()
		changes, next, err := e.client.Changes(ctx, e.product, after)
		if err != nil {
			return err
		}
		e.mu.Lock()
		for _, ch := range changes {
			if ch.EntitlementVersion > e.min[ch.OrganizationID] {
				e.min[ch.OrganizationID] = ch.EntitlementVersion
			}
			if c := e.cache[ch.OrganizationID]; c != nil && c.claims.EntitlementVersion < ch.EntitlementVersion {
				delete(e.cache, ch.OrganizationID)
			}
		}
		e.after = next
		e.mu.Unlock()
		if len(changes) < 500 {
			return nil
		}
	}
}

// Run polls the change feed until ctx ends.
func (e *Entitlements) Run(ctx context.Context) {
	t := time.NewTicker(e.poll)
	defer t.Stop()
	for {
		if err := e.Poll(ctx); err != nil && ctx.Err() == nil {
			e.onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// unavailable reports whether err means Central or its keys could not be
// reached (as opposed to a refusal).
func unavailable(err error) bool {
	return errors.Is(err, scerrors.ErrUnavailable) || errors.Is(err, scerrors.ErrKeysUnavailable)
}
