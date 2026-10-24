package jwks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Arif9878/saas-central-go/scerrors"
)

func newKey(t testing.TB) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func jwk(kid string, pub ed25519.PublicKey) map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": kid, "use": "sig", "alg": "EdDSA",
		"x": base64.RawURLEncoding.EncodeToString(pub)}
}

// issuer serves a JWKS whose keys and availability the test changes.
type issuer struct {
	mu       sync.Mutex
	keys     []map[string]string
	down     bool
	delay    time.Duration
	maxAge   int
	requests atomic.Int64
	notMod   atomic.Int64
}

func (s *issuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	s.mu.Lock()
	keys, down, delay, maxAge := s.keys, s.down, s.delay, s.maxAge
	s.mu.Unlock()
	time.Sleep(delay)
	if down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	body, _ := json.Marshal(map[string]any{"keys": keys})
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		s.notMod.Add(1)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setup(t *testing.T, opts ...Option) (*issuer, *Cache, *clock, ed25519.PublicKey) {
	t.Helper()
	k1 := newKey(t)
	iss := &issuer{keys: []map[string]string{jwk("ent-1", k1)}, maxAge: 300}
	srv := httptest.NewServer(iss)
	t.Cleanup(srv.Close)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, err := New(srv.URL, append([]Option{WithInsecureHTTP(), WithClock(clk.now)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return iss, c, clk, k1
}

func TestCacheAndRotation(t *testing.T) {
	iss, c, clk, k1 := setup(t)
	ctx := context.Background()
	got, err := c.Key(ctx, "ent-1")
	if err != nil || !got.Equal(k1) {
		t.Fatalf("Key = %v, %v", got, err)
	}
	for range 10 {
		if _, err := c.Key(ctx, "ent-1"); err != nil {
			t.Fatal(err)
		}
	}
	if n := iss.requests.Load(); n != 1 {
		t.Errorf("cached lookups fetched %d times", n)
	}

	// The issuer publishes a new key: a token with its kid triggers a refresh.
	k2 := newKey(t)
	iss.mu.Lock()
	iss.keys = append(iss.keys, jwk("ent-2", k2))
	iss.mu.Unlock()
	clk.add(31 * time.Second)
	if got, err := c.Key(ctx, "ent-2"); err != nil || !got.Equal(k2) {
		t.Fatalf("new key: %v, %v", got, err)
	}
	// Made-up kids right after: refused without asking the issuer.
	before := iss.requests.Load()
	for range 20 {
		if _, err := c.Key(ctx, "ent-bogus"); !errors.Is(err, scerrors.ErrUnknownKey) {
			t.Fatalf("bogus kid: %v", err)
		}
	}
	if iss.requests.Load() != before {
		t.Error("unknown kids caused refreshes within the minimum interval")
	}

	// The old key is retired: once the cache expires, it is gone.
	iss.mu.Lock()
	iss.keys = iss.keys[1:]
	iss.mu.Unlock()
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Errorf("before expiry the retired key is still cached: %v", err)
	}
	clk.add(301 * time.Second)
	if _, err := c.Key(ctx, "ent-1"); !errors.Is(err, scerrors.ErrUnknownKey) {
		t.Errorf("retired key after expiry: %v", err)
	}
}

func TestConditionalRefresh(t *testing.T) {
	iss, c, clk, _ := setup(t)
	ctx := context.Background()
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Fatal(err)
	}
	clk.add(10 * time.Minute)
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Fatal(err)
	}
	if iss.notMod.Load() != 1 {
		t.Errorf("expired cache was not revalidated with If-None-Match (304s: %d)", iss.notMod.Load())
	}
}

func TestConcurrentUnknownKid(t *testing.T) {
	iss, c, clk, _ := setup(t)
	ctx := context.Background()
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Fatal(err)
	}
	k2 := newKey(t)
	iss.mu.Lock()
	iss.keys = append(iss.keys, jwk("ent-2", k2))
	iss.delay = 50 * time.Millisecond
	iss.mu.Unlock()
	clk.add(time.Minute)
	before := iss.requests.Load()
	var wg sync.WaitGroup
	var failed atomic.Int64
	for range 100 {
		wg.Go(func() {
			if _, err := c.Key(ctx, "ent-2"); err != nil {
				failed.Add(1)
			}
		})
	}
	wg.Wait()
	if n := iss.requests.Load() - before; n != 1 {
		t.Errorf("100 concurrent lookups of a new kid made %d requests, want 1", n)
	}
	if failed.Load() != 0 {
		t.Errorf("%d lookups failed", failed.Load())
	}
}

func TestOutage(t *testing.T) {
	iss, c, clk, _ := setup(t, WithMaxStale(time.Hour))
	ctx := context.Background()
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Fatal(err)
	}
	iss.mu.Lock()
	iss.down = true
	iss.mu.Unlock()
	clk.add(30 * time.Minute) // expired, within MaxStale
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Errorf("stale keys should serve during an outage: %v", err)
	}
	clk.add(2 * time.Hour) // beyond MaxStale: fail closed
	if _, err := c.Key(ctx, "ent-1"); !errors.Is(err, scerrors.ErrKeysUnavailable) {
		t.Errorf("after MaxStale: %v", err)
	}
	iss.mu.Lock()
	iss.down = false
	iss.mu.Unlock()
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		t.Errorf("after recovery: %v", err)
	}
}

func TestNeverFetched(t *testing.T) {
	iss, c, _, _ := setup(t)
	iss.mu.Lock()
	iss.down = true
	iss.mu.Unlock()
	if _, err := c.Key(context.Background(), "ent-1"); !errors.Is(err, scerrors.ErrKeysUnavailable) {
		t.Errorf("no keys and issuer down: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	iss.mu.Lock()
	iss.delay = 100 * time.Millisecond
	iss.mu.Unlock()
	if _, err := c.Key(ctx, "ent-1"); !errors.Is(err, scerrors.ErrKeysUnavailable) {
		t.Errorf("cancelled context: %v", err)
	}
}

func TestTTLFromCacheControl(t *testing.T) {
	c := &Cache{o: options{defaultTTL: 5 * time.Minute, minTTL: time.Minute, maxTTL: time.Hour}}
	for cc, want := range map[string]time.Duration{
		"": 5 * time.Minute, "public, max-age=600": 10 * time.Minute, "max-age=5": time.Minute,
		"max-age=999999": time.Hour, "no-cache": 5 * time.Minute, "max-age=abc": 5 * time.Minute,
	} {
		if got := c.ttl(cc); got != want {
			t.Errorf("ttl(%q) = %v, want %v", cc, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	k := newKey(t)
	x := base64.RawURLEncoding.EncodeToString(k)
	for name, tc := range map[string]struct {
		body string
		ok   bool
		n    int
	}{
		"valid":            {`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"ent-1","x":"` + x + `"}]}`, true, 1},
		"others skipped":   {`{"keys":[{"kty":"RSA","kid":"r","n":"AQ","e":"AQAB"},{"kty":"OKP","crv":"X25519","kid":"x","x":"` + x + `"},{"kty":"OKP","crv":"Ed25519","kid":"enc","use":"enc","x":"` + x + `"},{"kty":"OKP","crv":"Ed25519","kid":"ent-1","alg":"EdDSA","x":"` + x + `"}]}`, true, 1},
		"private material": {`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"ent-1","x":"` + x + `","d":"c2VjcmV0"}]}`, false, 0},
		"duplicate kid":    {`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"ent-1","x":"` + x + `"},{"kty":"OKP","crv":"Ed25519","kid":"ent-1","x":"` + x + `"}]}`, false, 0},
		"short key":        {`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"ent-1","x":"AAAA"}]}`, false, 0},
		"no kid":           {`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}]}`, false, 0},
		"no usable key":    {`{"keys":[{"kty":"RSA","kid":"r"}]}`, false, 0},
		"not JSON":         {`<html>`, false, 0},
	} {
		keys, err := Parse([]byte(tc.body))
		if (err == nil) != tc.ok || len(keys) != tc.n {
			t.Errorf("%s: %d keys, %v", name, len(keys), err)
		}
	}
}

func TestNewRequiresHTTPS(t *testing.T) {
	for _, u := range []string{"http://issuer.example/jwks.json", "/jwks.json", "ftp://x/y", ""} {
		if _, err := New(u); err == nil {
			t.Errorf("New(%q) accepted", u)
		}
	}
	if _, err := New("https://issuer.example/.well-known/jwks.json"); err != nil {
		t.Error(err)
	}
}

func BenchmarkCachedLookup(b *testing.B) {
	k := newKey(b)
	iss := &issuer{keys: []map[string]string{jwk("ent-1", k)}, maxAge: 300}
	srv := httptest.NewServer(iss)
	defer srv.Close()
	c, _ := New(srv.URL, WithInsecureHTTP())
	ctx := context.Background()
	if _, err := c.Key(ctx, "ent-1"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Key(ctx, "ent-1"); err != nil {
			b.Fatal(err)
		}
	}
}
