package saascentral_test

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"

	saascentral "github.com/Arif9878/saas-central-go"
	"github.com/Arif9878/saas-central-go/scerrors"
)

// outletFromSession stands for Bilas' own authentication: the outlet of
// the signed-in device, from Bilas' database, never from the request body.
func outletFromSession(r *http.Request) string { return r.Header.Get("X-Test-Outlet") }

// Example shows Bilas (laundry-app/backend) checking a feature locally on
// every request, without changing its own business logic: its outlet is
// mapped to a Central organization once, the entitlement token is cached
// and verified locally, and changes arrive through the feed.
func Example() {
	ctx := context.Background()
	client, err := saascentral.NewClient(
		saascentral.WithBaseURL("https://platform.nusakarya.id"),
		saascentral.WithClientCredentials(os.Getenv("CENTRAL_CLIENT_ID"), os.Getenv("CENTRAL_CLIENT_SECRET")),
		saascentral.WithScopes("organization:read", "entitlement:read"),
	)
	if err != nil {
		log.Fatal(err)
	}
	ents, err := saascentral.NewEntitlements(client, "laundry")
	if err != nil {
		log.Fatal(err)
	}
	go ents.Run(ctx) // drops cached tokens when a subscription changes

	var orgs sync.Map // outlet → organization; mappings change rarely
	orgOf := func(ctx context.Context, outlet string) (string, error) {
		if v, ok := orgs.Load(outlet); ok {
			return v.(string), nil
		}
		org, err := client.ResolveTenant(ctx, "laundry", outlet)
		if err == nil {
			orgs.Store(outlet, org)
		}
		return org, err
	}

	// Reports are a Pro feature.
	reports := func(w http.ResponseWriter, r *http.Request) {
		org, err := orgOf(r.Context(), outletFromSession(r))
		if err != nil {
			http.Error(w, "outlet not linked to an account", http.StatusForbidden)
			return
		}
		claims, err := ents.Get(r.Context(), org)
		switch {
		case errors.Is(err, scerrors.ErrUnavailable):
			// Central down and the cached token expired: Bilas' documented
			// fail mode is its free features (the cashier keeps working);
			// reports are not one of them.
			http.Error(w, "reports are unavailable right now", http.StatusServiceUnavailable)
			return
		case err != nil:
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		if err := claims.Require("reports"); err != nil {
			http.Error(w, "upgrade to Pro for reports", http.StatusPaymentRequired)
			return
		}
		_, _ = w.Write([]byte("report…"))
	}

	// Creating an outlet: the limit is in the token, the count is Bilas'.
	createOutlet := func(w http.ResponseWriter, r *http.Request) {
		org, _ := orgOf(r.Context(), outletFromSession(r))
		claims, err := ents.Get(r.Context(), org)
		if err != nil {
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		outletsNow := int64(1) // SELECT count(*) FROM outlets WHERE owner_account_id = …
		if err := claims.WithinLimit("outlets", outletsNow); errors.Is(err, scerrors.ErrQuotaExceeded) {
			http.Error(w, "your plan's outlet limit is reached", http.StatusPaymentRequired)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}

	http.HandleFunc("GET /v1/reports", reports)
	http.HandleFunc("POST /v1/outlets", createOutlet)
}
