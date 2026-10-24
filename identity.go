package saascentral

import (
	"context"
	"net/http"
	"net/url"
)

// Users who sign in to the product itself (Google in its app) and the
// businesses they create. The product verifies the
// Google ID token as it always did; it also passes it to Central, which
// verifies it again and links the person to their Nusa Karya account.

// Link outcomes.
const (
	LinkExisting = "existing" // the account was known
	LinkCreated  = "created"  // a new account
	LinkLinked   = "linked"   // linked to the account with the same proven address
	LinkPending  = "pending"  // the address's owner must open an emailed link first; User is nil
)

// User is a person, as Central knows them.
type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
}

// SignIn is the result of LinkGoogle.
type SignIn struct {
	Status string `json:"status"`
	User   *User  `json:"user"`
}

// LinkGoogle reports a Google sign-in to the product (identity:link).
// idToken is the ID token the app received, for one of the product's
// Google clients registered in Central. Call it after the product's own
// sign-in succeeded, and do not fail that sign-in when Central is
// unavailable: call again at the next one. With LinkPending, keep the
// product's session and retry later; there is no Central user yet.
func (c *Client) LinkGoogle(ctx context.Context, product, idToken string) (SignIn, error) {
	var out SignIn
	err := c.call(ctx, http.MethodPost, "/api/v1/service/identities/google", map[string]string{"product": product, "id_token": idToken}, &out)
	return out, err
}

// User returns a person who reached Central through product
// (identity:link); others are scerrors.ErrNotFound.
func (c *Client) User(ctx context.Context, product, userID string) (User, error) {
	var u User
	err := c.call(ctx, http.MethodGet, "/api/v1/service/users/"+url.PathEscape(userID)+"?product="+url.QueryEscape(product), nil, &u)
	return u, err
}

// NewOrganization is a business to create for one of the product's users.
type NewOrganization struct {
	Product     string `json:"product"`
	OwnerUserID string `json:"owner_user_id"`
	Name        string `json:"name"`
	// ExternalTenantID is the product's own ID for the business (a clinic
	// ID, a captcha account ID). Creating again with the same one returns
	// the same organization, so retries are safe.
	ExternalTenantID string `json:"external_tenant_id"`
	// Plan, if set, subscribes it: the plan's trial (once per organization
	// and per person) or a free plan. Needs subscription:write.
	Plan     string `json:"plan,omitempty"`
	Interval string `json:"interval,omitempty"`
	Currency string `json:"currency,omitempty"`
}

// Subscription outcomes of CreateOrganization.
const (
	SubscriptionNone            = "none"
	SubscriptionStarted         = "started"
	SubscriptionExisting        = "existing"
	SubscriptionPaymentRequired = "payment_required" // the fallback plan applies until it is paid
)

// CreatedOrganization is the result of CreateOrganization.
type CreatedOrganization struct {
	Organization struct {
		ID     string `json:"id"`
		Slug   string `json:"slug"`
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"organization"`
	ExternalTenantID   string `json:"external_tenant_id"`
	Created            bool   `json:"created"`
	SubscriptionStatus string `json:"subscription_status"`
}

// CreateOrganization creates a business owned by one of the product's
// users, maps the product's tenant to it, and grants it to this client
// (organization:create). The organization's ID is what Entitlements.Get
// takes from then on.
func (c *Client) CreateOrganization(ctx context.Context, req NewOrganization) (CreatedOrganization, error) {
	var out CreatedOrganization
	err := c.call(ctx, http.MethodPost, "/api/v1/service/organizations", req, &out)
	return out, err
}
