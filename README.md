# saas-central-go

Go SDK for Nusa Karya products integrating with SaaS Central: OAuth 2.0
client credentials (client secret or `private_key_jwt`), tenant resolution,
signed entitlement tokens verified locally against Central's JWKS and
cached per organization, the entitlement change feed, and product sign-in
(linking users, creating organizations).

```go
import saascentral "github.com/Arif9878/saas-central-go"

client, err := saascentral.NewClient(
	saascentral.WithBaseURL("https://platform.nusakarya.id"),
	saascentral.WithClientCredentials(os.Getenv("CENTRAL_CLIENT_ID"), os.Getenv("CENTRAL_CLIENT_SECRET")),
	saascentral.WithScopes("organization:read", "entitlement:read"),
)
ents, err := saascentral.NewEntitlements(client, "captcha")
go ents.Run(ctx) // follows the change feed
claims, err := ents.Get(ctx, orgID)
```

Packages: `entitlements` (claims and verification), `jwks` (key set
cache), `token` (Central's token types and checks), `scerrors` (error
values to branch on with `errors.Is`).

Keep client credentials server-side; the SDK never logs them or puts them
in errors.
