# Deskconn Cloud Router

The main Deskconn router that connects all services and devices.

## Setup

1. Clone the project

```bash
git clone git@github.com:xconnio/deskconn-router.git
cd deskconn-router
```

2. Configure environment variables
   Create or edit the .env file with appropriate values:

```bash
DESKCONN_POSTGRES_HOST=localhost
DESKCONN_POSTGRES_URL=postgres://router:random@${DESKCONN_POSTGRES_HOST}:5432/deskconn_account_service?sslmode=disable&search_path=deskconn
DESKCONN_ROUTER_ADDRESS=localhost:8080
```

> **Note:** `DESKCONN_POSTGRES_URL` must point to the same Postgres database used by
> the [account service](https://github.com/xconnio/deskconn-account-service).
>
> When running `make run-docker`, the router joins the `deskconn` Docker network created by the
> account service (start it first) and should use
> `DESKCONN_POSTGRES_HOST=deskconn-account-service-postgres` in `.env`.

## Run

```bash
make run
```

## Using your own backend

The router itself, in the `router` package, doesn't depend on the account service. What
depends on the deployment is left to callbacks in `router.Config`:

| Field                | What you decide                                                                  |
|----------------------|----------------------------------------------------------------------------------|
| `Authenticate`       | Who may join, as which authid and role (required)                                |
| `Machines`           | The machines to serve at startup                                                 |
| `Roles`              | The cloud realm's roles and permissions                                          |
| `MachinePermissions` | What a machine's daemon may do on the cloud realm                                |
| `UserRoles`          | Users' roles in a machine's realm and what each may do there; they may also relay streams to it |

Machines can also be added and removed at runtime with `Router.AddMachine` and `Router.RemoveMachine`, or by
calling `io.xconn.deskconn.realm.add` / `io.xconn.deskconn.realm.remove` (realm, authid) with a role allowed to.

`cmd/deskconn-router` plugs in the account service; a minimal router with its own logic looks like this:

```go
r, err := router.New(ctx, router.Config{
	Machines: func(ctx context.Context) ([]router.Machine, error) {
		return []router.Machine{{AuthID: "office-pc", Realm: "office-pc-realm"}}, nil
	},
	Authenticate: func(request auth.Request) (auth.Response, error) {
		// Look the key up wherever you keep them.
		if request.AuthID() == "office-pc" {
			return auth.NewResponse("office-pc", router.MachineAuthRole("office-pc"), 0)
		}
		return auth.NewResponse(request.AuthID(), "user", 0)
	},
	UserRoles:   []xconn.RealmRole{{Name: "user", Permissions: router.MachineUserPermissions()}},
	QUICAddress: "0.0.0.0:8081",
})
if err != nil {
	log.Fatal(err)
}
log.Fatal(r.Serve(ctx))
```

The example admits anyone as a user; a real `Authenticate` checks the CryptoSign public key
(`request.(*auth.RequestCryptoSign).PublicKey()`) or answers WAMP-CRA with the user's secret.
