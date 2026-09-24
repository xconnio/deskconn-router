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
