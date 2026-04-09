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
DESKCONN_POSTGRES_URL=postgres://router:random@localhost:5432/deskconn_account_service?sslmode=disable&search_path=deskconn
DESKCONN_ROUTER_ADDRESS=localhost:8080
```

> **Note:** `DESKCONN_POSTGRES_URL` must point to the same Postgres database used by
> the [account service](https://github.com/xconnio/deskconn-account-service).

## Run

```bash
make run
```
