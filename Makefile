IMAGE := xconnio/deskconn-router
VERSION := $(shell git describe --tags --always)

test:
	go test -count=1 ./... -v

lint:
	golangci-lint run

build:
	CGO_ENABLED=0 go build github.com/xconnio/deskconn-router/cmd/deskconn-router

run:
	CGO_ENABLED=0 go run github.com/xconnio/deskconn-router/cmd/deskconn-router

build-docker:
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

run-docker:
	docker compose up
