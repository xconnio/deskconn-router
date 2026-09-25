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

DOCKER_BUILD := docker buildx build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest

build-docker:
	$(DOCKER_BUILD) --platform linux/amd64,linux/arm64 .

build-docker-amd64:
	$(DOCKER_BUILD) --platform linux/amd64 .

build-docker-arm64:
	$(DOCKER_BUILD) --platform linux/arm64 .

push-docker:
	@[ "$$CI" = true ] || { echo "push-docker only runs in CI"; exit 1; }
	$(DOCKER_BUILD) --platform linux/amd64,linux/arm64 --push .

run-docker:
	docker compose up
