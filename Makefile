test:
	go test -count=1 ./... -v

lint:
	golangci-lint run

build:
	CGO_ENABLED=1 go build github.com/xconnio/deskconn-router/cmd/deskconn-router

run:
	CGO_ENABLED=1 go run github.com/xconnio/deskconn-router/cmd/deskconn-router
