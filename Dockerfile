FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN apk add --no-cache make git && make build

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/deskconn-router /deskconn-router
WORKDIR /app

ENTRYPOINT ["/deskconn-router"]
