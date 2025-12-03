# syntax=docker/dockerfile:1.6

FROM golang:1.24-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build all binaries: server, migrate, and seed
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-migrate ./cmd/migrate && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-seed ./cmd/seed

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && addgroup -S app && adduser -S app -G app
WORKDIR /app
# Copy all binaries
COPY --from=builder /bin/auth /usr/local/bin/auth
COPY --from=builder /bin/auth-migrate /usr/local/bin/auth-migrate
COPY --from=builder /bin/auth-seed /usr/local/bin/auth-seed
COPY config/keys ./config/keys
# TLS certificates directory (optional, can be mounted as volume)
RUN mkdir -p ./config/certs
USER app
EXPOSE 4101
# Default entrypoint is the server
ENTRYPOINT ["/usr/local/bin/auth"]

