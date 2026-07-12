# syntax=docker/dockerfile:1.6

FROM golang:1.26-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./

RUN GOTOOLCHAIN=auto go mod download
COPY . .
# Build all binaries: server, migrate, seed, setup-db, and session-cleanup
RUN GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth ./cmd/server && \
    GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-migrate ./cmd/migrate && \
    GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-seed ./cmd/seed && \
    GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-setup-db ./cmd/setup-db && \
    GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/auth-session-cleanup ./cmd/session-cleanup

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata rclone && addgroup -S app && adduser -S app -G app
WORKDIR /app
# Copy all binaries
COPY --from=builder /bin/auth /usr/local/bin/auth
COPY --from=builder /bin/auth-migrate /usr/local/bin/auth-migrate
COPY --from=builder /bin/auth-seed /usr/local/bin/auth-seed
COPY --from=builder /bin/auth-setup-db /usr/local/bin/auth-setup-db
COPY --from=builder /bin/auth-session-cleanup /usr/local/bin/auth-session-cleanup
COPY config/keys ./config/keys
COPY internal/ent/migrate/migrations ./internal/ent/migrate/migrations
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
# TLS certificates directory (optional, can be mounted as volume)
RUN mkdir -p ./config/certs && chmod +x /usr/local/bin/entrypoint.sh
USER app
EXPOSE 4101
# Default entrypoint is the wrapper script
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

