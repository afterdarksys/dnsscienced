FROM golang:1.25-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY dnsasm/go/go.mod dnsasm/go/go.mod
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY tests/differential/runner ./tests/differential/runner
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/dns-differential ./tests/differential/runner

FROM alpine:3.22
COPY --from=builder /out/dns-differential /usr/local/bin/dns-differential
ENTRYPOINT ["/usr/local/bin/dns-differential"]
