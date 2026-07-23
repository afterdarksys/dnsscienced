# syntax=docker/dockerfile:1

# Linux/amd64 is the primary deployment target. DNSASM requires a native cgo
# toolchain even though the final executable is statically linked with musl.
FROM golang:1.25-alpine AS builder

WORKDIR /build

RUN apk add --no-cache build-base nasm

COPY go.mod go.sum ./
COPY dnsasm/go/go.mod dnsasm/go/go.mod
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN make -C dnsasm dirs \
    && make -C dnsasm USE_ASM=1 build/lib/libdnsasm.a
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=1 GOOS=linux go build \
    -ldflags '-linkmode external -extldflags "-static"' \
    -o /out/dnsscienced ./cmd/dnsscienced/

# Final stage contains no compiler, source, or cgo runtime dependencies.
FROM alpine:3.22

WORKDIR /app

RUN apk --no-cache add ca-certificates tzdata

RUN mkdir -p /zones

COPY --from=builder /out/dnsscienced ./dnsscienced

EXPOSE 53/udp 53/tcp 9090/tcp

ENTRYPOINT ["/app/dnsscienced"]
CMD ["-authoritative"]
