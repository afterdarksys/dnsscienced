# Multi-stage build for dnsscienced
FROM golang:alpine AS builder

WORKDIR /build

# Copy everything
COPY . .

# Download dependencies
RUN go mod download

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o dnsscienced ./cmd/dnsscienced/

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/dnsscienced .

# Create zones directory
RUN mkdir -p /zones

# Expose DNS ports and gRPC
EXPOSE 53/udp 53/tcp 9090/tcp

ENTRYPOINT ["./dnsscienced"]
CMD ["-authoritative"]
