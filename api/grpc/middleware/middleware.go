package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// CtxKeyID is the context key for the authenticated API key ID (D-08: audit logging).
// Set by apiKeyUnaryInterceptor after successful Bearer token validation.
// Handlers retrieve it via ctx.Value(middleware.CtxKeyID{}) for audit log annotations.
type CtxKeyID struct{}

var (
	RPCRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "dnsscienced_grpc_requests_total", Help: "Total gRPC requests"},
		[]string{"method", "code"},
	)
	RPCDurations = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "dnsscienced_grpc_duration_seconds", Help: "RPC duration", Buckets: prometheus.DefBuckets},
		[]string{"method"},
	)
)

func init() {
	prometheus.MustRegister(RPCRequests, RPCDurations)
}

func genID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// UnaryLoggingMetrics adds request-id, logs start/finish via metadata, and records metrics.
func UnaryLoggingMetrics() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		md, _ := metadata.FromIncomingContext(ctx)
		rids := md.Get("x-request-id")
		rid := ""
		if len(rids) > 0 { rid = rids[0] } else { rid = genID(); md.Set("x-request-id", rid) }
		// proceed
		resp, err := handler(ctx, req)
		st := status.Convert(err)
		RPCRequests.WithLabelValues(info.FullMethod, st.Code().String()).Inc()
		RPCDurations.WithLabelValues(info.FullMethod).Observe(time.Since(start).Seconds())
		return resp, err
	}
}

// StreamLoggingMetrics records metrics around streaming RPCs.
func StreamLoggingMetrics() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		st := status.Convert(err)
		RPCRequests.WithLabelValues(info.FullMethod, st.Code().String()).Inc()
		RPCDurations.WithLabelValues(info.FullMethod).Observe(time.Since(start).Seconds())
		return err
	}
}
