package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/afterdarksys/dnsscienced/internal/logging"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// CtxKeyID is the context key for the authenticated API key ID (D-08: audit logging).
// Set by apiKeyUnaryInterceptor after successful Bearer token validation.
// Handlers retrieve it via ctx.Value(middleware.CtxKeyID{}) for audit log annotations.
type CtxKeyID struct{}

// callerIdentity extracts an audit-safe caller identifier from ctx.
// Per D-08: logs the named key id (not a hash, not the secret).
// Priority: API key id from context > cert CN from peer TLS info > "unknown".
func callerIdentity(ctx context.Context) string {
	if kid, ok := ctx.Value(CtxKeyID{}).(string); ok && kid != "" {
		return "key:" + kid
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "unknown"
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "unknown"
	}
	return "cert:" + tlsInfo.State.PeerCertificates[0].Subject.CommonName
}

// remoteAddr extracts the remote address from gRPC peer context (D-07 remote_addr field).
func remoteAddr(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	return p.Addr.String()
}

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

// AuditUnaryInterceptor logs one structured entry per unary RPC after the handler returns.
// D-07 fields: caller (named key_id per D-08 or cert CN), method, timestamp (RFC3339),
// code (result), latency_ms, remote_addr (from peer.FromContext).
func AuditUnaryInterceptor(logger *logging.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		st := status.Convert(err)
		logger.Info().
			Str("caller", callerIdentity(ctx)).
			Str("method", info.FullMethod).
			Str("code", st.Code().String()).
			Int64("latency_ms", time.Since(start).Milliseconds()).
			Str("remote_addr", remoteAddr(ctx)).
			Str("timestamp", time.Now().Format(time.RFC3339)).
			Msg("admin rpc")
		return resp, err
	}
}

// AuditStreamInterceptor logs one structured entry per streaming RPC after the handler returns.
// D-07 fields: caller, method, timestamp (RFC3339), code (result), latency_ms, remote_addr.
func AuditStreamInterceptor(logger *logging.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		err := handler(srv, ss)
		st := status.Convert(err)
		logger.Info().
			Str("caller", callerIdentity(ss.Context())).
			Str("method", info.FullMethod).
			Str("code", st.Code().String()).
			Int64("latency_ms", time.Since(start).Milliseconds()).
			Str("remote_addr", remoteAddr(ss.Context())).
			Str("timestamp", time.Now().Format(time.RFC3339)).
			Msg("admin rpc")
		return err
	}
}
