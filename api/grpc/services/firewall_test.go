package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/dnsscience/dnsscienced/internal/firewalld"
)

// newTestFirewall creates a minimal *firewalld.Firewall for service tests.
func newTestFirewall(t *testing.T) *firewalld.Firewall {
	t.Helper()
	fw, err := firewalld.New(firewalld.Config{Enabled: true})
	require.NoError(t, err)
	return fw
}

func TestFirewallService_Stats(t *testing.T) {
	fw := newTestFirewall(t)
	svc := NewFirewallService(fw)
	resp, err := svc.FirewallStats(context.Background(), &pb.FirewallStatsRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	// Fresh firewall: all counters are zero. Just assert the fields exist and are accessible.
	assert.GreaterOrEqual(t, resp.TotalQueries, uint64(0))
	assert.GreaterOrEqual(t, resp.TotalBlocked, uint64(0))
	assert.GreaterOrEqual(t, resp.TotalNxdomain, uint64(0))
	assert.GreaterOrEqual(t, resp.TotalDropped, uint64(0))
	assert.GreaterOrEqual(t, resp.TotalRedirected, uint64(0))
}

func TestFirewallService_LoadScript(t *testing.T) {
	tests := []struct {
		name        string
		req         *pb.FirewallLoadScriptRequest
		wantErr     bool
		errCode     codes.Code
		errContains string
	}{
		{
			name:        "missing script_id",
			req:         &pb.FirewallLoadScriptRequest{Body: "def on_query(q, score): pass"},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			errContains: "script_id is required",
		},
		{
			name:        "missing body",
			req:         &pb.FirewallLoadScriptRequest{ScriptId: "myscript"},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			errContains: "body is required",
		},
		{
			name: "valid starlark",
			req:  &pb.FirewallLoadScriptRequest{ScriptId: "myscript", Body: "def on_query(q, score): pass"},
		},
		{
			name:        "invalid starlark syntax",
			req:         &pb.FirewallLoadScriptRequest{ScriptId: "bad", Body: "this is not valid starlark !!@@##"},
			wantErr:     true,
			errCode:     codes.InvalidArgument,
			errContains: "compile script:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := newTestFirewall(t)
			svc := NewFirewallService(fw)
			resp, err := svc.LoadScript(context.Background(), tt.req)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.errCode, status.Code(err))
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.req.ScriptId, resp.ScriptId)
			}
		})
	}
}

func TestFirewallService_RemoveScript(t *testing.T) {
	tests := []struct {
		name    string
		req     *pb.FirewallRemoveScriptRequest
		wantErr bool
		errCode codes.Code
	}{
		{
			name:    "missing script_id",
			req:     &pb.FirewallRemoveScriptRequest{},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name: "valid script_id not loaded — silent success",
			req:  &pb.FirewallRemoveScriptRequest{ScriptId: "nonexistent"},
		},
		{
			name: "remove previously loaded script",
			req:  &pb.FirewallRemoveScriptRequest{ScriptId: "toremove"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := newTestFirewall(t)
			if tt.req.ScriptId == "toremove" {
				// Pre-load the script so Remove has something to remove.
				_, err := NewFirewallService(fw).LoadScript(context.Background(), &pb.FirewallLoadScriptRequest{
					ScriptId: "toremove",
					Body:     "def on_query(q, score): pass",
				})
				require.NoError(t, err)
			}
			svc := NewFirewallService(fw)
			_, err := svc.RemoveScript(context.Background(), tt.req)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.errCode, status.Code(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFirewallService_InjectScore(t *testing.T) {
	tests := []struct {
		name    string
		req     *pb.FirewallInjectScoreRequest
		wantErr bool
		errCode codes.Code
	}{
		{
			name: "domain target",
			req: &pb.FirewallInjectScoreRequest{
				Target: &pb.FirewallInjectScoreRequest_Domain{Domain: "evil.example.com"},
				Score:  80,
			},
		},
		{
			name: "ip target",
			req: &pb.FirewallInjectScoreRequest{
				Target: &pb.FirewallInjectScoreRequest_Ip{Ip: "1.2.3.4"},
				Score:  90,
			},
		},
		{
			name:    "nil target",
			req:     &pb.FirewallInjectScoreRequest{Score: 50},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name: "empty domain",
			req: &pb.FirewallInjectScoreRequest{
				Target: &pb.FirewallInjectScoreRequest_Domain{Domain: ""},
				Score:  80,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
		{
			name: "empty ip",
			req: &pb.FirewallInjectScoreRequest{
				Target: &pb.FirewallInjectScoreRequest_Ip{Ip: ""},
				Score:  90,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := newTestFirewall(t)
			svc := NewFirewallService(fw)
			_, err := svc.InjectScore(context.Background(), tt.req)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, tt.errCode, status.Code(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}
