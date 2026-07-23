package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dnsscience/dnsscienced/internal/server"
)

func TestAuthoritativeRoleAppliesSafeDefaults(t *testing.T) {
	cfg := &Config{Role: RoleAuthoritative, Server: server.DefaultConfig()}
	if err := cfg.ApplyRoleProfile(); err != nil {
		t.Fatalf("ApplyRoleProfile: %v", err)
	}
	if !cfg.Server.EnableAuthoritative || cfg.Server.EnableRecursive {
		t.Fatalf("modes = authoritative:%v recursive:%v", cfg.Server.EnableAuthoritative, cfg.Server.EnableRecursive)
	}
}

func TestAuthoritativeRoleRejectsRecursionAndForwarding(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"recursion": func(cfg *Config) {
			cfg.Server.EnableRecursive = true
		},
		"forwarding": func(cfg *Config) {
			cfg.Forwarders = map[string][]string{"": {"192.0.2.53"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{Role: RoleAuthoritative, Server: server.DefaultConfig()}
			mutate(cfg)
			if err := cfg.ApplyRoleProfile(); err == nil {
				t.Fatal("expected incompatible authoritative role to fail")
			}
		})
	}
}

func TestRecursiveRoleRejectsAuthoritativeData(t *testing.T) {
	cfg := &Config{
		Role:   RoleRecursive,
		Server: server.DefaultConfig(),
		Zones:  []ZoneConfig{{Name: "example."}},
	}
	if err := cfg.ApplyRoleProfile(); err == nil {
		t.Fatal("expected recursive role with primary zone to fail")
	}
}

func TestForwarderRoleRequiresGlobalUpstreamAndForcesOnly(t *testing.T) {
	cfg := &Config{
		Role:       RoleForwarder,
		Server:     server.DefaultConfig(),
		Forwarders: map[string][]string{"": {"192.0.2.53"}},
	}
	if err := cfg.ApplyRoleProfile(); err != nil {
		t.Fatalf("ApplyRoleProfile: %v", err)
	}
	if !cfg.Server.EnableRecursive || cfg.Server.RecursiveConfig.ForwardMode != "only" {
		t.Fatalf("forwarder modes = recursive:%v mode:%q",
			cfg.Server.EnableRecursive, cfg.Server.RecursiveConfig.ForwardMode)
	}

	cfg.Server.RecursiveConfig.ForwardMode = "first"
	if err := cfg.ApplyRoleProfile(); err == nil {
		t.Fatal("expected direct-fallback forwarding to fail")
	}
}

func TestLocalRootRequiresExplicitRootAndLoopbackListeners(t *testing.T) {
	base := func() *Config {
		cfg := &Config{
			Role:   RoleLocalRoot,
			Server: server.DefaultConfig(),
			Zones:  []ZoneConfig{{Name: ".", Type: "secondary"}},
		}
		cfg.Server.UDPAddr = "127.0.0.1:53"
		cfg.Server.TCPAddr = "[::1]:53"
		return cfg
	}

	cfg := base()
	if err := cfg.ApplyRoleProfile(); err != nil {
		t.Fatalf("ApplyRoleProfile: %v", err)
	}
	if !cfg.Server.EnableAuthoritative || cfg.Server.EnableRecursive {
		t.Fatalf("modes = authoritative:%v recursive:%v", cfg.Server.EnableAuthoritative, cfg.Server.EnableRecursive)
	}

	cfg = base()
	cfg.Server.UDPAddr = "0.0.0.0:53"
	if err := cfg.ApplyRoleProfile(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback local root error = %v", err)
	}
}

func TestPublicRootRejectsTenantPolicyAndExtraZones(t *testing.T) {
	cfg := &Config{
		Role:   RolePublicRoot,
		Server: server.DefaultConfig(),
		Zones: []ZoneConfig{
			{Name: ".", Type: "secondary"},
			{Name: "example.", Type: "primary"},
		},
	}
	if err := cfg.ApplyRoleProfile(); err == nil {
		t.Fatal("expected extra public-root zone to fail")
	}

	cfg.Zones = cfg.Zones[:1]
	cfg.Server.RPZ.Enabled = true
	if err := cfg.ApplyRoleProfile(); err == nil {
		t.Fatal("expected RPZ in public-root role to fail")
	}
}

func TestRoleUnknownAndCustom(t *testing.T) {
	cfg := &Config{Role: "mystery", Server: server.DefaultConfig()}
	if err := cfg.ApplyRoleProfile(); err == nil {
		t.Fatal("expected unknown role to fail")
	}
	cfg.Role = RoleCustom
	cfg.Server.EnableAuthoritative = true
	cfg.Server.EnableRecursive = true
	if err := cfg.ApplyRoleProfile(); err != nil {
		t.Fatalf("custom role: %v", err)
	}
}

func TestLoadAppliesAndValidatesRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := `
role: forwarder
forwarders:
  "":
    - 192.0.2.53:53
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Server.EnableRecursive || cfg.Server.RecursiveConfig.ForwardMode != "only" {
		t.Fatalf("loaded forwarder profile = recursive:%v mode:%q",
			cfg.Server.EnableRecursive, cfg.Server.RecursiveConfig.ForwardMode)
	}
	if cfg.Resolver.ForwardMode != "only" {
		t.Fatalf("resolver compatibility alias mode = %q, want only", cfg.Resolver.ForwardMode)
	}

	contents = `
role: authoritative
server:
  enable_recursive: true
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected Load to reject incompatible role")
	}
}
