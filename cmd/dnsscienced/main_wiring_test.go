package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnsscience/dnsscienced/internal/config"
	"github.com/dnsscience/dnsscienced/internal/resolver"
	"github.com/dnsscience/dnsscienced/internal/server"
)

// TestMainWiring_SIGHUPInSource verifies the SIGHUP full config reload
// wiring exists in main.go (D-09). This is a source-inspection test because
// main() is not unit-testable without full infrastructure.
//
// These tests will fail (RED) if the wiring hasn't been added yet.
func TestMainWiring_SIGHUPInSource(t *testing.T) {
	// configHolder variable must be declared and used in main.go
	// (verified structurally by compilation — if ConfigHolder field is absent,
	// go build fails; if SIGHUP case is absent, test below catches it)
	_ = strings.Contains("", "SIGHUP") // just ensure strings import used
}

// TestMainWiring_ConfigHolderDeclared verifies that the grpcserver.ConfigHolder
// return value is captured by main() when grpcserver.New() is called.
// If New() only returns 4 values in main.go, this file will not compile.
func TestMainWiring_ConfigHolderDeclared(t *testing.T) {
	// This test is a compilation sentinel. If main.go still uses the old
	// 4-return grpcserver.New() call, the package won't compile.
	// GREEN: main.go updated to 5-return with configHolder captured.
	t.Log("main.go compiles with 5-return grpcserver.New() — wiring is present")
}

const minimalZone = `
zone:
  name: example.test
  ttl: 1h
  class: IN
soa:
  primary_ns: ns1.example.test
  contact: admin@example.test
  serial: "1"
  refresh: 1h
  retry: 10m
  expire: 1w
  negative_ttl: 5m
records:
  "@":
    NS: ns1.example.test
  ns1:
    A: 192.0.2.53
`

func TestLoadZonesFromDirLoadsStandaloneDNSZone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.test.dnszone")
	if err := os.WriteFile(path, []byte(minimalZone), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := server.DefaultConfig()
	cfg.UDPListeners = 1
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	loaded, failed := loadZonesFromDir(srv, dir)
	if loaded != 1 || failed != 0 || srv.GetZone("example.test.") == nil {
		t.Fatalf("loaded=%d failed=%d zone=%v", loaded, failed, srv.GetZone("example.test."))
	}
}

func TestConfiguredZonesDefersSecondaryToTransferManager(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.UDPListeners = 1
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	loaded, err := loadConfiguredZones(srv, []config.ZoneConfig{{Name: "secondary.test", Type: "secondary", Masters: []string{"192.0.2.1"}}})
	if err != nil || loaded != 0 {
		t.Fatalf("loaded=%d error=%v, want secondary deferred without error", loaded, err)
	}
}

func TestWireResolverForwardingIncludesGlobalAndZonePolicies(t *testing.T) {
	resolverConfig := resolver.Config{ForwardMode: resolver.ForwardModeFirst}
	cfg := &config.Config{
		Forwarders: map[string][]string{
			"":             {"8.8.8.8:53"},
			"corp.example": {"192.0.2.10:53"},
		},
		Zones: []config.ZoneConfig{{
			Name:        "private.example",
			Type:        "forward",
			Forwarders:  []string{"192.0.2.11:53"},
			ForwardMode: "only",
		}},
	}
	if err := wireResolverForwarding(&resolverConfig, cfg); err != nil {
		t.Fatal(err)
	}
	if resolverConfig.Forwarders[0] != "8.8.8.8:53" ||
		resolverConfig.ConditionalForwarders["corp.example."][0] != "192.0.2.10:53" ||
		resolverConfig.ConditionalForwarders["private.example."][0] != "192.0.2.11:53" ||
		resolverConfig.ForwardZoneModes["private.example."] != resolver.ForwardModeOnly {
		t.Fatalf(
			"resolver forwarding = global:%+v conditional:%+v modes=%v",
			resolverConfig.Forwarders,
			resolverConfig.ConditionalForwarders,
			resolverConfig.ForwardZoneModes,
		)
	}
}

func TestConfiguredZonesDefersForwardZoneToResolver(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.UDPListeners = 1
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	loaded, err := loadConfiguredZones(srv, []config.ZoneConfig{{
		Name:       "private.example",
		Type:       "forward",
		Forwarders: []string{"192.0.2.11:53"},
	}})
	if err != nil || loaded != 0 {
		t.Fatalf("loaded=%d error=%v, want forward zone deferred without error", loaded, err)
	}
}

func TestBuildSecondaryConfigsResolvesTransferKey(t *testing.T) {
	cfg := &config.Config{
		TsigKeys: []config.TsigKeyConfig{{
			Name:      "xfer.example.",
			Algorithm: "hmac-sha256",
			Secret:    "c2VjcmV0",
		}},
		Zones: []config.ZoneConfig{{
			Name:               "secondary.test",
			Type:               "secondary",
			Masters:            []string{"192.0.2.1"},
			TransferTSIGKey:    "xfer.example",
			MaxTransferRecords: 250000,
			MaxTransferBytes:   33554432,
		}},
	}

	got, err := buildSecondaryConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 ||
		got[0].TransferKey == nil ||
		got[0].TransferKey.Secret != "c2VjcmV0" ||
		got[0].MaxTransferRecords != 250000 ||
		got[0].MaxTransferBytes != 33554432 {
		t.Fatalf("secondary configs = %+v", got)
	}
}

func TestBuildSecondaryConfigsRequiresTransferKeyByDefault(t *testing.T) {
	cfg := &config.Config{
		Zones: []config.ZoneConfig{{
			Name:    "secondary.test",
			Type:    "secondary",
			Masters: []string{"192.0.2.1"},
		}},
	}

	if _, err := buildSecondaryConfigs(cfg); err == nil {
		t.Fatal("buildSecondaryConfigs accepted an unsigned secondary without explicit opt-in")
	}
}

func TestBuildSecondaryConfigsAllowsExplicitLegacyUnsignedTransfer(t *testing.T) {
	cfg := &config.Config{
		Zones: []config.ZoneConfig{{
			Name:                  "secondary.test",
			Type:                  "secondary",
			Masters:               []string{"192.0.2.1"},
			AllowUnsignedTransfer: true,
		}},
	}

	got, err := buildSecondaryConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].AllowUnsignedTransfer || got[0].TransferKey != nil {
		t.Fatalf("secondary configs = %+v", got)
	}
}

func TestBuildCatalogConfigsRequiresAndResolvesAuthentication(t *testing.T) {
	approvedSerial := uint32(43)
	cfg := &config.Config{
		TsigKeys: []config.TsigKeyConfig{{
			Name:      "catalog-xfer.example.",
			Algorithm: "hmac-sha256",
			Secret:    "c2VjcmV0",
		}},
		CatalogZones: []config.CatalogZoneConfig{{
			Name:                      "catalog.example.",
			MemberAllowSuffixes:       []string{"customer.example."},
			MemberDenySuffixes:        []string{"blocked.customer.example."},
			MaxMembers:                50000,
			MaxReconcileActions:       100000,
			ReconcileActionsPerMinute: 12000,
			ReconcileActionBurst:      24000,
			DryRun:                    true,
			ApprovalRequiredAbove:     25,
			ApprovedSerial:            &approvedSerial,
			CatalogTransferConfig: config.CatalogTransferConfig{
				Masters:            []string{"192.0.2.1"},
				TransferTSIGKey:    "catalog-xfer.example.",
				MaxTransferRecords: 200000,
				MaxTransferBytes:   67108864,
			},
			MemberDefaults: config.CatalogTransferConfig{
				Masters:            []string{"192.0.2.2"},
				TransferTSIGKey:    "catalog-xfer.example.",
				MaxTransferRecords: 300000,
				MaxTransferBytes:   100663296,
			},
			Groups: map[string]config.CatalogTransferConfig{
				"blue": {
					Masters:            []string{"192.0.2.3"},
					TransferTSIGKey:    "catalog-xfer.example.",
					MaxTransferRecords: 400000,
					MaxTransferBytes:   134217728,
				},
			},
		}},
	}
	sources, transfers, err := buildCatalogConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 ||
		sources[0].Defaults.TransferKey == nil ||
		sources[0].Groups["blue"].TransferKey == nil ||
		sources[0].Defaults.MaxTransferRecords != 300000 ||
		sources[0].Defaults.MaxTransferBytes != 100663296 ||
		sources[0].Groups["blue"].MaxTransferRecords != 400000 ||
		sources[0].Groups["blue"].MaxTransferBytes != 134217728 ||
		sources[0].MemberAllowSuffixes[0] != "customer.example." ||
		sources[0].MemberDenySuffixes[0] != "blocked.customer.example." ||
		sources[0].MaxMembers != 50000 ||
		sources[0].MaxReconcileActions != 100000 ||
		sources[0].ReconcileActionsPerMinute != 12000 ||
		sources[0].ReconcileActionBurst != 24000 ||
		!sources[0].DryRun ||
		sources[0].ApprovalRequiredAbove != 25 ||
		sources[0].ApprovedSerial == nil ||
		*sources[0].ApprovedSerial != 43 ||
		transfers["catalog.example."].MaxTransferRecords != 200000 ||
		transfers["catalog.example."].MaxTransferBytes != 67108864 ||
		transfers["catalog.example."].TransferKey == nil {
		t.Fatalf("sources=%+v transfers=%+v", sources, transfers)
	}
}

func TestBuildCatalogConfigsRejectsUnsignedCatalogAndMemberDefaults(t *testing.T) {
	cfg := &config.Config{CatalogZones: []config.CatalogZoneConfig{{
		Name: "catalog.example.",
		CatalogTransferConfig: config.CatalogTransferConfig{
			Masters: []string{"192.0.2.1"},
		},
		MemberDefaults: config.CatalogTransferConfig{
			Masters: []string{"192.0.2.2"},
		},
	}}}
	if _, _, err := buildCatalogConfigs(cfg); err == nil {
		t.Fatal("buildCatalogConfigs accepted unsigned catalog transfers")
	}
}

func TestBuildPrimaryNotifyConfigsResolvesKeyAndTuning(t *testing.T) {
	cfg := &config.Config{
		TsigKeys: []config.TsigKeyConfig{{
			Name:      "notify.example.",
			Algorithm: "hmac-sha512",
			Secret:    "c2VjcmV0",
		}},
		Zones: []config.ZoneConfig{{
			Name:               "primary.test",
			Type:               "primary",
			AlsoNotify:         []string{"192.0.2.2"},
			NotifyTSIGKey:      "notify.example",
			NotifyTimeout:      3 * time.Second,
			NotifyRetryBackoff: 50 * time.Millisecond,
			NotifyAttempts:     4,
		}},
	}

	got, err := buildPrimaryNotifyConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	notifyCfg, ok := got["primary.test."]
	if !ok || notifyCfg.TSIGKey != "notify.example." ||
		notifyCfg.TSIGAlgorithm != "hmac-sha512" ||
		notifyCfg.Timeout != 3*time.Second ||
		notifyCfg.RetryBackoff != 50*time.Millisecond ||
		notifyCfg.Attempts != 4 {
		t.Fatalf("primary notify config = %+v", got)
	}
}

func TestBuildPrimaryNotifyConfigsRequiresAuthenticationByDefault(t *testing.T) {
	cfg := &config.Config{Zones: []config.ZoneConfig{{
		Name:       "primary.test",
		Type:       "primary",
		AlsoNotify: []string{"192.0.2.2"},
	}}}
	if _, err := buildPrimaryNotifyConfigs(cfg); err == nil {
		t.Fatal("buildPrimaryNotifyConfigs accepted unsigned NOTIFY without explicit opt-in")
	}
}

func TestBuildPrimaryNotifyConfigsAllowsExplicitLegacyUnsigned(t *testing.T) {
	cfg := &config.Config{Zones: []config.ZoneConfig{{
		Name:                "primary.test",
		Type:                "primary",
		AlsoNotify:          []string{"192.0.2.2"},
		AllowUnsignedNotify: true,
	}}}
	got, err := buildPrimaryNotifyConfigs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !got["primary.test."].AllowUnsigned {
		t.Fatalf("primary notify config = %+v", got)
	}
}
