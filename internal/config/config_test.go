package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file
	yamlContent := `
server:
  udp_addr: ":1053"
  udp_listeners: 2
  primary_notify_workers: 6
  enable_recursive: true
  read_timeout: 2s
  rrl:
    enabled: true
    responses_per_second: 50
    exempt_cidrs:
      - "192.168.1.0/24"
      - "10.0.0.0/8"

resolver:
  cache:
    max_entries: 500
    darkapi_key: "test-key-123"
  forwarders:
    - "8.8.8.8:53"

runtime:
  max_procs: 6
  gc_percent: 80
  memory_limit_mb: 768

dhcp:
  enabled: true
  interfaces: ["eth0", "eth1"]
  failover:
    enabled: true
    name: "ha-pair-1"
    role: "primary"
    peer: "192.168.1.5"
    mode: "load-balance"
    mclt: 3600s
    split: 128
    site_id: "nyc-dc1"
    vrrp_interface: "eth0"
    
  lease:
    default: 24h
    max: 72h
    min: 1h
    
  boot:
    filename: "pxelinux.0"
    next_server: "192.168.1.50"
    
  snooping:
    enabled: true
    trust_all: false
    trusted_relays: ["10.0.0.1/32"]
    
  option_defs:
    - name: "unifi-controller"
      code: 43
      type: "ip"
  
  global_options:
    "domain-name": "example.com"
    "unifi-controller": "10.0.0.5"
  
  option_sets:
    "voip":
      "tftp-server-name": "192.168.1.10"
      
  classes:
    - name: "Polycom Phones"
      match: "option[60] contains 'Polycom'"
      option_set: "voip"
      
  hosts:
    - hostname: "printer-1"
      mac: "00:11:22:33:44:55"
      ip: "192.168.1.250"
      
  subnets:
    - subnet: "192.168.1.0/24"
      range: "192.168.1.100-192.168.1.200"
      lease:
        default: 12h
      options:
        "routers": "192.168.1.1"
`
	tmpfile, err := os.CreateTemp("", "dnsscienced-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tmpfile.Close()

	// Load the config
	cfg, err := Load(tmpfile.Name())
	require.NoError(t, err)

	// Verify Server Config
	assert.Equal(t, ":1053", cfg.Server.UDPAddr)
	assert.Equal(t, 2, cfg.Server.UDPListeners)
	assert.Equal(t, 6, cfg.Server.PrimaryNotifyWorkers)
	assert.Equal(t, true, cfg.Server.EnableRecursive)
	assert.Equal(t, 2*time.Second, cfg.Server.ReadTimeout)

	// Verify RRL Config
	assert.Equal(t, true, cfg.Server.RRLConfig.Enabled)
	assert.Equal(t, 50, cfg.Server.RRLConfig.ResponsesPerSecond)
	assert.Len(t, cfg.Server.RRLConfig.ExemptCIDRs, 2)
	assert.Len(t, cfg.Server.RRLConfig.ExemptPrefixes, 2)
	assert.Equal(t, "192.168.1.0/24", cfg.Server.RRLConfig.ExemptPrefixes[0].String())

	// Verify Resolver/Cache Config
	assert.Equal(t, 500, cfg.Resolver.CacheConfig.MaxEntries)
	assert.Equal(t, "test-key-123", cfg.Resolver.CacheConfig.DarkAPIKey)

	// Verify Go runtime tuning is decoded but not applied by Load.
	require.NotNil(t, cfg.Runtime.GCPercent)
	assert.Equal(t, 6, cfg.Runtime.MaxProcs)
	assert.Equal(t, 80, *cfg.Runtime.GCPercent)
	assert.Equal(t, int64(768), cfg.Runtime.MemoryLimitMB)

	// Verify DHCP Config
	assert.True(t, cfg.DHCP.Enabled)
	assert.Equal(t, []string{"eth0", "eth1"}, cfg.DHCP.Interfaces)

	// Verify Failover
	assert.True(t, cfg.DHCP.Failover.Enabled)
	assert.Equal(t, "ha-pair-1", cfg.DHCP.Failover.Name)
	assert.Equal(t, "primary", cfg.DHCP.Failover.Role)
	assert.Equal(t, "192.168.1.5", cfg.DHCP.Failover.Peer)
	assert.Equal(t, "eth0", cfg.DHCP.Failover.VRRPInterface)
	// New Failover Fields
	assert.Equal(t, "load-balance", cfg.DHCP.Failover.Mode)
	assert.Equal(t, 3600*time.Second, cfg.DHCP.Failover.MCLT)
	assert.Equal(t, 128, cfg.DHCP.Failover.Split)
	assert.Equal(t, "nyc-dc1", cfg.DHCP.Failover.SiteID)

	// Verify Lease
	assert.Equal(t, 24*time.Hour, cfg.DHCP.Lease.Default)
	assert.Equal(t, 72*time.Hour, cfg.DHCP.Lease.Max)
	assert.Equal(t, 1*time.Hour, cfg.DHCP.Lease.Min)

	// Verify Boot
	assert.Equal(t, "pxelinux.0", cfg.DHCP.Boot.Filename)
	assert.Equal(t, "192.168.1.50", cfg.DHCP.Boot.NextServer)

	// Verify Snooping
	assert.True(t, cfg.DHCP.Snooping.Enabled)
	assert.False(t, cfg.DHCP.Snooping.TrustAll)
	assert.Equal(t, []string{"10.0.0.1/32"}, cfg.DHCP.Snooping.TrustedRelays)

	// Verify Custom Options
	require.Len(t, cfg.DHCP.OptionDefs, 1)
	assert.Equal(t, "unifi-controller", cfg.DHCP.OptionDefs[0].Name)
	assert.Equal(t, 43, cfg.DHCP.OptionDefs[0].Code)
	assert.Equal(t, "ip", cfg.DHCP.OptionDefs[0].Type)

	// Verify Hosts
	require.Len(t, cfg.DHCP.Hosts, 1)
	assert.Equal(t, "printer-1", cfg.DHCP.Hosts[0].Hostname)
	assert.Equal(t, "00:11:22:33:44:55", cfg.DHCP.Hosts[0].MAC)
	assert.Equal(t, "192.168.1.250", cfg.DHCP.Hosts[0].IP)

	assert.Equal(t, "example.com", cfg.DHCP.GlobalOptions["domain-name"])
	assert.Equal(t, "10.0.0.5", cfg.DHCP.GlobalOptions["unifi-controller"])

	assert.Contains(t, cfg.DHCP.OptionSets, "voip")
	assert.Equal(t, "192.168.1.10", cfg.DHCP.OptionSets["voip"]["tftp-server-name"])

	require.Len(t, cfg.DHCP.Classes, 1)
	assert.Equal(t, "Polycom Phones", cfg.DHCP.Classes[0].Name)
	assert.Equal(t, "voip", cfg.DHCP.Classes[0].OptionSet)

	require.Len(t, cfg.DHCP.Subnets, 1)
	assert.Equal(t, "192.168.1.0/24", cfg.DHCP.Subnets[0].Subnet)
	assert.Equal(t, "192.168.1.100-192.168.1.200", cfg.DHCP.Subnets[0].Range)
	assert.Equal(t, "192.168.1.1", cfg.DHCP.Subnets[0].Options["routers"])
	// Verify Subnet Override
	assert.Equal(t, 12*time.Hour, cfg.DHCP.Subnets[0].Lease.Default)
}

func TestMastersAndForwarders(t *testing.T) {
	yamlContent := `
masters:
  internal:
    - "10.0.1.10:53"
    - "10.0.1.11:53"
  external:
    - "8.8.8.8:53"
    - "1.1.1.1:53"

forwarders:
  "":
    - "8.8.8.8:53"
    - "1.1.1.1:53"
  "corp.example.com":
    - "10.0.1.53:53"
`
	tmpfile, err := os.CreateTemp("", "dnsscienced-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tmpfile.Close()

	cfg, err := Load(tmpfile.Name())
	require.NoError(t, err)

	// Verify Masters
	assert.Len(t, cfg.Masters, 2)
	assert.Len(t, cfg.Masters["internal"], 2)
	assert.Equal(t, "10.0.1.10:53", cfg.Masters["internal"][0])
	assert.Equal(t, "10.0.1.11:53", cfg.Masters["internal"][1])
	assert.Len(t, cfg.Masters["external"], 2)

	// Verify Forwarders
	assert.Len(t, cfg.Forwarders, 2)
	assert.Len(t, cfg.Forwarders[""], 2) // Global forwarders
	assert.Equal(t, "8.8.8.8:53", cfg.Forwarders[""][0])
	assert.Len(t, cfg.Forwarders["corp.example.com"], 1)
	assert.Equal(t, "10.0.1.53:53", cfg.Forwarders["corp.example.com"][0])
}

func TestZoneConfigs(t *testing.T) {
	yamlContent := `
zones:
  - name: "example.com"
    type: "primary"
    file: "/etc/dnsscienced/zones/example.com.zone"
    enable_0x20: true
    enable_dnssec: true
    enable_scrubbing: true
    allow_transfer:
      - "192.0.2.0/24"
    allow_update:
      - "198.51.100.0/24"
    update_tsig_keys:
      - "update-key.example."
    also_notify:
      - "192.0.2.53:53"
    notify_tsig_key: "notify-key.example."
    notify_timeout: 2s
    notify_retry_backoff: 250ms
    notify_attempts: 4
    dnssec_signing:
      enabled: true
      algorithm: "ECDSAP256SHA256"
      ksk_lifetime: 8760h
      zsk_lifetime: 2160h
      signature_validity: 720h
      signature_refresh: 168h
      nsec3: true
      nsec3_iterations: 10
      nsec3_salt_length: 8

  - name: "secondary.example.com"
    type: "secondary"
    masters:
      - "10.0.1.10:53"
      - "10.0.1.11:53"
    transfer_source: "10.0.0.5"
    transfer_tsig_key: "secondary-xfer.example."
    allow_unsigned_transfer: true
    refresh_interval: 3600s

  - name: "forward.example.com"
    type: "forward"
    forwarders:
      - "203.0.113.53:53"
    forward_mode: "only"

  - name: "legacy.example.com"
    type: "primary"
    file: "/etc/dnsscienced/zones/legacy.zone"
    enable_0x20: false
`
	tmpfile, err := os.CreateTemp("", "dnsscienced-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(yamlContent))
	require.NoError(t, err)
	tmpfile.Close()

	cfg, err := Load(tmpfile.Name())
	require.NoError(t, err)

	// Verify number of zones
	require.Len(t, cfg.Zones, 4)

	// Verify primary zone
	primaryZone := cfg.Zones[0]
	assert.Equal(t, "example.com", primaryZone.Name)
	assert.Equal(t, "primary", primaryZone.Type)
	assert.Equal(t, "/etc/dnsscienced/zones/example.com.zone", primaryZone.File)
	require.NotNil(t, primaryZone.Enable0x20)
	assert.True(t, *primaryZone.Enable0x20)
	require.NotNil(t, primaryZone.EnableDNSSEC)
	assert.True(t, *primaryZone.EnableDNSSEC)
	require.NotNil(t, primaryZone.EnableScrubbing)
	assert.True(t, *primaryZone.EnableScrubbing)
	assert.Len(t, primaryZone.AllowTransfer, 1)
	assert.Equal(t, "192.0.2.0/24", primaryZone.AllowTransfer[0])
	assert.Equal(t, []string{"198.51.100.0/24"}, primaryZone.AllowUpdate)
	assert.Equal(t, []string{"update-key.example."}, primaryZone.UpdateTSIGKeys)
	assert.Len(t, primaryZone.AlsoNotify, 1)
	assert.Equal(t, "notify-key.example.", primaryZone.NotifyTSIGKey)
	assert.Equal(t, 2*time.Second, primaryZone.NotifyTimeout)
	assert.Equal(t, 250*time.Millisecond, primaryZone.NotifyRetryBackoff)
	assert.Equal(t, 4, primaryZone.NotifyAttempts)

	// Verify DNSSEC signing config
	require.NotNil(t, primaryZone.DNSSECSigning)
	assert.True(t, primaryZone.DNSSECSigning.Enabled)
	assert.Equal(t, "ECDSAP256SHA256", primaryZone.DNSSECSigning.Algorithm)
	assert.Equal(t, 8760*time.Hour, primaryZone.DNSSECSigning.KSKLifetime)
	assert.Equal(t, 2160*time.Hour, primaryZone.DNSSECSigning.ZSKLifetime)
	assert.Equal(t, 720*time.Hour, primaryZone.DNSSECSigning.SignatureValidity)
	assert.Equal(t, 168*time.Hour, primaryZone.DNSSECSigning.SignatureRefresh)
	assert.True(t, primaryZone.DNSSECSigning.NSEC3)
	assert.Equal(t, uint16(10), primaryZone.DNSSECSigning.NSEC3Iterations)
	assert.Equal(t, uint8(8), primaryZone.DNSSECSigning.NSEC3SaltLength)

	// Verify secondary zone
	secondaryZone := cfg.Zones[1]
	assert.Equal(t, "secondary.example.com", secondaryZone.Name)
	assert.Equal(t, "secondary", secondaryZone.Type)
	assert.Len(t, secondaryZone.Masters, 2)
	assert.Equal(t, "10.0.1.10:53", secondaryZone.Masters[0])
	assert.Equal(t, "10.0.0.5", secondaryZone.TransferSource)
	assert.Equal(t, "secondary-xfer.example.", secondaryZone.TransferTSIGKey)
	assert.True(t, secondaryZone.AllowUnsignedTransfer)
	assert.Equal(t, 3600*time.Second, secondaryZone.RefreshInterval)

	// Verify forward zone
	forwardZone := cfg.Zones[2]
	assert.Equal(t, "forward.example.com", forwardZone.Name)
	assert.Equal(t, "forward", forwardZone.Type)
	assert.Len(t, forwardZone.Forwarders, 1)
	assert.Equal(t, "203.0.113.53:53", forwardZone.Forwarders[0])
	assert.Equal(t, "only", forwardZone.ForwardMode)

	// Verify legacy zone with 0x20 disabled
	legacyZone := cfg.Zones[3]
	assert.Equal(t, "legacy.example.com", legacyZone.Name)
	require.NotNil(t, legacyZone.Enable0x20)
	assert.False(t, *legacyZone.Enable0x20)
}

func TestZoneConfigPointerFields(t *testing.T) {
	// Test per-zone security overrides
	enable0x20True := true
	enable0x20False := false

	zones := []ZoneConfig{
		{
			Name:       "secure.example.com",
			Type:       "primary",
			Enable0x20: &enable0x20True,
		},
		{
			Name:       "legacy.example.com",
			Type:       "primary",
			Enable0x20: &enable0x20False,
		},
		{
			Name: "default.example.com",
			Type: "primary",
			// Enable0x20 is nil, should use global setting
		},
	}

	// Zone 1: explicitly enabled
	require.NotNil(t, zones[0].Enable0x20)
	assert.True(t, *zones[0].Enable0x20)

	// Zone 2: explicitly disabled
	require.NotNil(t, zones[1].Enable0x20)
	assert.False(t, *zones[1].Enable0x20)

	// Zone 3: nil (use global)
	assert.Nil(t, zones[2].Enable0x20)
}

func TestTopLevelRuntimeSectionsAreAppliedToServer(t *testing.T) {
	yamlContent := `
resolver:
  enable_0x20: false
  query_timeout: 3s
cache:
  max_entries: 42
firewall:
  enabled: true
experimental:
  enabled: true
  doq:
    enabled: true
`
	path := writeConfigForTest(t, yamlContent)
	cfg, err := Load(path)
	require.NoError(t, err)
	assert.False(t, cfg.Server.RecursiveConfig.Enable0x20)
	assert.Equal(t, 3*time.Second, cfg.Server.RecursiveConfig.QueryTimeout)
	assert.Equal(t, 42, cfg.Server.RecursiveConfig.CacheConfig.MaxEntries)
	assert.NotZero(t, cfg.Server.RecursiveConfig.CacheConfig.MaxTTL, "overlay must retain resolver defaults")
	assert.True(t, cfg.Server.Firewall.Enabled)
	assert.True(t, cfg.Server.Experimental.Enabled)
	assert.True(t, cfg.Server.Experimental.DoQ.Enabled)
}

func writeConfigForTest(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestDistributedExampleConfigsParse(t *testing.T) {
	for _, name := range []string{"config.example.yaml", "config.production.yaml"} {
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(filepath.Join("..", "..", name))
			require.NoError(t, err)
			assert.Equal(t, 100, cfg.Server.RecursiveConfig.Workers)
			assert.Equal(t, 1000, cfg.Server.RecursiveConfig.WorkerQueueSize)
			assert.Equal(t, 2*time.Second, cfg.Server.RecursiveConfig.QueryTimeout)
			assert.Equal(t, 2, cfg.Server.RecursiveConfig.NameserverParallelism)
			assert.Equal(t, 25*time.Millisecond, cfg.Server.RecursiveConfig.NameserverHedgeDelay)
			if name == "config.example.yaml" {
				assert.Equal(t, 10000, cfg.Server.RecursiveConfig.CacheConfig.MaxEntries)
				assert.Equal(t, "json", cfg.Logging.Format)
			} else {
				assert.Equal(t, 100000, cfg.Server.RecursiveConfig.CacheConfig.MaxEntries)
			}
		})
	}
}
