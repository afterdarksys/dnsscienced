package config

import (
	"os"
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
