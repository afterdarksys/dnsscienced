package config

import (
	"fmt"
	"net"
	"strings"
)

const (
	RoleCustom        = "custom"
	RoleAuthoritative = "authoritative"
	RoleRecursive     = "recursive"
	RoleForwarder     = "forwarder"
	RoleLocalRoot     = "local-root"
	RolePublicRoot    = "public-root"
)

// ApplyRoleProfile applies secure defaults and rejects configurations that
// contradict the selected deployment role. Empty roles retain legacy behavior;
// custom is an explicit acknowledgement that the operator is composing modes.
func (c *Config) ApplyRoleProfile() error {
	role := strings.ToLower(strings.TrimSpace(c.Role))
	c.Role = role
	switch role {
	case "", RoleCustom:
		return nil
	case RoleAuthoritative:
		if c.Server.EnableRecursive {
			return roleError(role, "recursion must be disabled")
		}
		if err := c.rejectForwarding(role); err != nil {
			return err
		}
		c.Server.EnableAuthoritative = true
	case RoleRecursive:
		if c.Server.EnableAuthoritative {
			return roleError(role, "authoritative service must be disabled")
		}
		if err := c.rejectAuthoritativeData(role); err != nil {
			return err
		}
		c.Server.EnableRecursive = true
	case RoleForwarder:
		if c.Server.EnableAuthoritative {
			return roleError(role, "authoritative service must be disabled")
		}
		if err := c.rejectAuthoritativeData(role); err != nil {
			return err
		}
		if !c.hasGlobalForwardingUpstream() {
			return roleError(role, "at least one global upstream is required")
		}
		mode := strings.ToLower(strings.TrimSpace(c.Server.RecursiveConfig.ForwardMode))
		if mode == "first" {
			return roleError(role, "forward_mode first permits direct fallback; use only")
		}
		c.Server.EnableRecursive = true
		c.Server.RecursiveConfig.ForwardMode = "only"
	case RoleLocalRoot:
		if err := c.applyRootRole(role, true); err != nil {
			return err
		}
	case RolePublicRoot:
		if err := c.applyRootRole(role, false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("role %q is unknown (valid: custom, authoritative, recursive, forwarder, local-root, public-root)", c.Role)
	}
	return nil
}

func (c *Config) applyRootRole(role string, requireLoopback bool) error {
	if c.Server.EnableRecursive {
		return roleError(role, "recursion must be disabled")
	}
	if err := c.rejectForwarding(role); err != nil {
		return err
	}
	if c.Server.RPZ.Enabled {
		return roleError(role, "RPZ tenant policy is not allowed")
	}
	if c.ZonesDir != "" {
		return roleError(role, "zones_dir is not allowed; configure exactly one explicit root zone")
	}
	if len(c.CatalogZones) != 0 {
		return roleError(role, "catalog zones are not allowed")
	}
	if len(c.Zones) != 1 || strings.TrimSpace(c.Zones[0].Name) != "." {
		return roleError(role, "exactly one explicit root zone named . is required")
	}
	zoneType := strings.ToLower(strings.TrimSpace(c.Zones[0].Type))
	if zoneType != "primary" && zoneType != "secondary" {
		return roleError(role, "the root zone must be primary or secondary")
	}
	if requireLoopback {
		for _, listener := range []struct {
			name    string
			address string
		}{
			{name: "server.udp_addr", address: c.Server.UDPAddr},
			{name: "server.tcp_addr", address: c.Server.TCPAddr},
		} {
			if err := requireLoopbackAddress(listener.name, listener.address); err != nil {
				return roleError(role, err.Error())
			}
		}
		if c.Server.DoT.Enabled {
			if err := requireLoopbackAddress("server.dot.address", c.Server.DoT.Address); err != nil {
				return roleError(role, err.Error())
			}
		}
		if c.Server.DoH.Enabled {
			if err := requireLoopbackAddress("server.doh.address", c.Server.DoH.Address); err != nil {
				return roleError(role, err.Error())
			}
		}
	}
	c.Server.EnableAuthoritative = true
	c.Server.EnableRecursive = false
	return nil
}

func (c *Config) rejectAuthoritativeData(role string) error {
	if c.ZonesDir != "" || len(c.CatalogZones) != 0 {
		return roleError(role, "authoritative zone sources are not allowed")
	}
	for _, zone := range c.Zones {
		switch strings.ToLower(strings.TrimSpace(zone.Type)) {
		case "", "primary", "secondary":
			return roleError(role, fmt.Sprintf("authoritative zone %q is not allowed", zone.Name))
		}
	}
	return nil
}

func (c *Config) rejectForwarding(role string) error {
	if c.hasForwardingUpstream() {
		return roleError(role, "forwarding configuration is not allowed")
	}
	mode := strings.ToLower(strings.TrimSpace(c.Server.RecursiveConfig.ForwardMode))
	if mode != "" && mode != "direct" {
		return roleError(role, "forward_mode must be direct")
	}
	return nil
}

func (c *Config) hasForwardingUpstream() bool {
	if len(c.Server.RecursiveConfig.Forwarders) != 0 || len(c.Forwarders) != 0 {
		return true
	}
	for _, zone := range c.Zones {
		if strings.EqualFold(strings.TrimSpace(zone.Type), "forward") || len(zone.Forwarders) != 0 {
			return true
		}
	}
	return false
}

func (c *Config) hasGlobalForwardingUpstream() bool {
	if len(c.Server.RecursiveConfig.Forwarders) != 0 {
		return true
	}
	return len(c.Forwarders[""]) != 0
}

func requireLoopbackAddress(field, address string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("%s must be an IP:port loopback address: %w", field, err)
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s must bind an explicit loopback IP", field)
	}
	return nil
}

func roleError(role, message string) error {
	return fmt.Errorf("role %s: %s", role, message)
}
