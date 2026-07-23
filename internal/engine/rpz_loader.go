package engine

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// LoadRPZFile parses QNAME, RPZ-CLIENT-IP, and RPZ-IP CNAME policies into an
// in-memory RPZ. The supported targets follow RPZ conventions: ".", "*.",
// "rpz-passthru.", "rpz-drop.", or a rewrite target.
func LoadRPZFile(name, filename, reason string) (*RPZ, error) {
	parsed, err := zone.ParseZoneFile(filename, zone.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("parse RPZ file: %w", err)
	}
	if parsed.Origin == "" {
		return nil, fmt.Errorf("RPZ file has no origin")
	}
	if reason == "" {
		reason = name
	}

	rpz := NewRPZ(name)
	ruleCount := 0
	owners := make(map[string]struct{})
	origin := strings.ToLower(dns.Fqdn(parsed.Origin))
	for _, rr := range parsed.GetAllRecords() {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}

		owner := strings.ToLower(dns.Fqdn(cname.Hdr.Name))
		if !dns.IsSubDomain(origin, owner) || owner == origin {
			continue
		}
		relative := strings.TrimSuffix(owner, origin)
		relative = strings.TrimSuffix(relative, ".")
		if relative == "" {
			continue
		}
		responseIPOwner, responseIP := strings.CutSuffix(relative, ".rpz-ip")
		if relative == "rpz-ip" {
			responseIP = true
			responseIPOwner = ""
		}
		clientIPOwner, clientIP := strings.CutSuffix(relative, ".rpz-client-ip")
		if relative == "rpz-client-ip" {
			clientIP = true
			clientIPOwner = ""
		}
		if isUnsupportedRPZTrigger(relative) {
			return nil, fmt.Errorf("unsupported RPZ trigger %q", owner)
		}
		if _, duplicate := owners[owner]; duplicate {
			return nil, fmt.Errorf("multiple CNAME policies for RPZ owner %q", owner)
		}
		owners[owner] = struct{}{}

		target := strings.ToLower(dns.Fqdn(cname.Target))
		action, rewriteTarget := rpzPolicyAction(target)
		if responseIP {
			prefix, err := parseRPZIPTrigger(responseIPOwner)
			if err != nil {
				return nil, fmt.Errorf("invalid RPZ-IP trigger %q: %w", owner, err)
			}
			if err := rpz.AddResponseIPRule(prefix, action, rewriteTarget, reason, filename); err != nil {
				return nil, fmt.Errorf("invalid RPZ-IP trigger %q: %w", owner, err)
			}
		} else if clientIP {
			prefix, err := parseRPZIPTrigger(clientIPOwner)
			if err != nil {
				return nil, fmt.Errorf("invalid RPZ-CLIENT-IP trigger %q: %w", owner, err)
			}
			if err := rpz.AddClientIPRule(prefix, action, rewriteTarget, reason, filename); err != nil {
				return nil, fmt.Errorf("invalid RPZ-CLIENT-IP trigger %q: %w", owner, err)
			}
		} else {
			wildcard := strings.HasPrefix(relative, "*.")
			trigger := strings.TrimPrefix(relative, "*.")
			rpz.addRule(trigger, action, rewriteTarget, reason, filename, wildcard, wildcard)
		}
		ruleCount++
	}

	if ruleCount == 0 {
		return nil, fmt.Errorf("RPZ file contains no supported QNAME policies")
	}
	return rpz, nil
}

func isUnsupportedRPZTrigger(relative string) bool {
	for _, suffix := range []string{
		"rpz-nsip",
		"rpz-nsdname",
	} {
		if relative == suffix || strings.HasSuffix(relative, "."+suffix) {
			return true
		}
	}
	return false
}

func rpzPolicyAction(target string) (RPZAction, string) {
	switch target {
	case ".":
		return RPZActionNXDomain, ""
	case "*.":
		return RPZActionNoData, ""
	case "rpz-passthru.":
		return RPZActionPassthru, ""
	case "rpz-drop.":
		return RPZActionDrop, ""
	default:
		return RPZActionRewrite, target
	}
}

func parseRPZIPTrigger(encoded string) (netip.Prefix, error) {
	labels := strings.Split(encoded, ".")
	if len(labels) < 2 {
		return netip.Prefix{}, fmt.Errorf("missing prefix length or address")
	}
	bits, err := parseRPZDecimal(labels[0], 128)
	if err != nil || bits == 0 {
		return netip.Prefix{}, fmt.Errorf("invalid prefix length %q", labels[0])
	}
	addressLabels := labels[1:]
	if len(addressLabels) == 4 && !containsRPZCompression(addressLabels) && bits <= 32 {
		var octets [4]byte
		for i, label := range addressLabels {
			value, err := parseRPZDecimal(label, 255)
			if err != nil {
				return netip.Prefix{}, fmt.Errorf("invalid IPv4 octet %q", label)
			}
			octets[3-i] = byte(value)
		}
		addr := netip.AddrFrom4(octets)
		prefix := netip.PrefixFrom(addr, bits)
		if prefix.Masked().Addr() != addr {
			return netip.Prefix{}, fmt.Errorf("non-zero host bits in %s", prefix)
		}
		return prefix, nil
	}

	words, err := parseRPZIPv6Words(addressLabels)
	if err != nil {
		return netip.Prefix{}, err
	}
	var raw [16]byte
	for i, word := range words {
		binary.BigEndian.PutUint16(raw[i*2:], word)
	}
	addr := netip.AddrFrom16(raw)
	prefix := netip.PrefixFrom(addr, bits)
	if prefix.Masked().Addr() != addr {
		return netip.Prefix{}, fmt.Errorf("non-zero host bits in %s", prefix)
	}
	return prefix, nil
}

func containsRPZCompression(labels []string) bool {
	for _, label := range labels {
		if label == "zz" {
			return true
		}
	}
	return false
}

func parseRPZDecimal(value string, maximum int) (int, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, fmt.Errorf("non-canonical decimal")
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 || parsed > maximum {
		return 0, fmt.Errorf("out of range")
	}
	return parsed, nil
}

func parseRPZIPv6Words(reversed []string) ([8]uint16, error) {
	var result [8]uint16
	zz := -1
	for i, label := range reversed {
		if label == "zz" {
			if zz != -1 {
				return result, fmt.Errorf("multiple IPv6 zz compression labels")
			}
			zz = i
			continue
		}
		if label == "" || len(label) > 4 || (len(label) > 1 && label[0] == '0') {
			return result, fmt.Errorf("invalid IPv6 word %q", label)
		}
		value, err := strconv.ParseUint(label, 16, 16)
		if err != nil {
			return result, fmt.Errorf("invalid IPv6 word %q", label)
		}
		reversed[i] = strconv.FormatUint(value, 16)
	}
	if zz == -1 && len(reversed) != 8 {
		return result, fmt.Errorf("IPv6 trigger requires eight words or zz compression")
	}
	if zz != -1 && len(reversed) > 8 {
		return result, fmt.Errorf("IPv6 trigger has too many words")
	}

	expanded := make([]uint16, 0, 8)
	for i, label := range reversed {
		if i == zz {
			for range 9 - len(reversed) {
				expanded = append(expanded, 0)
			}
			continue
		}
		value, _ := strconv.ParseUint(label, 16, 16)
		expanded = append(expanded, uint16(value))
	}
	if len(expanded) != 8 {
		return result, fmt.Errorf("IPv6 trigger does not encode eight words")
	}
	for i, word := range expanded {
		result[7-i] = word
	}
	return result, nil
}
