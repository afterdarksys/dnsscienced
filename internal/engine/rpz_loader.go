package engine

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// LoadRPZFile parses all five standard RPZ trigger families into memory.
// Supported targets follow RPZ conventions: ".", "*.", "rpz-passthru.",
// "rpz-drop.", or a rewrite target.
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
		nsDNameOwner, nsDName := strings.CutSuffix(relative, ".rpz-nsdname")
		if relative == "rpz-nsdname" {
			nsDName = true
			nsDNameOwner = ""
		}
		nsIPOwner, nsIP := strings.CutSuffix(relative, ".rpz-nsip")
		if relative == "rpz-nsip" {
			nsIP = true
			nsIPOwner = ""
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
		} else if nsDName {
			wildcard := strings.HasPrefix(nsDNameOwner, "*.")
			trigger := strings.TrimPrefix(nsDNameOwner, "*.")
			if trigger == "" {
				return nil, fmt.Errorf("invalid RPZ-NSDNAME trigger %q: nameserver name is required", owner)
			}
			rpz.AddNSDNameRule(
				trigger,
				action,
				rewriteTarget,
				reason,
				filename,
				wildcard,
			)
		} else if nsIP {
			prefix, err := parseRPZIPTrigger(nsIPOwner)
			if err != nil {
				return nil, fmt.Errorf("invalid RPZ-NSIP trigger %q: %w", owner, err)
			}
			if err := rpz.AddNSIPRule(prefix, action, rewriteTarget, reason, filename); err != nil {
				return nil, fmt.Errorf("invalid RPZ-NSIP trigger %q: %w", owner, err)
			}
		} else {
			wildcard := strings.HasPrefix(relative, "*.")
			trigger := strings.TrimPrefix(relative, "*.")
			rpz.addRule(trigger, action, rewriteTarget, reason, filename, wildcard, wildcard)
		}
		ruleCount++
	}

	if ruleCount == 0 {
		return nil, fmt.Errorf("RPZ file contains no supported policies")
	}
	return rpz, nil
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
