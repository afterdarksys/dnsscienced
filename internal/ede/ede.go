package ede

import (
	"github.com/miekg/dns"
)

// Extended DNS Error (EDE) codes from RFC 8914
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes
const (
	// Informational codes
	InfoCodeOther                    uint16 = 0  // Other Error
	InfoCodeUnsupportedDNSKEYAlg     uint16 = 1  // Unsupported DNSKEY Algorithm
	InfoCodeUnsupportedDSDigest      uint16 = 2  // Unsupported DS Digest Type
	InfoCodeStaleAnswer              uint16 = 3  // Stale Answer
	InfoCodeForgedAnswer             uint16 = 4  // Forged Answer
	InfoCodeDNSSECIndeterminate      uint16 = 5  // DNSSEC Indeterminate
	InfoCodeDNSSECBogus              uint16 = 6  // DNSSEC Bogus
	InfoCodeSignatureExpired         uint16 = 7  // Signature Expired
	InfoCodeSignatureNotYetValid     uint16 = 8  // Signature Not Yet Valid
	InfoCodeDNSKEYMissing            uint16 = 9  // DNSKEY Missing
	InfoCodeRRSIGsMissing            uint16 = 10 // RRSIGs Missing
	InfoCodeNoZoneKeyBitSet          uint16 = 11 // No Zone Key Bit Set
	InfoCodeNSECMissing              uint16 = 12 // NSEC Missing
	InfoCodeCachedError              uint16 = 13 // Cached Error
	InfoCodeNotReady                 uint16 = 14 // Not Ready
	InfoCodeBlocked                  uint16 = 15 // Blocked
	InfoCodeCensored                 uint16 = 16 // Censored
	InfoCodeFiltered                 uint16 = 17 // Filtered
	InfoCodeProhibited               uint16 = 18 // Prohibited
	InfoCodeStaleNXDOMAINAnswer      uint16 = 19 // Stale NXDOMAIN Answer
	InfoCodeNotAuthoritative         uint16 = 20 // Not Authoritative
	InfoCodeNotSupported             uint16 = 21 // Not Supported
	InfoCodeNoReachableAuthority     uint16 = 22 // No Reachable Authority
	InfoCodeNetworkError             uint16 = 23 // Network Error
	InfoCodeInvalidData              uint16 = 24 // Invalid Data
	InfoCodeSignatureExpiredBeforeValid uint16 = 25 // Signature Expired Before Valid
	InfoCodeTooEarly                 uint16 = 26 // Too Early (draft-ietf-dnsop-serve-stale)
	InfoCodeUnsupportedNSEC3Iterations uint16 = 27 // Unsupported NSEC3 Iterations Value
)

// EDE represents an Extended DNS Error
type EDE struct {
	InfoCode  uint16 // EDE info code
	ExtraText string // Optional extra text
}

// Common EDE instances for reuse
var (
	EDEBlocked = EDE{
		InfoCode:  InfoCodeBlocked,
		ExtraText: "Domain blocked by protective DNS policy",
	}
	EDECensored = EDE{
		InfoCode:  InfoCodeCensored,
		ExtraText: "Domain censored by protective DNS policy",
	}
	EDEFiltered = EDE{
		InfoCode:  InfoCodeFiltered,
		ExtraText: "Domain filtered by protective DNS policy",
	}
	EDEMalware = EDE{
		InfoCode:  InfoCodeBlocked,
		ExtraText: "Domain blocked: malware",
	}
	EDEPhishing = EDE{
		InfoCode:  InfoCodeBlocked,
		ExtraText: "Domain blocked: phishing",
	}
	EDEC2 = EDE{
		InfoCode:  InfoCodeBlocked,
		ExtraText: "Domain blocked: command & control",
	}
	EDECryptomining = EDE{
		InfoCode:  InfoCodeBlocked,
		ExtraText: "Domain blocked: cryptomining",
	}
	EDEDNSSECBogus = EDE{
		InfoCode:  InfoCodeDNSSECBogus,
		ExtraText: "DNSSEC validation failed",
	}
	EDEStaleAnswer = EDE{
		InfoCode:  InfoCodeStaleAnswer,
		ExtraText: "Answer served from stale cache",
	}
)

// AddToMessage adds an EDE option to a DNS message
func (e *EDE) AddToMessage(msg *dns.Msg) {
	if msg == nil {
		return
	}

	// Find or create OPT record
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, false)
		opt = msg.IsEdns0()
	}

	if opt == nil {
		return // Failed to create OPT record
	}

	// Create EDE option
	ede := &dns.EDNS0_EDE{
		InfoCode:  e.InfoCode,
		ExtraText: e.ExtraText,
	}

	// Add to OPT record
	opt.Option = append(opt.Option, ede)
}

// NewEDE creates a new Extended DNS Error
func NewEDE(infoCode uint16, extraText string) *EDE {
	return &EDE{
		InfoCode:  infoCode,
		ExtraText: extraText,
	}
}

// NewBlockedEDE creates an EDE for a blocked domain with category
func NewBlockedEDE(category string) *EDE {
	var extraText string
	switch category {
	case "malware":
		extraText = "Domain blocked: malware"
	case "phishing":
		extraText = "Domain blocked: phishing"
	case "c2", "command-control":
		extraText = "Domain blocked: command & control"
	case "cryptomining":
		extraText = "Domain blocked: cryptomining"
	case "spam":
		extraText = "Domain blocked: spam"
	case "adult":
		extraText = "Domain blocked: adult content"
	case "gambling":
		extraText = "Domain blocked: gambling"
	case "ads", "advertising":
		extraText = "Domain blocked: advertising"
	case "tracking":
		extraText = "Domain blocked: tracking"
	case "botnet":
		extraText = "Domain blocked: botnet"
	default:
		extraText = "Domain blocked by protective DNS policy"
	}

	return &EDE{
		InfoCode:  InfoCodeBlocked,
		ExtraText: extraText,
	}
}

// GetEDEFromMessage extracts EDE options from a DNS message
func GetEDEFromMessage(msg *dns.Msg) []*EDE {
	if msg == nil {
		return nil
	}

	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}

	var edes []*EDE
	for _, option := range opt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok {
			edes = append(edes, &EDE{
				InfoCode:  ede.InfoCode,
				ExtraText: ede.ExtraText,
			})
		}
	}

	return edes
}

// InfoCodeToString returns a human-readable description of an EDE info code
func InfoCodeToString(infoCode uint16) string {
	switch infoCode {
	case InfoCodeOther:
		return "Other Error"
	case InfoCodeUnsupportedDNSKEYAlg:
		return "Unsupported DNSKEY Algorithm"
	case InfoCodeUnsupportedDSDigest:
		return "Unsupported DS Digest Type"
	case InfoCodeStaleAnswer:
		return "Stale Answer"
	case InfoCodeForgedAnswer:
		return "Forged Answer"
	case InfoCodeDNSSECIndeterminate:
		return "DNSSEC Indeterminate"
	case InfoCodeDNSSECBogus:
		return "DNSSEC Bogus"
	case InfoCodeSignatureExpired:
		return "Signature Expired"
	case InfoCodeSignatureNotYetValid:
		return "Signature Not Yet Valid"
	case InfoCodeDNSKEYMissing:
		return "DNSKEY Missing"
	case InfoCodeRRSIGsMissing:
		return "RRSIGs Missing"
	case InfoCodeNoZoneKeyBitSet:
		return "No Zone Key Bit Set"
	case InfoCodeNSECMissing:
		return "NSEC Missing"
	case InfoCodeCachedError:
		return "Cached Error"
	case InfoCodeNotReady:
		return "Not Ready"
	case InfoCodeBlocked:
		return "Blocked"
	case InfoCodeCensored:
		return "Censored"
	case InfoCodeFiltered:
		return "Filtered"
	case InfoCodeProhibited:
		return "Prohibited"
	case InfoCodeStaleNXDOMAINAnswer:
		return "Stale NXDOMAIN Answer"
	case InfoCodeNotAuthoritative:
		return "Not Authoritative"
	case InfoCodeNotSupported:
		return "Not Supported"
	case InfoCodeNoReachableAuthority:
		return "No Reachable Authority"
	case InfoCodeNetworkError:
		return "Network Error"
	case InfoCodeInvalidData:
		return "Invalid Data"
	case InfoCodeSignatureExpiredBeforeValid:
		return "Signature Expired Before Valid"
	case InfoCodeTooEarly:
		return "Too Early"
	case InfoCodeUnsupportedNSEC3Iterations:
		return "Unsupported NSEC3 Iterations Value"
	default:
		return "Unknown"
	}
}

// String returns a string representation of the EDE
func (e *EDE) String() string {
	desc := InfoCodeToString(e.InfoCode)
	if e.ExtraText != "" {
		return desc + ": " + e.ExtraText
	}
	return desc
}
