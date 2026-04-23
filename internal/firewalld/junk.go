package firewalld

import (
	"math"
	"strings"

	"github.com/miekg/dns"
)

// JunkDetector identifies bogus / bot-generated DNS queries.
//
// It detects three patterns without any lock contention:
//
//  1. DGA domains: SLD entropy > 4.2 (reuses engine.IsDGA logic inline
//     to avoid a circular dependency between firewalld and engine).
//  2. DNS tunnels / data exfiltration: full name length > 60 chars and
//     label entropy > 4.5.
//  3. Random-subdomain bots: leftmost label entropy exceeds the
//     configured threshold (default 4.0) — catches patterns like
//     3334dcscs-1714000000.foo.com.
type JunkDetector struct {
	cfg JunkConfig
}

func newJunkDetector(cfg JunkConfig) *JunkDetector {
	if cfg.RandomSubdomainThreshold == 0 {
		cfg.RandomSubdomainThreshold = 4.0
	}
	return &JunkDetector{cfg: cfg}
}

// Detect returns a non-ALLOW Decision when qctx.Name looks like junk.
func (jd *JunkDetector) Detect(qctx *QueryContext) *Decision {
	name := qctx.Name
	// Strip trailing dot for analysis.
	bare := strings.TrimSuffix(name, ".")

	labels := dns.SplitDomainName(bare)
	if len(labels) == 0 {
		return allow()
	}

	// Check data exfiltration / DNS tunnel first (longer check, catches
	// base64-encoded payloads in sub-labels).
	if jd.cfg.BlockDataExfil && jd.isDataExfil(bare) {
		return &Decision{
			Verdict:  VerdictNXDomain,
			Reason:   "dns tunnel / data exfiltration pattern",
			RuleName: "junk:data_exfil",
		}
	}

	// DGA check on the SLD (second-level domain label).
	if jd.cfg.BlockDGA && len(labels) >= 2 {
		sld := labels[len(labels)-2]
		if jd.isDGA(sld) {
			return &Decision{
				Verdict:  VerdictNXDomain,
				Reason:   "DGA domain detected",
				RuleName: "junk:dga",
			}
		}
	}

	// Random subdomain bot: leftmost label entropy above threshold.
	if jd.cfg.BlockRandomSubdomain && len(labels) >= 2 {
		leftmost := labels[0]
		if entropy(leftmost) > jd.cfg.RandomSubdomainThreshold {
			return &Decision{
				Verdict:  VerdictNXDomain,
				Reason:   "high-entropy random subdomain",
				RuleName: "junk:random_subdomain",
			}
		}
	}

	return allow()
}

// isDGA mirrors engine.IsDGA without depending on that package.
func (jd *JunkDetector) isDGA(label string) bool {
	if len(label) < 6 {
		return false
	}
	return entropy(label) > 4.2
}

// isDataExfil mirrors engine.IsDataExfiltration.
func (jd *JunkDetector) isDataExfil(name string) bool {
	if len(name) < 60 {
		return false
	}
	return entropy(name) > 4.5
}

// entropy calculates Shannon entropy of s using an array-indexed count
// (no heap allocation for ASCII input).
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
