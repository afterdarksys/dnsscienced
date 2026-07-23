package secondary

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

// TransferFetcher requests IXFR when an exact prior zone is available and
// otherwise uses AXFR.
type TransferFetcher struct {
	Timeout time.Duration
}

func (f TransferFetcher) Fetch(ctx context.Context, cfg Config, current *zone.Zone) (*zone.Zone, error) {
	if current == nil || current.SOA == nil {
		return (AXFRFetcher{Timeout: f.Timeout}).Fetch(ctx, cfg, nil)
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	request := new(dns.Msg)
	request.SetIxfr(cfg.Name, current.SOA.Serial, current.SOA.Ns, current.SOA.Mbox)
	var failures []string
	for _, master := range cfg.Masters {
		records, err := transferRecords(ctx, cfg, master, timeout, request.Copy())
		if err == nil {
			replacement, incremental, parseErr := applyTransfer(current, cfg.Name, records)
			if parseErr == nil && (incremental || cfg.AllowAXFRFallback) {
				return replacement, nil
			}
			if parseErr == nil {
				parseErr = fmt.Errorf("master returned AXFR while allow_axfr_fallback is false")
			}
			err = parseErr
		}
		failures = append(failures, fmt.Sprintf("%s: %v", master, err))
	}
	return nil, fmt.Errorf("all masters failed: %s", strings.Join(failures, "; "))
}

// applyTransfer distinguishes a full AXFR fallback from an IXFR sequence.
func applyTransfer(current *zone.Zone, name string, records []dns.RR) (*zone.Zone, bool, error) {
	if len(records) == 0 {
		return nil, false, fmt.Errorf("empty transfer")
	}
	target, ok := records[0].(*dns.SOA)
	if !ok {
		return nil, false, fmt.Errorf("transfer does not start with SOA")
	}
	if len(records) == 1 {
		if target.Serial != current.SOA.Serial {
			return nil, true, fmt.Errorf("single-SOA IXFR changed serial from %d to %d", current.SOA.Serial, target.Serial)
		}
		return current.Clone(), true, nil
	}
	if _, incremental := records[1].(*dns.SOA); !incremental {
		full, err := zoneFromAXFR(name, records)
		return full, false, err
	}

	finalSOA, ok := records[len(records)-1].(*dns.SOA)
	if !ok || finalSOA.Serial != target.Serial {
		return nil, true, fmt.Errorf("IXFR is not bounded by current SOA serial %d", target.Serial)
	}

	work := current.Clone()
	index := 1
	for index < len(records)-1 {
		oldSOA, ok := records[index].(*dns.SOA)
		if !ok || work.SOA == nil || oldSOA.Serial != work.SOA.Serial {
			return nil, true, fmt.Errorf("IXFR delta starts at unexpected serial")
		}
		index++

		var deleted []dns.RR
		for index < len(records)-1 {
			if _, ok := records[index].(*dns.SOA); ok {
				break
			}
			deleted = append(deleted, records[index])
			index++
		}
		if index >= len(records)-1 {
			return nil, true, fmt.Errorf("IXFR delta missing new SOA")
		}
		newSOA := records[index].(*dns.SOA)
		if !zone.SerialGreater(newSOA.Serial, oldSOA.Serial) {
			return nil, true, fmt.Errorf("IXFR serial %d does not advance %d", newSOA.Serial, oldSOA.Serial)
		}
		index++

		var added []dns.RR
		for index < len(records)-1 {
			if _, ok := records[index].(*dns.SOA); ok {
				break
			}
			added = append(added, records[index])
			index++
		}
		for _, rr := range deleted {
			if !zoneHasRR(work, rr) {
				return nil, true, fmt.Errorf("IXFR deletes absent record %s", rr)
			}
			if err := work.DeleteRecord(rr); err != nil {
				return nil, true, err
			}
		}
		if err := work.DeleteRRSet(work.Origin, dns.TypeSOA); err != nil {
			return nil, true, err
		}
		work.SOA = nil
		if err := work.AddRecord(dns.Copy(newSOA)); err != nil {
			return nil, true, err
		}
		for _, rr := range added {
			if zoneHasRR(work, rr) {
				return nil, true, fmt.Errorf("IXFR adds existing record %s", rr)
			}
			if err := work.AddRecord(dns.Copy(rr)); err != nil {
				return nil, true, err
			}
		}
	}
	if index != len(records)-1 || work.SOA == nil {
		return nil, true, fmt.Errorf("IXFR ended without a complete final delta")
	}
	if work.SOA.Serial != target.Serial {
		return nil, true, fmt.Errorf("IXFR ended at serial %d, want %d", work.SOA.Serial, target.Serial)
	}
	if err := work.Validate(); err != nil {
		return nil, true, err
	}
	return work, true, nil
}

func zoneHasRR(z *zone.Zone, candidate dns.RR) bool {
	want := normalizedRR(candidate)
	for _, rr := range z.ExactRecords(candidate.Header().Name, candidate.Header().Rrtype) {
		if normalizedRR(rr) == want {
			return true
		}
	}
	return false
}

func normalizedRR(rr dns.RR) string {
	copyRR := dns.Copy(rr)
	copyRR.Header().Name = strings.ToLower(dns.Fqdn(copyRR.Header().Name))
	copyRR.Header().Class = dns.ClassINET
	copyRR.Header().Ttl = 0
	return copyRR.String()
}
