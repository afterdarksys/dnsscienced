package zone

import (
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Delta is one serial-to-serial zone change suitable for RFC 1995 IXFR.
type Delta struct {
	FromSOA *dns.SOA
	ToSOA   *dns.SOA
	Deleted []dns.RR
	Added   []dns.RR
}

// Journal retains a bounded number of recent deltas per zone.
type Journal struct {
	mu        sync.RWMutex
	maxDeltas int
	zones     map[string][]Delta
}

func NewJournal(maxDeltas int) *Journal {
	if maxDeltas <= 0 {
		maxDeltas = 100
	}
	return &Journal{
		maxDeltas: maxDeltas,
		zones:     make(map[string][]Delta),
	}
}

// Record computes and stores one delta. Non-successor or invalid versions
// reset history because they cannot form a safe contiguous IXFR chain.
func (j *Journal) Record(previous, next *Zone) {
	if previous == nil || next == nil {
		return
	}
	if previous.SOA == nil || next.SOA == nil ||
		!strings.EqualFold(previous.Origin, next.Origin) ||
		!SerialGreater(next.SOA.Serial, previous.SOA.Serial) {
		j.Reset(next.Origin)
		return
	}
	delta := Diff(previous, next)
	name := strings.ToLower(dns.Fqdn(next.Origin))

	j.mu.Lock()
	history := j.zones[name]
	if len(history) > 0 && history[len(history)-1].ToSOA.Serial != delta.FromSOA.Serial {
		history = nil
	}
	history = append(history, delta)
	if len(history) > j.maxDeltas {
		history = append([]Delta(nil), history[len(history)-j.maxDeltas:]...)
	}
	j.zones[name] = history
	j.mu.Unlock()
}

// Changes returns a contiguous oldest-to-newest chain.
func (j *Journal) Changes(name string, fromSerial, toSerial uint32) ([]Delta, bool) {
	name = strings.ToLower(dns.Fqdn(name))
	j.mu.RLock()
	history := j.zones[name]
	start := -1
	for i := range history {
		if history[i].FromSOA.Serial == fromSerial {
			start = i
			break
		}
	}
	if start < 0 {
		j.mu.RUnlock()
		return nil, false
	}
	var result []Delta
	expected := fromSerial
	for _, delta := range history[start:] {
		if delta.FromSOA.Serial != expected {
			j.mu.RUnlock()
			return nil, false
		}
		result = append(result, copyDelta(delta))
		expected = delta.ToSOA.Serial
		if expected == toSerial {
			j.mu.RUnlock()
			return result, true
		}
	}
	j.mu.RUnlock()
	return nil, false
}

func (j *Journal) Reset(name string) {
	j.mu.Lock()
	delete(j.zones, strings.ToLower(dns.Fqdn(name)))
	j.mu.Unlock()
}

func Diff(previous, next *Zone) Delta {
	oldRecords := recordSet(previous)
	newRecords := recordSet(next)
	delta := Delta{
		FromSOA: dns.Copy(previous.SOA).(*dns.SOA),
		ToSOA:   dns.Copy(next.SOA).(*dns.SOA),
	}
	oldKeys := make([]string, 0, len(oldRecords))
	for key := range oldRecords {
		oldKeys = append(oldKeys, key)
	}
	sort.Strings(oldKeys)
	for _, key := range oldKeys {
		if _, ok := newRecords[key]; !ok {
			delta.Deleted = append(delta.Deleted, dns.Copy(oldRecords[key]))
		}
	}
	newKeys := make([]string, 0, len(newRecords))
	for key := range newRecords {
		newKeys = append(newKeys, key)
	}
	sort.Strings(newKeys)
	for _, key := range newKeys {
		if _, ok := oldRecords[key]; !ok {
			delta.Added = append(delta.Added, dns.Copy(newRecords[key]))
		}
	}
	return delta
}

func recordSet(z *Zone) map[string]dns.RR {
	result := make(map[string]dns.RR)
	for _, rr := range z.GetAllRecords() {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		copyRR := dns.Copy(rr)
		copyRR.Header().Name = strings.ToLower(dns.Fqdn(copyRR.Header().Name))
		result[copyRR.String()] = copyRR
	}
	return result
}

func copyDelta(delta Delta) Delta {
	result := Delta{
		FromSOA: dns.Copy(delta.FromSOA).(*dns.SOA),
		ToSOA:   dns.Copy(delta.ToSOA).(*dns.SOA),
		Deleted: make([]dns.RR, len(delta.Deleted)),
		Added:   make([]dns.RR, len(delta.Added)),
	}
	for i, rr := range delta.Deleted {
		result.Deleted[i] = dns.Copy(rr)
	}
	for i, rr := range delta.Added {
		result.Added[i] = dns.Copy(rr)
	}
	return result
}

// SerialGreater implements RFC 1982's half-range serial comparison.
func SerialGreater(next, current uint32) bool {
	return next != current && uint32(next-current) < 1<<31
}
