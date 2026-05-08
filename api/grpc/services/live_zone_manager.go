package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/dnsscience/dnsscienced/api/grpc/ports"
	"github.com/dnsscience/dnsscienced/internal/zone"
)

// LiveZoneManager implements ports.ZoneManager backed by a live SrvAdapter.
// It replaces the demo engine.ZoneManager for production use so that
// ZoneService.UpdateRecords actually writes to the running DNS server.
type LiveZoneManager struct {
	srv        SrvAdapter
	zonesDir   string
	compileBin string
}

// NewLiveZoneManager constructs a LiveZoneManager.
func NewLiveZoneManager(srv SrvAdapter, zonesDir, compileBin string) *LiveZoneManager {
	return &LiveZoneManager{srv: srv, zonesDir: zonesDir, compileBin: compileBin}
}

// UpdateRecords applies add/delete/replace operations to a zone, persists to
// disk via compile, and hot-reloads the zone into the running server.
func (m *LiveZoneManager) UpdateRecords(ctx context.Context, zoneName string, updates []ports.RecordUpdate, incrementSerial bool) (*ports.UpdateOutcome, error) {
	origin := dns.Fqdn(strings.TrimSuffix(zoneName, "."))
	z := m.srv.GetZone(origin)
	if z == nil {
		return &ports.UpdateOutcome{Zone: zoneName, Failed: int32(len(updates))},
			fmt.Errorf("zone not found: %s", zoneName)
	}

	applied := int32(0)
	var results []ports.UpdateResult

	for _, u := range updates {
		var err error
		switch u.Operation {
		case "UPDATE_OPERATION_ADD":
			err = m.applyAdd(z, u, origin)
		case "UPDATE_OPERATION_DELETE":
			m.applyDelete(z, u, origin)
		case "UPDATE_OPERATION_REPLACE":
			m.applyDelete(z, ports.RecordUpdate{Name: u.Name, Type: u.Type, Data: u.OldData}, origin)
			err = m.applyAdd(z, u, origin)
		default:
			err = fmt.Errorf("unknown operation: %s", u.Operation)
		}

		res := ports.UpdateResult{Update: u, Success: err == nil}
		if err != nil {
			res.Error = err.Error()
		} else {
			applied++
		}
		results = append(results, res)
	}

	failed := int32(len(updates)) - applied

	if applied > 0 {
		if err := m.persistAndReload(ctx, z, origin); err != nil {
			// Return what we applied in-memory; flag persistence failure.
			return &ports.UpdateOutcome{
				Zone:    zoneName,
				Applied: applied,
				Failed:  failed,
				Results: results,
			}, fmt.Errorf("applied in-memory but failed to persist: %w", err)
		}
	}

	return &ports.UpdateOutcome{
		Zone:    zoneName,
		Applied: applied,
		Failed:  failed,
		Results: results,
	}, nil
}

func (m *LiveZoneManager) applyAdd(z *zone.Zone, u ports.RecordUpdate, origin string) error {
	rr, err := buildLiveRR(u, origin)
	if err != nil {
		return err
	}
	return z.AddRecord(rr)
}

func (m *LiveZoneManager) applyDelete(z *zone.Zone, u ports.RecordUpdate, origin string) {
	ownerName := resolveOwner(u.Name, origin)
	rrtype, ok := dns.StringToType[strings.ToUpper(u.Type)]
	if !ok {
		return
	}
	typeMap, ok := z.Records[ownerName]
	if !ok {
		return
	}
	if u.Data == "" {
		// Delete all records of this type at this owner.
		delete(typeMap, rrtype)
	} else {
		rrs := typeMap[rrtype]
		filtered := rrs[:0]
		for _, rr := range rrs {
			if rrContent(rr) != u.Data {
				filtered = append(filtered, rr)
			}
		}
		if len(filtered) == 0 {
			delete(typeMap, rrtype)
		} else {
			typeMap[rrtype] = filtered
		}
	}
	if len(typeMap) == 0 {
		delete(z.Records, ownerName)
	}
}

func (m *LiveZoneManager) persistAndReload(ctx context.Context, z *zone.Zone, origin string) error {
	if m.zonesDir == "" || m.compileBin == "" {
		// No persistence configured — in-memory only.
		return nil
	}

	domain := strings.TrimSuffix(origin, ".")
	dnszonePath := filepath.Join(m.zonesDir, domain+".dnszone")
	dzcPath := filepath.Join(m.zonesDir, domain+".dzc")

	data, err := zone.SerializeDNSZone(z)
	if err != nil {
		return fmt.Errorf("serialize zone: %w", err)
	}
	if err := os.WriteFile(dnszonePath, data, 0644); err != nil {
		return fmt.Errorf("write zone file: %w", err)
	}

	ms := &ManagementService{zonesDir: m.zonesDir, compileBin: m.compileBin, startTime: time.Now()}
	if err := ms.compileZone(ctx, dnszonePath, dzcPath); err != nil {
		return fmt.Errorf("compile zone: %w", err)
	}

	updated, err := zone.LoadCompiledZone(dzcPath)
	if err != nil {
		return fmt.Errorf("load compiled zone: %w", err)
	}
	return m.srv.AddZone(updated)
}

// buildLiveRR constructs a dns.RR from a RecordUpdate.
func buildLiveRR(u ports.RecordUpdate, origin string) (dns.RR, error) {
	ownerName := resolveOwner(u.Name, origin)
	rrtype, ok := dns.StringToType[strings.ToUpper(u.Type)]
	if !ok {
		return nil, fmt.Errorf("unknown record type: %s", u.Type)
	}
	ttl := u.TTL
	if ttl == 0 {
		ttl = 300
	}
	hdr := dns.RR_Header{Name: ownerName, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}
	switch rrtype {
	case dns.TypeTXT:
		return &dns.TXT{Hdr: hdr, Txt: []string{u.Data}}, nil
	case dns.TypeA:
		ip := dns.TypeToString[dns.TypeA]
		_ = ip
		parsed := strings.TrimSpace(u.Data)
		rr := &dns.A{Hdr: hdr}
		if p := strings.Split(parsed, "."); len(p) == 4 {
			rr.A = []byte{parseByte(p[0]), parseByte(p[1]), parseByte(p[2]), parseByte(p[3])}
		}
		return rr, nil
	default:
		rrStr := fmt.Sprintf("%s %d IN %s %s", ownerName, ttl, u.Type, u.Data)
		return dns.NewRR(rrStr)
	}
}

func resolveOwner(name, origin string) string {
	if name == "" || name == "@" {
		return strings.ToLower(origin)
	}
	if name[len(name)-1] == '.' {
		return strings.ToLower(name)
	}
	return strings.ToLower(name) + "." + origin
}

func parseByte(s string) byte {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return byte(n)
}

// ListZones lists zones from zonesDir .dzc files.
func (m *LiveZoneManager) ListZones(_ context.Context, _ string, _ string) ([]ports.ZoneInfo, error) {
	if m.zonesDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(m.zonesDir)
	if err != nil {
		return nil, err
	}
	var out []ports.ZoneInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".dzc") {
			continue
		}
		domain := strings.TrimSuffix(e.Name(), ".dzc")
		origin := dns.Fqdn(domain)
		z := m.srv.GetZone(origin)
		if z == nil {
			continue
		}
		info := ports.ZoneInfo{Name: origin, Type: "primary", Status: "active"}
		if z.SOA != nil {
			info.SOA = ports.SOA{
				Primary: z.SOA.Ns,
				Admin:   z.SOA.Mbox,
				Serial:  z.SOA.Serial,
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// GetZone retrieves a single zone.
func (m *LiveZoneManager) GetZone(_ context.Context, name string, includeRecords bool, recordType string) (*ports.ZoneInfo, []ports.ResourceRecord, error) {
	origin := dns.Fqdn(strings.TrimSuffix(name, "."))
	z := m.srv.GetZone(origin)
	if z == nil {
		return nil, nil, fmt.Errorf("zone not found: %s", name)
	}
	info := &ports.ZoneInfo{Name: origin, Type: "primary", Status: "active"}
	if z.SOA != nil {
		info.SOA = ports.SOA{Primary: z.SOA.Ns, Admin: z.SOA.Mbox, Serial: z.SOA.Serial}
	}
	var recs []ports.ResourceRecord
	if includeRecords {
		filterType := strings.ToUpper(recordType)
		for owner, typeMap := range z.Records {
			for rrtype, rrs := range typeMap {
				typeName := dns.TypeToString[rrtype]
				if filterType != "" && typeName != filterType {
					continue
				}
				for _, rr := range rrs {
					recs = append(recs, ports.ResourceRecord{
						Name: owner, Type: typeName, Class: "IN",
						TTL: rr.Header().Ttl, Data: rrContent(rr),
					})
				}
			}
		}
	}
	return info, recs, nil
}

// GetRecords returns records for a zone, optionally filtered.
func (m *LiveZoneManager) GetRecords(_ context.Context, zoneName, host, rtype string) ([]ports.ResourceRecord, error) {
	origin := dns.Fqdn(strings.TrimSuffix(zoneName, "."))
	z := m.srv.GetZone(origin)
	if z == nil {
		return nil, fmt.Errorf("zone not found: %s", zoneName)
	}
	filterType := strings.ToUpper(rtype)
	var out []ports.ResourceRecord
	for owner, typeMap := range z.Records {
		if host != "" && owner != resolveOwner(host, origin) {
			continue
		}
		for rrtype, rrs := range typeMap {
			typeName := dns.TypeToString[rrtype]
			if filterType != "" && typeName != filterType {
				continue
			}
			for _, rr := range rrs {
				out = append(out, ports.ResourceRecord{
					Name: owner, Type: typeName, Class: "IN",
					TTL: rr.Header().Ttl, Data: rrContent(rr),
				})
			}
		}
	}
	return out, nil
}

// ReloadZone reloads a zone from its .dzc file.
func (m *LiveZoneManager) ReloadZone(_ context.Context, name string, _ bool) (*ports.ReloadOutcome, error) {
	if m.zonesDir == "" {
		return &ports.ReloadOutcome{Zone: name, Success: false, Message: "zonesDir not configured"}, nil
	}
	domain := strings.TrimSuffix(dns.Fqdn(strings.TrimSuffix(name, ".")), ".")
	dzcPath := filepath.Join(m.zonesDir, domain+".dzc")
	z, err := zone.LoadCompiledZone(dzcPath)
	if err != nil {
		return &ports.ReloadOutcome{Zone: name, Success: false, Message: err.Error()}, nil
	}
	if err := m.srv.AddZone(z); err != nil {
		return &ports.ReloadOutcome{Zone: name, Success: false, Message: err.Error()}, nil
	}
	return &ports.ReloadOutcome{Zone: name, Success: true, Message: "reloaded"}, nil
}

// Notify and Transfer are not implemented for the live manager.
func (m *LiveZoneManager) Notify(_ context.Context, name string, _ []string) (*ports.NotifyOutcome, error) {
	return &ports.NotifyOutcome{Zone: name}, nil
}
func (m *LiveZoneManager) Transfer(_ context.Context, name, _, _ string) (*ports.TransferOutcome, error) {
	return &ports.TransferOutcome{Zone: name, Success: false, Error: "not implemented"}, nil
}
