package secondary

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dnsscience/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

const (
	defaultMaxTransferRecords  = 1_000_000
	defaultMaxTransferBytes    = int64(256 << 20)
	absoluteMaxTransferRecords = 10_000_000
	absoluteMaxTransferBytes   = int64(2 << 30)
)

// AXFRFetcher retrieves a complete zone over TCP.
type AXFRFetcher struct {
	Timeout time.Duration
}

func (f AXFRFetcher) Fetch(ctx context.Context, cfg Config, _ *zone.Zone) (*zone.Zone, error) {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var failures []string
	for _, master := range cfg.Masters {
		z, err := f.fetchMaster(ctx, cfg, master, timeout)
		if err == nil {
			return z, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", master, err))
	}
	return nil, fmt.Errorf("all masters failed: %s", strings.Join(failures, "; "))
}

func (f AXFRFetcher) fetchMaster(ctx context.Context, cfg Config, master string, timeout time.Duration) (*zone.Zone, error) {
	request := new(dns.Msg)
	request.SetAxfr(cfg.Name)
	records, err := transferRecords(ctx, cfg, master, timeout, request)
	if err != nil {
		return nil, err
	}
	return zoneFromAXFR(cfg.Name, records)
}

func transferRecords(ctx context.Context, cfg Config, master string, timeout time.Duration, request *dns.Msg) ([]dns.RR, error) {
	dialer := net.Dialer{Timeout: timeout}
	if cfg.TransferSource != "" {
		ip := net.ParseIP(cfg.TransferSource)
		if ip == nil {
			return nil, fmt.Errorf("invalid transfer_source %q", cfg.TransferSource)
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	conn, err := dialer.DialContext(ctx, "tcp", master)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	transfer := &dns.Transfer{
		Conn:         &dns.Conn{Conn: conn},
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}
	if cfg.TransferKey != nil {
		request.SetTsig(cfg.TransferKey.Name, cfg.TransferKey.Algorithm, 300, time.Now().Unix())
		transfer.TsigSecret = map[string]string{cfg.TransferKey.Name: cfg.TransferKey.Secret}
	}

	envelopes, err := transfer.In(request, master)
	if err != nil {
		return nil, err
	}

	accumulator, err := newTransferAccumulator(cfg)
	if err != nil {
		return nil, err
	}
	for envelope := range envelopes {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		for _, rr := range envelope.RR {
			if err := accumulator.add(rr); err != nil {
				return nil, err
			}
		}
	}
	return accumulator.records, nil
}

type transferAccumulator struct {
	maxRecords int
	maxBytes   int64
	bytes      int64
	records    []dns.RR
}

func newTransferAccumulator(cfg Config) (*transferAccumulator, error) {
	maxRecords := cfg.MaxTransferRecords
	if maxRecords == 0 {
		maxRecords = defaultMaxTransferRecords
	}
	maxBytes := cfg.MaxTransferBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxTransferBytes
	}
	if maxRecords < 1 || maxRecords > absoluteMaxTransferRecords {
		return nil, fmt.Errorf("max_transfer_records must be between 1 and %d", absoluteMaxTransferRecords)
	}
	if maxBytes < 1 || maxBytes > absoluteMaxTransferBytes {
		return nil, fmt.Errorf("max_transfer_bytes must be between 1 and %d", absoluteMaxTransferBytes)
	}
	return &transferAccumulator{maxRecords: maxRecords, maxBytes: maxBytes}, nil
}

func (a *transferAccumulator) add(rr dns.RR) error {
	if rr == nil {
		return fmt.Errorf("transfer contains nil record")
	}
	if len(a.records) >= a.maxRecords {
		return fmt.Errorf("transfer exceeds max_transfer_records %d", a.maxRecords)
	}
	wireBytes := int64(dns.Len(rr))
	if wireBytes > a.maxBytes-a.bytes {
		return fmt.Errorf("transfer exceeds max_transfer_bytes %d", a.maxBytes)
	}
	a.records = append(a.records, dns.Copy(rr))
	a.bytes += wireBytes
	return nil
}

func zoneFromAXFR(name string, records []dns.RR) (*zone.Zone, error) {
	if len(records) < 2 {
		return nil, fmt.Errorf("AXFR returned fewer than two records")
	}
	opening, firstOK := records[0].(*dns.SOA)
	closing, lastOK := records[len(records)-1].(*dns.SOA)
	if !firstOK || !lastOK || opening.Serial != closing.Serial {
		return nil, fmt.Errorf("AXFR is not bounded by matching SOA records")
	}
	result := zone.New(name)
	for i, rr := range records {
		if rr.Header().Class != dns.ClassINET {
			return nil, fmt.Errorf("record %s has non-IN class", rr.Header().Name)
		}
		if i == len(records)-1 {
			continue
		}
		if err := result.AddRecord(dns.Copy(rr)); err != nil {
			return nil, err
		}
	}
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}
