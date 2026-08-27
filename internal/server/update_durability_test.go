package server

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/afterdarksys/dnsscienced/internal/zone"
	"github.com/miekg/dns"
)

func TestPersistentUpdateIsDurableBeforeSuccess(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	path := filepath.Join(t.TempDir(), "example.com.dnszone")
	s.persistPaths = map[string]string{"example.com.": path}

	before := s.GetZone("example.com.").SOA.Serial
	added, err := dns.NewRR("durable.example.com. 300 IN A 192.0.2.80")
	if err != nil {
		t.Fatal(err)
	}
	writer := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(
		writer,
		makeUpdateMsg("example.com.", nil, []dns.RR{added}),
		net.ParseIP("192.0.2.1"),
	)
	if len(writer.msgs) != 1 || writer.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("responses = %+v, want NOERROR", writer.msgs)
	}

	persisted, err := zone.ParseZoneFile(path, zone.DefaultConfig())
	if err != nil {
		t.Fatalf("parse durable replacement: %v", err)
	}
	live := s.GetZone("example.com.")
	if persisted.SOA == nil || live.SOA == nil ||
		persisted.SOA.Serial != live.SOA.Serial ||
		!zone.SerialGreater(live.SOA.Serial, before) ||
		len(persisted.GetRecords("durable.example.com.", dns.TypeA)) != 1 {
		t.Fatalf("persisted serial=%v live serial=%v records=%v",
			persisted.SOA,
			live.SOA,
			persisted.GetRecords("durable.example.com.", dns.TypeA),
		)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("persisted mode = %o, want 600", mode)
	}
}

func TestPersistentUpdateFailureLeavesLiveZoneUntouched(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	path := filepath.Join(t.TempDir(), "missing", "example.com.dnszone")
	s.persistPaths = map[string]string{"example.com.": path}

	before := s.GetZone("example.com.").SOA.Serial
	added, err := dns.NewRR("rejected.example.com. 300 IN A 192.0.2.81")
	if err != nil {
		t.Fatal(err)
	}
	writer := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(
		writer,
		makeUpdateMsg("example.com.", nil, []dns.RR{added}),
		net.ParseIP("192.0.2.1"),
	)
	if len(writer.msgs) != 1 || writer.msgs[0].Rcode != dns.RcodeServerFailure {
		t.Fatalf("responses = %+v, want SERVFAIL", writer.msgs)
	}
	live := s.GetZone("example.com.")
	if live.SOA.Serial != before ||
		len(live.GetRecords("rejected.example.com.", dns.TypeA)) != 0 {
		t.Fatalf("failed persistence mutated live zone: serial=%d records=%v",
			live.SOA.Serial,
			live.GetRecords("rejected.example.com.", dns.TypeA),
		)
	}
	if matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("temporary files survived failure: %v", matches)
	}
}

func TestConcurrentUpdatesDoNotLoseCommittedRecords(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck

	const updates = 64
	before := s.GetZone("example.com.").SOA.Serial
	start := make(chan struct{})
	errs := make(chan error, updates)
	var wg sync.WaitGroup
	for i := 0; i < updates; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr, err := dns.NewRR(fmt.Sprintf(
				"concurrent-%d.example.com. 300 IN A 192.0.2.%d",
				i,
				(i%200)+1,
			))
			if err != nil {
				errs <- err
				return
			}
			<-start
			writer := newAXFRTestWriter("192.0.2.1")
			s.handleUpdate(
				writer,
				makeUpdateMsg("example.com.", nil, []dns.RR{rr}),
				net.ParseIP("192.0.2.1"),
			)
			if len(writer.msgs) != 1 || writer.msgs[0].Rcode != dns.RcodeSuccess {
				errs <- fmt.Errorf("update %d responses = %+v", i, writer.msgs)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}

	live := s.GetZone("example.com.")
	if !zone.SerialGreater(live.SOA.Serial, before) {
		t.Fatalf("serial = %d, want RFC 1982 progression beyond %d", live.SOA.Serial, before)
	}
	for i := 0; i < updates; i++ {
		name := fmt.Sprintf("concurrent-%d.example.com.", i)
		if got := live.GetRecords(name, dns.TypeA); len(got) != 1 {
			t.Fatalf("%s records = %v", name, got)
		}
	}
}

func TestConcurrentTSIGReplayReturnsOriginalResultWithoutReapplying(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck

	expected := s.GetZone("example.com.").Clone()
	if err := expected.IncrementSerial(); err != nil {
		t.Fatal(err)
	}
	added, err := dns.NewRR("replay-safe.example.com. 300 IN A 192.0.2.82")
	if err != nil {
		t.Fatal(err)
	}
	request := makeUpdateMsg("example.com.", nil, []dns.RR{added})
	request.IsTsig().MAC = "9f84f4f86a6a9dcfd8e62cf4a2d7bd6f50d5c91e5c0be0cc59db2d8f58ecf59e"
	request.IsTsig().MACSize = 32

	const duplicates = 32
	start := make(chan struct{})
	results := make(chan int, duplicates)
	var wg sync.WaitGroup
	for i := 0; i < duplicates; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			writer := newAXFRTestWriter("192.0.2.1")
			s.handleUpdate(writer, request.Copy(), net.ParseIP("192.0.2.1"))
			if len(writer.msgs) != 1 {
				results <- -1
				return
			}
			results <- writer.msgs[0].Rcode
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for rcode := range results {
		if rcode != dns.RcodeSuccess {
			t.Fatalf("duplicate response rcode = %d, want NOERROR", rcode)
		}
	}

	live := s.GetZone("example.com.")
	if live.SOA.Serial != expected.SOA.Serial {
		t.Fatalf("serial = %d, want exactly one application (%d)", live.SOA.Serial, expected.SOA.Serial)
	}
	if got := live.GetRecords("replay-safe.example.com.", dns.TypeA); len(got) != 1 {
		t.Fatalf("records = %v, want one replay-safe A record", got)
	}
	if got := s.GetStats().UpdateReplays; got != duplicates-1 {
		t.Fatalf("update replays = %d, want %d", got, duplicates-1)
	}
}

func TestUpdateReplayCacheSaturationFailsClosed(t *testing.T) {
	s, err := testServerWithUpdate([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop() //nolint:errcheck
	s.updateReplay = newUpdateReplayCache(1)

	first := makeUpdateMsg("example.com.", nil, []dns.RR{
		makeAddRR("first.example.com.", "192.0.2.83"),
	})
	first.IsTsig().MAC = "aaaaaaaa"
	first.IsTsig().MACSize = 4
	firstWriter := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(firstWriter, first, net.ParseIP("192.0.2.1"))
	if len(firstWriter.msgs) != 1 || firstWriter.msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("first response = %+v, want NOERROR", firstWriter.msgs)
	}

	second := makeUpdateMsg("example.com.", nil, []dns.RR{
		makeAddRR("blocked.example.com.", "192.0.2.84"),
	})
	second.IsTsig().MAC = "bbbbbbbb"
	second.IsTsig().MACSize = 4
	secondWriter := newAXFRTestWriter("192.0.2.1")
	s.handleUpdate(secondWriter, second, net.ParseIP("192.0.2.1"))
	if len(secondWriter.msgs) != 1 || secondWriter.msgs[0].Rcode != dns.RcodeServerFailure {
		t.Fatalf("saturated response = %+v, want SERVFAIL", secondWriter.msgs)
	}
	if got := s.GetZone("example.com.").GetRecords("blocked.example.com.", dns.TypeA); len(got) != 0 {
		t.Fatalf("saturated cache allowed mutation: %v", got)
	}
	if got := s.GetStats().UpdateReplayFull; got != 1 {
		t.Fatalf("replay cache saturation count = %d, want 1", got)
	}
}
