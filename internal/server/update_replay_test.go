package server

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func replayTestTSIG(mac string, signed time.Time, fudge uint16) *dns.TSIG {
	return &dns.TSIG{
		Hdr:        dns.RR_Header{Name: "update-key.example.", Rrtype: dns.TypeTSIG, Class: dns.ClassANY},
		Algorithm:  dns.HmacSHA256,
		TimeSigned: uint64(signed.Unix()),
		Fudge:      fudge,
		MAC:        mac,
	}
}

func TestUpdateReplayCacheCoalescesAndExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newUpdateReplayCache(1)
	request := replayTestTSIG("aaaaaaaa", now, 5)

	entry, duplicate, saturated := cache.beginUpdate(request, now)
	if entry == nil || duplicate || saturated {
		t.Fatalf("first reservation = (%v, %v, %v), want entry/new/not saturated", entry, duplicate, saturated)
	}
	cache.finishUpdate(entry, dns.RcodeSuccess)

	replayed, duplicate, saturated := cache.beginUpdate(request, now.Add(time.Second))
	if replayed != entry || !duplicate || saturated {
		t.Fatalf("replay = (%v, %v, %v), want original/duplicate/not saturated", replayed, duplicate, saturated)
	}
	if got := replayed.wait(); got != dns.RcodeSuccess {
		t.Fatalf("cached rcode = %d, want NOERROR", got)
	}

	replacement, duplicate, saturated := cache.beginUpdate(request, now.Add(6*time.Second))
	if replacement == nil || replacement == entry || duplicate || saturated {
		t.Fatalf("expired reservation = (%v, %v, %v), want replacement/new/not saturated", replacement, duplicate, saturated)
	}
}

func TestUpdateReplayCacheFailsClosedAtCapacity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newUpdateReplayCache(1)
	first, duplicate, saturated := cache.beginUpdate(replayTestTSIG("aaaaaaaa", now, 300), now)
	if first == nil || duplicate || saturated {
		t.Fatal("first reservation failed")
	}

	entry, duplicate, saturated := cache.beginUpdate(replayTestTSIG("bbbbbbbb", now, 300), now)
	if entry != nil || duplicate || !saturated {
		t.Fatalf("full cache = (%v, %v, %v), want nil/new/saturated", entry, duplicate, saturated)
	}
}

func TestDefaultUpdateReplayCacheSize(t *testing.T) {
	if got := DefaultConfig().UpdateReplayCacheSize; got != defaultUpdateReplayCacheSize {
		t.Fatalf("default update replay cache size = %d, want %d", got, defaultUpdateReplayCacheSize)
	}
}
