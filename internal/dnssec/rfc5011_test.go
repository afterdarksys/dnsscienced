package dnssec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type observingRFC5011Resolver struct {
	message *dns.Msg
	called  chan struct{}
}

func (r observingRFC5011Resolver) Query(_ context.Context, _ string, _ uint16) (*dns.Msg, error) {
	select {
	case r.called <- struct{}{}:
	default:
	}
	return r.message.Copy(), nil
}

func newRFC5011TestValidator(t *testing.T, anchor dns.DNSKEY) *Validator {
	t.Helper()
	dir := t.TempDir()
	anchorPath := filepath.Join(dir, "root.key")
	if err := os.WriteFile(anchorPath, []byte(anchor.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultValidatorConfig()
	cfg.TrustAnchorFile = anchorPath
	cfg.AutoTrustAnchor = true
	cfg.TrustAnchorStateFile = filepath.Join(dir, "managed-keys.json")
	validator, err := NewValidator(cfg, stubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func TestRFC5011RequiresDurableStatePath(t *testing.T) {
	key, _ := generatedDNSKEY(t, ".")
	dir := t.TempDir()
	anchorPath := filepath.Join(dir, "root.key")
	if err := os.WriteFile(anchorPath, []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultValidatorConfig()
	cfg.TrustAnchorFile = anchorPath
	cfg.AutoTrustAnchor = true
	if _, err := NewValidator(cfg, stubResolver{}); err == nil {
		t.Fatal("automatic trust-anchor maintenance accepted no durable state path")
	}
}

func TestRFC5011RejectsBroadStateFilePermissions(t *testing.T) {
	key, _ := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, key)
	if err := os.Chmod(validator.rfc5011.path, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := validator.config
	if _, err := NewValidator(cfg, stubResolver{}); err == nil {
		t.Fatal("RFC 5011 accepted a state file readable by other users")
	}
}

func TestRFC5011AddHoldDownPersistsAcrossRestart(t *testing.T) {
	current, currentPrivate := generatedDNSKEY(t, ".")
	candidate, _ := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, current)
	manager := validator.rfc5011

	rrset := []dns.RR{&current, &candidate}
	signatures := []dns.RRSIG{*signedRRSet(t, rrset, ".", current, currentPrivate)}
	if err := manager.process([]dns.DNSKEY{current, candidate}, signatures); err != nil {
		t.Fatal(err)
	}
	candidateID := rfc5011KeyID(&candidate)
	if got := manager.keys[candidateID]; got == nil || got.State != rfc5011AddPending {
		t.Fatalf("candidate state = %+v, want add-pending", got)
	}
	if len(validator.anchorSnapshot()) != 1 {
		t.Fatal("pending key became a trust anchor before its hold-down elapsed")
	}

	manager.keys[candidateID].FirstSeen = time.Now().Add(-rfc5011AddHoldDown)
	if err := manager.process([]dns.DNSKEY{current, candidate}, signatures); err != nil {
		t.Fatal(err)
	}
	if manager.keys[candidateID].State != rfc5011Valid || len(validator.anchorSnapshot()) != 2 {
		t.Fatal("continuously observed key was not accepted after a fresh post-hold-down RRset")
	}

	cfg := DefaultValidatorConfig()
	cfg.TrustAnchorFile = filepath.Join(filepath.Dir(manager.path), "root.key")
	cfg.AutoTrustAnchor = true
	cfg.TrustAnchorStateFile = manager.path
	restarted, err := NewValidator(cfg, stubResolver{})
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.anchorSnapshot()) != 2 {
		t.Fatal("accepted RFC 5011 anchors did not survive restart")
	}
}

func TestRFC5011PendingKeyDisappearanceResetsAcceptance(t *testing.T) {
	current, currentPrivate := generatedDNSKEY(t, ".")
	candidate, _ := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, current)
	manager := validator.rfc5011

	withCandidate := []dns.RR{&current, &candidate}
	if err := manager.process(
		[]dns.DNSKEY{current, candidate},
		[]dns.RRSIG{*signedRRSet(t, withCandidate, ".", current, currentPrivate)},
	); err != nil {
		t.Fatal(err)
	}
	withoutCandidate := []dns.RR{&current}
	if err := manager.process(
		[]dns.DNSKEY{current},
		[]dns.RRSIG{*signedRRSet(t, withoutCandidate, ".", current, currentPrivate)},
	); err != nil {
		t.Fatal(err)
	}
	if manager.keys[rfc5011KeyID(&candidate)] != nil {
		t.Fatal("candidate absent from a validated RRset retained its acceptance timer")
	}
}

func TestRFC5011AuthenticatedRevocationIsImmediateAndDurable(t *testing.T) {
	current, currentPrivate := generatedDNSKEY(t, ".")
	standby, standbyPrivate := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, current)
	manager := validator.rfc5011

	// Install the standby through the normal add hold-down transition.
	initial := []dns.RR{&current, &standby}
	initialSignatures := []dns.RRSIG{*signedRRSet(t, initial, ".", current, currentPrivate)}
	if err := manager.process([]dns.DNSKEY{current, standby}, initialSignatures); err != nil {
		t.Fatal(err)
	}
	standbyID := rfc5011KeyID(&standby)
	manager.keys[standbyID].FirstSeen = time.Now().Add(-rfc5011AddHoldDown)
	if err := manager.process([]dns.DNSKEY{current, standby}, initialSignatures); err != nil {
		t.Fatal(err)
	}

	revoked := current
	revoked.Flags |= dnskeyRevokeFlag
	revocationSet := []dns.RR{&revoked, &standby}
	revocationSignatures := []dns.RRSIG{
		*signedRRSet(t, revocationSet, ".", revoked, currentPrivate),
		*signedRRSet(t, revocationSet, ".", standby, standbyPrivate),
	}
	if err := manager.process([]dns.DNSKEY{revoked, standby}, revocationSignatures); err != nil {
		t.Fatal(err)
	}
	currentID := rfc5011KeyID(&current)
	if manager.keys[currentID].State != rfc5011Revoked {
		t.Fatalf("revoked key state = %s", manager.keys[currentID].State)
	}
	anchors := validator.anchorSnapshot()
	if len(anchors) != 1 || rfc5011KeyID(&anchors[0]) != standbyID {
		t.Fatalf("active anchors after revocation = %+v", anchors)
	}

	manager.keys[currentID].StateSince = time.Now().Add(-rfc5011RemoveHoldDown)
	standbySet := []dns.RR{&standby}
	if err := manager.process(
		[]dns.DNSKEY{standby},
		[]dns.RRSIG{*signedRRSet(t, standbySet, ".", standby, standbyPrivate)},
	); err != nil {
		t.Fatal(err)
	}
	if manager.keys[currentID].State != rfc5011Removed {
		t.Fatal("revoked key was not tombstoned after the remove hold-down")
	}
}

func TestRFC5011RejectsUnauthenticatedAnchorInjection(t *testing.T) {
	current, _ := generatedDNSKEY(t, ".")
	attacker, attackerPrivate := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, current)
	rrset := []dns.RR{&attacker}
	err := validator.rfc5011.process(
		[]dns.DNSKEY{attacker},
		[]dns.RRSIG{*signedRRSet(t, rrset, ".", attacker, attackerPrivate)},
	)
	if err == nil {
		t.Fatal("untrusted key authenticated its own injection")
	}
	if len(validator.anchorSnapshot()) != 1 {
		t.Fatal("failed injection changed the active trust anchors")
	}
}

func TestRFC5011RefreshLoopUsesDNSKEYResolver(t *testing.T) {
	current, currentPrivate := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, current)
	rrset := []dns.RR{&current}
	resolver := mapResolver{
		".:DNSKEY": {Answer: append(rrset, signedRRSet(t, rrset, ".", current, currentPrivate))},
	}
	delay, err := validator.rfc5011.refresh(context.Background(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if delay < rfc5011MinRefresh || delay > rfc5011MaxRefresh {
		t.Fatalf("refresh delay = %v", delay)
	}
}

func TestRFC5011StartActivelyRefreshes(t *testing.T) {
	current, currentPrivate := generatedDNSKEY(t, ".")
	candidate, _ := generatedDNSKEY(t, ".")
	validator := newRFC5011TestValidator(t, current)
	rrset := []dns.RR{&current, &candidate}
	resolver := observingRFC5011Resolver{
		message: &dns.Msg{Answer: append(rrset, signedRRSet(t, rrset, ".", current, currentPrivate))},
		called:  make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	validator.rfc5011.start(ctx, resolver, 0)
	validator.rfc5011.start(ctx, resolver, 0) // sync.Once prevents duplicate loops.
	select {
	case <-resolver.called:
	case <-time.After(time.Second):
		t.Fatal("RFC 5011 active refresh did not query the trust point")
	}
	deadline := time.Now().Add(time.Second)
	for {
		validator.rfc5011.mu.Lock()
		state := validator.rfc5011.keys[rfc5011KeyID(&candidate)]
		validator.rfc5011.mu.Unlock()
		if state != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("RFC 5011 active refresh did not process the DNSKEY RRset")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
}
