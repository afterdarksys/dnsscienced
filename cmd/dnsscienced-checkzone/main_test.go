package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunValidDNSZone(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-v", filepath.Join("..", "..", "internal", "zone", "testdata", "example.com.dnszone")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "zone name: example.com.") {
		t.Fatalf("stdout missing zone name: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "record sets:") {
		t.Fatalf("stdout missing verbose stats: %s", stdout.String())
	}
}

func TestRunRejectsUnknownRecordKey(t *testing.T) {
	path := writeTempZone(t, strings.Replace(validZoneYAML, "A: 192.0.2.53", "AA: 192.0.2.53", 1))

	var stdout, stderr bytes.Buffer
	code := run([]string{path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown record key "AA"`) {
		t.Fatalf("stderr missing unknown key error: %s", stderr.String())
	}
}

func TestRunRejectsSemanticZoneError(t *testing.T) {
	path := writeTempZone(t, strings.Replace(validZoneYAML, "- ns1.example.test", "- ns2.example.test", 1))

	var stdout, stderr bytes.Buffer
	code := run([]string{path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing glue records") {
		t.Fatalf("stderr missing validation error: %s", stderr.String())
	}
}

func TestRunQuietValidZone(t *testing.T) {
	path := writeTempZone(t, validZoneYAML)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-q", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit = %d, stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("quiet stdout = %q, want empty", stdout.String())
	}
}

func TestRunReportsMissingZoneName(t *testing.T) {
	path := writeTempZone(t, `records: {}`)

	var stdout, stderr bytes.Buffer
	code := run([]string{path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing zone section") {
		t.Fatalf("stderr missing zone section error: %s", stderr.String())
	}
}

func writeTempZone(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.test.dnszone")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const validZoneYAML = `zone:
  name: example.test
  ttl: 1h
  class: IN

soa:
  primary_ns: ns1.example.test
  contact: admin@example.test
  serial: 2026081500
  refresh: 2h
  retry: 1h
  expire: 2w
  negative_ttl: 1h

records:
  "@":
    NS:
      - ns1.example.test
    A: 192.0.2.10
  ns1:
    A: 192.0.2.53
`
