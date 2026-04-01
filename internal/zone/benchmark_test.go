package zone

import (
	"os"
	"testing"
)

// BenchmarkParseTextZone benchmarks parsing a text zone file
func BenchmarkParseTextZone(b *testing.B) {
	testFile := "testdata/example.com.dnszone"
	cfg := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseDNSZone(testFile, cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadCompiledZone benchmarks loading a compiled zone file
func BenchmarkLoadCompiledZone(b *testing.B) {
	// First compile the zone
	testFile := "testdata/example.com.dnszone"
	compiledFile := "testdata/example.com.dzc"

	cfg := DefaultConfig()
	z, err := ParseDNSZone(testFile, cfg)
	if err != nil {
		b.Fatal(err)
	}

	opts := CompileOptions{
		SourceFile:      testFile,
		OutputFile:      compiledFile,
		SourceFormat:    "dnszone",
		IncludeTextRepr: false,
	}

	compiled, err := CompileZone(z, opts)
	if err != nil {
		b.Fatal(err)
	}

	if err := WriteCompiledZone(compiled, compiledFile); err != nil {
		b.Fatal(err)
	}

	defer os.Remove(compiledFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadCompiledZone(compiledFile)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompileZone benchmarks zone compilation
func BenchmarkCompileZone(b *testing.B) {
	testFile := "testdata/example.com.dnszone"
	cfg := DefaultConfig()

	z, err := ParseDNSZone(testFile, cfg)
	if err != nil {
		b.Fatal(err)
	}

	opts := CompileOptions{
		SourceFile:      testFile,
		SourceFormat:    "dnszone",
		IncludeTextRepr: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CompileZone(z, opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseZoneFile benchmarks the smart parser (auto-detects compiled)
func BenchmarkParseZoneFile(b *testing.B) {
	testFile := "testdata/example.com.dnszone"
	compiledFile := "testdata/example.com.dzc"
	cfg := DefaultConfig()

	// Pre-compile the zone
	z, err := ParseDNSZone(testFile, cfg)
	if err != nil {
		b.Fatal(err)
	}

	_, err = CompileAndWrite(z, CompileOptions{
		SourceFile:   testFile,
		OutputFile:   compiledFile,
		SourceFormat: "dnszone",
	})
	if err != nil {
		b.Fatal(err)
	}

	defer os.Remove(compiledFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseZoneFile(testFile, cfg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
