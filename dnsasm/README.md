# DNSASM packet-processing research library

DNSASM is a portable C reference parser with optional architecture-specific
header routines and Go/cgo bindings. It is retained for differential testing,
fuzzing, and performance research. It is not a DNS network server and is not
used by dnsscienced's production request path.

## Measured production decision

The 12-byte production header check uses bounds-checked scalar Go with
caller-owned output. On the documented Linux/amd64 benchmark, it took roughly
4.6–4.8 ns per header with zero allocations. Crossing cgo for one x86 assembly
header parse took roughly 102–112 ns and allocated once, so selecting assembly
there would reduce throughput.

The optional x86-64 routine reads exactly the 12-byte DNS header and requires
only baseline SSE2. AVX2/AVX-512 are deliberately not assumed. The portable C
implementation remains the audited reference and supplies question/RR parsing
in normal builds. See [Performance tuning](../docs/PERFORMANCE_TUNING.md) for
the benchmark method and current results.

## Layout

```text
dnsasm/
├── Makefile
├── console/main.c
├── go/
│   ├── dnsasm.go
│   └── dnsasm_test.go
├── include/dnsasm.h
└── src/
    ├── dnsasm.c
    ├── arm64/{header.s,question.s}
    └── x86_64/{header.asm,question.asm}
```

`USE_ASM=1` currently selects the architecture-specific header routine. The
more complex name/question/RR logic stays on the C reference path until an
assembly alternative has equivalent differential and fuzz coverage.

## Build and test

```sh
# Portable C reference library and console
make
make test

# Optional native header routine
make clean
make USE_ASM=1
make test

# Go differential tests and benchmarks
go test ./go
go test ./go -run '^$' -bench . -benchmem
```

Build on the target operating system and architecture. The repository's
multi-stage Dockerfile builds the Linux/amd64 NASM variant before statically
linking dnsscienced.

## Go API

```go
import dnsasm "github.com/dnsscience/dnsscienced/dnsasm/go"

var header dnsasm.Header
if err := dnsasm.ParseHeaderInto(packet, &header); err != nil {
    return err
}

question, nextOffset, err := dnsasm.ParseQuestion(packet, 12)
```

The public APIs validate packet bounds. “Zero allocation” applies only to the
measured caller-owned header and fixed-stride batch APIs; question parsing
returns Go strings and is not described as zero-copy.

## Security boundary

DNSASM does not implement TSIG, DNS Cookies, ACLs, RRL, RPZ, DNSSEC validation,
authoritative lookup, recursive resolution, EDNS policy, TCP fallback, or
observability. Packets accepted by production dnsscienced always continue
through the audited `miekg/dns` parser and the complete server policy pipeline.

## License

Apache 2.0.
