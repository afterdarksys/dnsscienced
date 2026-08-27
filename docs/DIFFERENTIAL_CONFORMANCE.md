# BIND and NSD Differential Conformance

The authoritative differential suite runs the same zone and query corpus against
DNSScienced, BIND, and NSD on Linux. It compares protocol semantics after
normalizing DNS message IDs, compression, RR order, owner-name case, and TTLs.
It does not hide meaningful differences in response codes, AA/TC flags, answer
RRsets, negative SOA proofs, referrals, or glue.

The reference versions are deliberately pinned. They are suite fixtures, not a
claim that each is the latest upstream release at the time this document is
read:

- BIND 9.20.24, selected from ISC's
  [security matrix](https://kb.isc.org/docs/aa-00913), built from ISC's signed
  release archive and checked against the SHA-256 recorded in its Dockerfile.
- NSD 4.15.0, selected from NLnet Labs'
  [download page](https://www.nlnetlabs.nl/projects/nsd/download/), built from
  the official archive and its published SHA-256.

Run the suite from the repository root:

```sh
tests/differential/run.sh
```

Docker Compose builds all three authoritative servers and a small isolated Go
runner, waits for each server to answer, then exercises:

- SOA, NS, A, AAAA, CNAME, MX, TXT, CAA, and wildcard answers;
- NODATA and NXDOMAIN negative answers with authoritative SOA data;
- delegation referrals and in-bailiwick glue;
- UDP, TCP, and EDNS(0).

This suite intentionally excludes recursive behavior, DNSSEC signing policy,
ANY-response policy, DNS UPDATE, NOTIFY, and zone transfer. Those require
separate profiles or stateful security tests; treating their policy differences
as wire incompatibilities would produce misleading results.

## Verification record

The suite passed all 14 cases on 2026-08-08 from commit `bedf179` after building
DNSScienced, BIND 9.20.24, and NSD 4.15.0 from the pinned Docker definitions.

This result establishes parity only for the corpus above. It does not establish
complete RFC parity, equivalent performance, equivalent security review, or the
operational maturity of BIND or NSD. Every expansion of the public comparison
should add executable cases before adding broader prose claims.

When updating either reference, use the vendor's official current-release page,
change the version and SHA-256 together, and run the full suite before merging.
