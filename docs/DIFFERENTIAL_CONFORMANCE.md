# BIND and NSD Differential Conformance

The authoritative differential suite runs the same zone and query corpus against
DNSScienced, BIND, and NSD on Linux. It compares protocol semantics after
normalizing DNS message IDs, compression, RR order, owner-name case, and TTLs.
It does not hide meaningful differences in response codes, AA/TC flags, answer
RRsets, negative SOA proofs, referrals, or glue.

The reference versions are deliberately pinned:

- BIND 9.20.24, the current BIND 9.20 stable release listed by ISC's
  [security matrix](https://kb.isc.org/docs/aa-00913), built from ISC's signed
  release archive and checked against the SHA-256 recorded in its Dockerfile.
- NSD 4.15.0, the current release on NLnet Labs'
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

When updating either reference, use the vendor's official current-release page,
change the version and SHA-256 together, and run the full suite before merging.
