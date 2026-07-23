# Threat-feed aggregation

DNSScienced can enrich cache entries from multiple explicitly configured
operator files and HTTPS feeds. No public feed is contacted unless it appears
in configuration.

```yaml
cache:
  threat_feeds:
    - name: operator-blocklist
      file: /etc/dnsscienced/threats/domains.txt
      format: domains
      score: 95
      categories: [malware, operator]
      refresh_interval: 5m
      max_bytes: 33554432
      max_entries: 1000000

    - name: commercial-feed
      url: https://feeds.example.net/domains.txt
      format: auto
      score: 85
      categories: [commercial]
      refresh_interval: 15m
      timeout: 10s
      auth_token: ${FEED_TOKEN}
```

Supported formats are:

- `domains`: one domain per non-comment line.
- `hosts`: hosts-file lines such as `0.0.0.0 blocked.example`.
- `urls`: one absolute HTTP(S) URL per line; both exact URL and hostname are
  indexed.
- `auto`: accepts one domain/URL or a conventional sinkhole hosts entry.

Parsing is strict and bounded. Malformed input, oversized sources, excessive
entries, non-regular local files, and insecure remote URLs are rejected. HTTP
requires the explicit `allow_insecure_http: true` escape hatch; HTTPS redirects
cannot silently downgrade.

Each source has an independent immutable last-good snapshot. A failed refresh
does not erase the prior data. Query-time lookup performs no file or network
I/O: all source snapshots are merged and atomically published.

When sources disagree, the highest score wins. Categories and contributing
source names are unioned, deduplicated, and sorted so results are deterministic.
The cache entry's `threat_source` contains the comma-separated provenance.
Matching applies to the listed domain and its descendants.

Local files load synchronously at cache startup. With no refresh interval they
are load-once; setting an interval enables bounded re-reading. Remote feeds
refresh immediately in the background and every 15 minutes by default.
