# Feed and enrichment fixtures (SYNTHETIC)

Synthetic files in the published formats of the sources Vigil downloads on request:

- `feodo-ipblocklist.json`, `feodo-ipblocklist.csv`: abuse.ch Feodo Tracker blocklist
  (JSON and CSV). One JSON row has an invalid address and must be skipped.
- `sslbl.csv`: abuse.ch SSLBL botnet C2 IP list.
- `urlhaus.csv`: abuse.ch URLhaus `csv_online`, with IP hosts, an IP:port host, a
  domain host and one row that is not a URL.
- `ip2asn-sample.tsv`: IPtoASN `ip2asn-combined.tsv`, with a "Not routed" row and one
  malformed line.

The listings are invented. Addresses are documentation ranges (198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32), except two public /24s (1.1.1.0, 9.9.9.0) used only
to exercise "internet" scope in country lookups. Their owners here are fictitious
(`SYNTHETIC-NET-*`). All AS numbers are from the documentation range in RFC 5398
(64496–64511). `malware.example` is a reserved example domain.
