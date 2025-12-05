# Analyzer Logic & Heuristics

## Summary

The analyzer parses PCAP files with Scapy and accumulates flows keyed by a 5-tuple:
(src, dst, sport, dport, protocol). Each flow records:

- total bytes, packets
- start/end timestamps
- per-second timeline buckets (pkts, bytes)

It also tracks DNS query counts and DNS TXT response sizes, and per-source per-second packet bursts.

## Flow identification

- A deterministic short ID is generated via SHA1 of the 5-tuple (first 12 hex chars).
- Note: direction is not normalized — reverse-direction packets create separate flows.

## Key accumulators

- acc (per-5-tuple): bytes, pkts, start, end, protocol, timeline (per-second)
- dns_query_counter: domain -> count
- dns_txt_sizes: domain -> list of TXT response sizes
- time_counter: (src, bucket) -> pkts in that second

## Heuristics (current thresholds)

- LARGE_FLOW_BYTES = 50_000 bytes — flag large flows
- LARGE_POST_BYTES = 20_000 bytes — flag large HTTP-like transfers
- DNS_QUERY_BURST = 5 — flag many queries to same name
- BURSTY_PKT = 10 pkts/sec — flag burst traffic
- DNS_TXT_SIZE_THRESHOLD = 100 bytes — large TXT responses

When a heuristic matches, an entry is appended to `suspicious` with:

- type: "flow" | "dns" | "dns_txt" | "burst"
- identifying fields (id / domain / src)
- reasons: human-readable list
- bytes / packets / count where appropriate

## DNS handling

- Queries: qname normalized (rstrip(".") + lowercase) before counting
- Responses: iterate DNS answer records; collect TXT sizes

## Output

- `flows`: map of flow_id -> metadata & timeline
- `suspicious`: array of findings (used by frontend)
- `summary`: counts and total_bytes
- top-level `suspicious_count` included for frontend convenience

## Known limitations & suggestions

- Directional merging: consider canonicalizing 5-tuple to merge bidirectional flows.
- Payload length: len(bytes(pkt)) is used (counts whole packet bytes). If you need application payload lengths, parse TCP/HTTP layers.
- DNS parsing: scapy record structures vary; current code uses defensive patterns.
- Scaling: large pcaps may consume memory. Consider streaming parse or chunked analysis.
- Multi-user: replace global LAST_ANALYSIS with persistent storage or per-upload IDs.

## Tuning tips

- For small sample pcaps lower thresholds (as currently done). For real networks, raise thresholds (e.g., 500KB+).
- Adjust DNS thresholds if you expect heavy legitimate DNS activity (CDNs, monitoring).

## How to add a new heuristic

1. Add a new threshold/config constant at top of analyzer.py.
2. Update the per-flow loop or DNS/time loops to append a structured suspicious entry when triggered.
3. Ensure the frontend can render the new `type` (it uses generic fields type/domain/src/reasons).
