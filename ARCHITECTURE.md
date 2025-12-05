# final-running-mvp — Architecture

## High-level components

- Frontend (React + Vite)
  - Upload UI, results table, flow details modal (FlowDetailModal.jsx), export buttons (JSON / CSV / PDF).
  - Calls backend API endpoints and renders returned analysis.
- Backend (FastAPI)
  - Upload endpoint: POST /analyze
  - Flow detail: GET /flows/{flow_id}
  - Export: GET /export/{fmt} (json, csv, pdf)
  - Keeps last analysis in-memory (LAST_ANALYSIS) for quick drilldown/export.
- Analyzer (analyzer.py)
  - Parses PCAP files with Scapy, builds flows and heuristics, returns structured JSON.

## End-to-end flow (sequence)

1. User selects a .pcap in the frontend and clicks Upload.
2. Frontend POSTs the file to backend `/analyze` (multipart).
3. Backend saves uploaded file to UPLOAD_DIR, calls `analyze_pcap(tmp_path)`.
4. analyzer.py reads pcap (scapy.rdpcap), accumulates per-5-tuple FlowAccumulator objects, performs DNS/time heuristics and payload entropy checks, and composes a result dict:
   - `flows`: map flow_id -> metadata, timeline, analysis
   - `suspicious`: list of findings
   - `summary`: flow_count, suspicious_count, total_bytes
5. Backend stores result in `LAST_ANALYSIS` and `LAST_RESULT`, returns summary + suspicious to frontend.
6. Frontend renders results. When a flow row is opened, it may:
   - Use flow id from the response or request `GET /flows/{flow_id}` to fetch details (reads LAST_ANALYSIS.data).
7. Export actions:
   - JSON: streaming JSON of `LAST_ANALYSIS.data`
   - CSV: streamed rows built from flows
   - PDF: generated on-demand using reportlab (either pretty JSON or formatted tables); backend streams PDF to client.

## Configuration & env

- Backend reads env variables via python-dotenv (backend/.env).
  - Server: BACKEND_HOST, BACKEND_PORT
  - UPLOAD_DIR, CORS_ORIGINS
- Analyzer thresholds read from env:
  - LARGE_FLOW_BYTES (bytes)
  - LARGE_POST_BYTES (bytes)
  - DNS_QUERY_BURST (count)
  - BURSTY_PKT (packets/sec)
  - DNS_TXT_SIZE_THRESHOLD (bytes)
- Security: current design uses in-memory last-result — not multi-user. For multi-user or persistence, add DB or per-upload IDs.

## Data shapes (summary)

- analyze response:
  {
  "flows": { "<flow_id>": { id, five_tuple, bytes, packets, start, end, duration, timeline: [{ts, pkts, bytes}], payload_analysis, tcp_flags, has_http_post } },
  "suspicious": [ { type, id/domain/src, reasons: [...], bytes/count } ],
  "summary": { flow_count, suspicious_count, total_bytes },
  "suspicious_count": <int>, "flow_count": <int>, "total_bytes": <int>
  }

## Notes & improvement suggestions

- Merge bidirectional packets by canonicalizing 5-tuple to identify flows across directions.
- Replace in-memory LAST_ANALYSIS with persistent store or ephemeral analysis IDs for multi-user use.
- Enable authentication / rate limits for upload endpoints in production.
- PDF generation is optional (reportlab). If used in prod, sanitize and limit size of embedded JSON to avoid excessive memory/IO.
