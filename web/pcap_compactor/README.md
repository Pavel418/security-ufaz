# pcap-compactor

A small Python module that turns raw packet captures into compact, hourly “flow-group” summaries suitable for downstream detection/analytics. It implements the hierarchical compression described in your spec: five-tuple grouping (excluding ephemeral source ports), behavioral features, scan splitting, and binomial sampling for HTTP URI tokens. This module does **not** save files; it emits records directly to your next stage.

## What it expects (inputs)

- **Time window:** UTC epoch seconds `[hour_start, hour_end)`; typically a 1-hour tumbling window.
- **Segments:** PCAP/PCAPNG files per sensor, optionally `.gz` or `.zst` compressed, organized by hour. Use the provided `FilesystemSegmentSource`, or implement your own `SegmentSourcePort`.
- **Packets:** The module reads packets and extracts only: timestamp, 5-tuple (minus `src_port` for grouping), TCP flags, and frame length.

## What it produces (outputs)

The orchestrator calls your sink (`EventSinkPort`) with:

- **`GroupRecord`** — one per flow group (or idle-split slice):
  - `key`: `{src_ip, dst_ip, dst_port, transport, service}`
  - `time`: `first_ts`, `last_ts`, `duration_s`
  - `counts`: `pkts_up`, `pkts_dn`, `bytes_up`, `bytes_dn`
  - `tcp_flags`: `syn`, `ack`, `rst`, `fin`
  - `tokens`: quantized bins for counts/duration/flags (integers)
  - optional protocol sections: `http={"uri_tokens":[...]}`, `ftp`, `smb`
  - `lineage_hour`: `(hour_start, hour_end)`
- **`ScanSummary`** — collapsed summary for repetitive port scans:
  - `src_ip`, `window`, `unique_dsts`, `unique_ports`, `syn_only_ratio`, `sample_targets`
- **Metrics** — a small dict at the end of the run (e.g., `packets_processed`, `groups_emitted`, `scans_collapsed`).

Your program decides what to do with these objects (queue, index, model input, etc.).

## Configuration

All knobs live in `PipelineConfig`. Defaults match the paper-style behavior.

```python
from pcap_compactor import PipelineConfig

cfg = PipelineConfig(
    window_seconds=3600,            # 1h
    idle_split_seconds=120,         # split long groups on idle gaps
    scan_unique_dsts_threshold=50,  # rule to flag scan candidates
    iforest_contamination=0.14,     # ~13.9% repetitive probes filtered
    iforest_estimators=256,
    count_log_base=2.0,             # log binning for counts/bytes
    duration_log_base=2.0,          # log binning for duration
    http_uri_token_budget=40,       # binomial sampling cap for HTTP tokens
)
````

Service labels are inferred by destination port (`80|8080→http`, `21→ftp`, `445→smb`, `22→ssh`, `53→dns`, else `unknown`). You can override `service_port_map` in the config if needed.

## Using it in your pipeline

Integrate as a **pure function over an hour**: source → compactor → your sink. The compactor has no persistence and can be run in-process or as part of a worker.

```python
from pcap_compactor import (
    PipelineConfig, run_hour, FilesystemSegmentSource, EventSinkPort
)

# 1) Define how to receive outputs
class NextStageSink(EventSinkPort):
    def on_group(self, record):
        # Send to your queue/model/aggregator
        pass

    def on_scan(self, summary):
        # Optional separate path for scan summaries
        pass

    def on_metrics(self, metrics):
        # Log or export
        pass

# 2) Declare the input source (filesystem-backed example)
source = FilesystemSegmentSource(
    root="/data/raw/pcap",          # root directory
    sensors=["edge-a", "edge-b"],   # or None to auto-discover subdirs
)

# 3) Configure and run for an hour window
cfg = PipelineConfig()
hour_start = 1697716800  # inclusive (UTC)
hour_end   = 1697720400  # exclusive (UTC)

sink = NextStageSink()
run_hour(source=source, sink=sink, cfg=cfg, hour_start=hour_start, hour_end=hour_end)
```

### How it compresses

* **Grouping:** `(src_ip, dst_ip, dst_port, transport, service)`; `src_port` is intentionally excluded.
* **Behavioral features:** directional packet/byte counts, duration, and TCP flag counts.
* **Quantization:** counts and duration are log-binned; flags are small linear bins → compact integer tokens.
* **Scan handling:** sources contacting more than 50 distinct destinations become candidates; an Isolation Forest on `syn_only_ratio` separates repetitive probes (collapsed into a `ScanSummary`) from outliers (kept as groups).
* **Sampling:** for HTTP, URI tokens are downsampled with binomial sampling to stay within a small token budget, preserving a fixed always-keep security lexicon.

### Notes for production use

* The module does not keep payloads; only compact features and optional tokens.
* Enrichers are stubs by default (no deep parsing); you can extend them later if you decide to expose safe payload snippets during intake.
* Backpressure is up to your sink. The default emitter is synchronous; swap it with an async/queued implementation if your downstream is slower than packet processing.