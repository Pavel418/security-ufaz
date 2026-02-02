# NDIS Security Monitor — README

End-to-end application for capturing network traffic, compressing it into flow-level features, detecting MITRE ATT&CK tactics and techniques, and presenting results in a web UI.

---

## Overview

The system operates as a staged pipeline:

1. **Capture**
   Live packet capture with rotating PCAP segments, or ad-hoc snapshot captures, or analysis of uploaded PCAP files.

2. **Compaction (Preprocessing)**
   Hierarchical compression of traffic into per-flow groups using a stable five-tuple: `(src_ip, dst_ip, dst_port, transport, service)` (intentionally excluding ephemeral `src_port`). Each group is summarized by directional packet/byte counts, session duration, and TCP flag histograms. Optional protocol enrichment adds one small, high-signal field per stateful protocol (e.g., HTTP URI tokens, FTP verb counts, an SMB command sketch). High-volume low-information patterns (e.g., scans) are collapsed so downstream stages focus on salient behavior.

3. **Detection**
   The compacted representation is converted into short, evidence-oriented descriptions and reasoned against the ATT&CK knowledge base to produce a structured `final_answer` list with `(tactic_name, technique_id, technique_name, reason, relevance, impact, score)`.

4. **Presentation (Web UI)**
   A Flask web interface provides Stream mode (live capture telemetry and on-demand snapshot detection), Upload & Analyze (run detection on a provided PCAP), and visualization of ATT&CK findings and summary metrics.

This staged design preserves behavioral signal, reduces data volume, enables explainable outputs, and generalizes better than single-shot keyword or classifier approaches.

---

## Installation

Requirements:

* Python 3.10+
* libpcap (Linux/macOS) or Npcap (Windows) for packet capture

Install Python dependencies:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

No API keys are required.

---

## Configuration

Typical server configuration keys (set in your Flask app factory or config module):

```python
app.config.update(
    LOG_DIR="logs",                        # where capture_*.pcap is written
    DEFAULT_INTERFACE="",                  # leave empty to select in UI; on Windows you can use r"\\Device\\NPF_Loopback"
    DETECTOR_CONFIG="detector/config.yaml",
    DETECT_INTERVAL_SECONDS=300,           # background periodic detection cadence
    DETECT_AUTOSTART=True,                 # start periodic detection on boot
    DETECT_SNAPSHOT_SECONDS=10,            # snapshot length for “Run Detection Now”
)
```

Notes:

* Windows interfaces are device strings like `\Device\NPF_{GUID}`; the UI lists available devices.
* Stream mode can rotate PCAPs (e.g., one file per 60 seconds) so detection always has fresh inputs.

---

## How the stages work

### 1) Capture

* **Live rotation**: start capture on a chosen interface; a new `capture_YYYYMMDD_HHMMSS.pcap` is produced each segment (e.g., every 60s).
* **Snapshot**: “Run Detection Now” pauses rotation if needed, records a short snapshot PCAP (default 10s), then resumes rotation.
* **Upload**: a PCAP or PCAPNG file can be uploaded and analyzed ad-hoc.

### 2) Compaction

* **Grouping**: per five-tuple `(src_ip, dst_ip, dst_port, transport, service)`.
* **Features**: directional packet/byte counts, session duration, and TCP flags (SYN/ACK/RST/FIN).
* **Protocol enrichment (minimal, one field per protocol)**:
  HTTP URI tokens, FTP command verb counts, and an SMB command sketch.
* **Scan handling**: repetitive probes are collapsed; potentially interesting outliers remain.
* **Outputs**: compact `GroupRecord`s (and small metrics) passed directly to detection.

### 3) Detection

* Consumes the compact JSON from the compactor.
* Produces `final_answer`: a ranked list of ATT&CK findings with:
  `tactic_name`, `technique_id`, `technique_name`, `reason`, `relevance`, `impact`, `score`.

### 4) Presentation

* **Home page**: upload a PCAP and run detection; view metrics and ATT&CK cards.
* **Stream mode**: select interface, see live telemetry (packets/s, Mbps, elapsed), stop and summarize, or trigger “Run Detection Now” to snapshot and detect immediately.
* **Results UI**: per-finding cards show tactic, technique (ID — name), reason, and scores; summary metrics include group counts and small compactor telemetry.

**PDF report generation**
After a successful detection, click **Download Report (PDF)** on Home or Stream to export a formatted report. The server converts the **latest persisted detection JSON** (saved under `LOG_DIR/detections/`) into a PDF and serves it via a download link. This does not re-run detection; it simply renders the most recent results into a printable document.

---

## Running the application

Development server:

```bash
python -m flask --app netapp --debug run --host 0.0.0.0 --port 5000
# then open http://localhost:5000/
```

### Stream mode (live)

1. Navigate to **Stream Mode**.
2. Select an interface from the list.
3. Start capture. PCAP segments rotate automatically.
4. Click **Run Detection Now** to snapshot and run the full pipeline on the most recent traffic; results render as ATT&CK cards.
5. Stop capture to finalize the session summary.

### Upload & Analyze

1. On **Home**, upload a `.pcap` or `.pcapng`.
2. Click **Analyze File** to run the full pipeline on the uploaded file.
3. Review summary metrics and ATT&CK findings.

---

## Test files

A directory of sample PCAPs is included (e.g., `test_files/`). These can be used to validate end-to-end behavior:

* **UI path**: Home → choose a file from `test_files/` → **Analyze File**.
* **Stream snapshot**: Stream Mode → choose interface (Loopback is available on Windows with Npcap) → **Run Detection Now**.

---

## API endpoints (used by the UI)

* `GET /stream/interfaces` — enumerate capture interfaces
* `POST /stream/start` — begin rotated capture on selected interface
* `GET /stream/data` — live telemetry snapshot (pps, Mbps, elapsed)
* `POST /stream/stop` — stop capture and return session summary
* `POST /detect/run-now` — take a fresh snapshot PCAP and run detection immediately
* `GET /detect/results` — retrieve the last detection results (periodic or on-demand)
* `POST /upload` — upload a file for analysis
* `POST /analyze` — run compactor → detector on the last uploaded PCAP and return detections
* `POST /report/generate` — render a PDF from the latest detection JSON and return a download URL

---

## Output

Detection responses include:

```json
{
  "pcap_file": "capture_YYYYMMDD_HHMMSS.pcap",
  "groups": 312,
  "scans": 0,
  "metrics": { "packets_processed": 12345, "groups_emitted": 312, "http_enriched": 7 },
  "final_answer": [
    {
      "tactic_name": "Credential Access",
      "technique_id": "T1110.001",
      "technique_name": "Password Guessing",
      "relevance": 0.95,
      "impact": 0.7,
      "reason": "Short explanation grounded in observed behavior.",
      "score": 1.65
    }
  ]
}
```

The UI renders these as readable cards with tactic, technique (ID — name), reason, and quick numeric indicators.

---

## Why this approach

* **Behavior preserved, volume reduced**: flow-group summaries encode who talked to whom, how much, and with what TCP handshake shape, retaining detection-critical context while cutting size.
* **Explainable outputs**: findings include concise, behavior-grounded reasons rather than opaque labels.
* **Robust to phrasing and novelty**: reasoning is driven by structured behavior, not brittle keywords, and is validated against a canonical tactics/techniques space.
* **Scalable**: hierarchical grouping and tiny protocol sketches keep token budgets small while maintaining coverage.

---

## Troubleshooting

* **No interfaces on Windows**: install Npcap (WinPcap API compatible), then choose Loopback or a listed `\Device\NPF_{GUID}`.
* **Permission errors**: packet capture may require admin/root.
* **Large captures**: prefer rotated segments (Stream Mode) or use provided test files for quick validation.