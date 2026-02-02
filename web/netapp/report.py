# Minimal JSON → PDF report (ONLY uses fields present in the provided schema)
# Schema used:
# {
#   "ran_at": "...",
#   "pcap_file": "...",
#   "results": {
#     "pcap_file": "...",
#     "groups": <int>,
#     "scans": <int>,
#     "metrics": {
#       "segments_seen": <int>,
#       "segments_valid": <int>,
#       "packets_processed": <int>,
#       "groups_emitted": <int>,
#       "scan_candidates": <int>,
#       "scans_collapsed": <int>,
#       "scan_outliers_kept": <int>,
#       "http_enriched": <int>,
#       "ftp_enriched": <int>,
#       "smb_enriched": <int>,
#       "sampling_applied": <int>
#     },
#     "final_answer": [
#       {
#         "tactic_name": "...",
#         "technique_id": "...",
#         "technique_name": "...",
#         "relevance": <float>,
#         "impact": <float>,
#         "reason": "...",
#         "score": <float>
#       },
#       ...
#     ]
#   }
# }

import argparse
import io
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# --- ReportLab ---
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

__all__ = [
    "build_pdf",                   # write to file from JSON file path
    "build_pdf_from_json",         # write to file from in-memory JSON
    "build_pdf_bytes_from_file",   # return PDF bytes from JSON file path
    "build_pdf_bytes_from_json",   # return PDF bytes from in-memory JSON
]

# =========================
# Fonts (avoid tofu/blocks)
# =========================

def _try_reg(name, path):
    try:
        if os.path.exists(path):
            pdfmetrics.registerFont(TTFont(name, path))
            return True
    except Exception:
        pass
    return False

def ensure_fonts():
    candidates = [
        ("DejaVuSans", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        ("DejaVuSans", "/Library/Fonts/DejaVu Sans.ttf"),
        ("DejaVuSans", "C:\\Windows\\Fonts\\DejaVuSans.ttf"),
        ("DejaVuSansMono", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        ("DejaVuSansMono", "/Library/Fonts/DejaVu Sans Mono.ttf"),
        ("DejaVuSansMono", "C:\\Windows\\Fonts\\DejaVuSansMono.ttf"),
    ]
    got_sans = got_mono = False
    for name, path in candidates:
        ok = _try_reg(name, path)
        if ok and name == "DejaVuSans": got_sans = True
        if ok and name == "DejaVuSansMono": got_mono = True
    return got_sans, got_mono

# =========================
# Data extraction (STRICT)
# =========================

METRIC_KEYS_ORDER = [
    "segments_seen",
    "segments_valid",
    "packets_processed",
    "groups_emitted",
    "scan_candidates",
    "scans_collapsed",
    "scan_outliers_kept",
    "http_enriched",
    "ftp_enriched",
    "smb_enriched",
    "sampling_applied",
]

def extract_core_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull ONLY fields that exist in the provided schema.
    """
    ran_at = data.get("ran_at")
    pcap_file = data.get("pcap_file")

    results = data.get("results") or {}
    res_pcap = results.get("pcap_file")
    groups = results.get("groups")
    scans = results.get("scans")

    metrics = (results.get("metrics") or {})
    metrics_filtered = {k: metrics.get(k) for k in METRIC_KEYS_ORDER if k in metrics}

    fa = results.get("final_answer") or []
    final_rows = []
    for it in fa:
        if not isinstance(it, dict):
            continue
        final_rows.append([
            it.get("tactic_name"),
            it.get("technique_id"),
            it.get("technique_name"),
            round(float(it.get("relevance", 0) or 0), 2),
            round(float(it.get("impact", 0) or 0), 2),
            it.get("reason"),
            round(float(it.get("score", (it.get("relevance", 0) or 0) + (it.get("impact", 0) or 0))), 2),
        ])

    return {
        "ran_at": ran_at,
        "pcap_file": pcap_file,
        "results_pcap_file": res_pcap,
        "groups": groups,
        "scans": scans,
        "metrics": metrics_filtered,
        "final_answer_rows": final_rows,
    }

# =========================
# PDF pieces
# =========================

def header_footer(canvas, doc, title):
    canvas.saveState()
    w,h=doc.pagesize
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(20*mm, h-15*mm, title)
    canvas.setStrokeColorRGB(0.2,0.2,0.2)
    canvas.setLineWidth(0.5)
    canvas.line(15*mm, h-17*mm, w-15*mm, h-17*mm)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(20*mm, 12*mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    canvas.drawRightString(w-20*mm, 12*mm, f"Page {doc.page}")
    canvas.restoreState()

def metrics_table(metrics: Dict[str, Any], styles, header_font, body_font, page_width=450):
    if not metrics:
        rows = [["Metric", "Value"], ["-", "-"]]
    else:
        header = ["Metric", "Value"]
        rows = [header]
        for k in METRIC_KEYS_ORDER:
            if k in metrics:
                rows.append([Paragraph(k, styles["Cell"]), Paragraph(str(metrics[k]), styles["CellNum"])])

    weights=[2.0,1.0]
    scale = page_width / sum(weights)
    col_widths=[w*scale for w in weights]

    t=Table(rows, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("WORDWRAP",(0,0),(-1,-1),1),
        ("FONTNAME",(0,0),(-1,0),header_font), ("FONTSIZE",(0,0),(-1,0),9.5),
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#EDEDED")), ("TEXTCOLOR",(0,0),(-1,0),colors.HexColor("#333333")),
        ("FONTNAME",(0,1),(-1,-1),body_font), ("FONTSIZE",(0,1),(-1,-1),9),
        ("ALIGN",(1,1),(1,-1),"RIGHT"),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CFCFCF")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#FBFBFB")]),
    ]))
    return t

def attack_table(rows: List[List[Any]], styles, header_font, body_font, page_width=450):
    header = ["Tactic","Technique ID","Technique","Relevance","Impact","Reason","Score"]
    if not rows:
        rows = [header, ["-","-","-","-","-","No techniques provided.","-"]]
    else:
        rows = [header] + rows
        # Wrap some columns
        for i,r in enumerate(rows):
            if i==0: continue
            r[0]=Paragraph(str(r[0] or "-"), styles["Cell"])
            r[2]=Paragraph(str(r[2] or "-"), styles["Cell"])
            r[5]=Paragraph(str(r[5] or "-"), styles["Cell"])

    weights=[1.0,0.9,1.3,0.7,0.7,2.8,0.7]
    scale = page_width / sum(weights)
    col_widths=[w*scale for w in weights]

    t=Table(rows, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("WORDWRAP",(0,0),(-1,-1),1),
        ("FONTNAME",(0,0),(-1,0),header_font), ("FONTSIZE",(0,0),(-1,0),9.5),
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#EDEDED")), ("TEXTCOLOR",(0,0),(-1,0),colors.HexColor("#333333")),
        ("FONTNAME",(0,1),(-1,-1),body_font), ("FONTSIZE",(0,1),(-1,-1),9),
        ("ALIGN",(3,1),(4,-1),"RIGHT"), ("ALIGN",(6,1),(6,-1),"RIGHT"),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#BBBBBB")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#FAFAFA")]),
    ]))
    return t

# =========================
# Story builder
# =========================

def _build_story(core: Dict[str, Any], title: str, doc_width: float):
    got_sans,_ = ensure_fonts()
    body_font = "DejaVuSans" if got_sans else "Helvetica"
    header_font = body_font

    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1X", parent=styles["Heading1"], fontName=header_font, fontSize=16, leading=19, spaceAfter=6))
    styles.add(ParagraphStyle(name="H2X", parent=styles["Heading2"], fontName=header_font, fontSize=13, leading=16, spaceAfter=4))
    styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontName=body_font, fontSize=10, leading=13, spaceAfter=8))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontName=body_font, fontSize=9, leading=12,
                              wordWrap="CJK", spaceAfter=0, spaceBefore=0))
    styles.add(ParagraphStyle(name="CellNum", parent=styles["Cell"], alignment=2))
    styles.add(ParagraphStyle(name="CellCenter", parent=styles["Cell"], alignment=1))

    # Overview text from ONLY the allowed fields
    ov_blocks = []
    if core.get("pcap_file"):
        ov_blocks.append(f"PCAP file (top-level): {core['pcap_file']}")
    if core.get("results_pcap_file"):
        ov_blocks.append(f"PCAP file (results): {core['results_pcap_file']}")
    if core.get("ran_at"):
        ov_blocks.append(f"Ran at: {core['ran_at']}")
    if core.get("groups") is not None:
        ov_blocks.append(f"Groups: {core['groups']}")
    if core.get("scans") is not None:
        ov_blocks.append(f"Scans: {core['scans']}")

    story=[]
    story += [Paragraph(title, styles["H1X"]), Spacer(1,2)]
    if ov_blocks:
        story += [Paragraph("Overview", styles["H2X"]),
                  Paragraph(" | ".join(str(x) for x in ov_blocks), styles["BodyX"]),
                  Spacer(1,4)]

    story += [Paragraph("Metrics", styles["H2X"]),
              metrics_table(core.get("metrics") or {}, styles, header_font, body_font, page_width=doc_width),
              Spacer(1,8)]

    story += [Paragraph("ATT&CK Mapping (Provided)", styles["H2X"]),
              attack_table(core.get("final_answer_rows") or [], styles, header_font, body_font, page_width=doc_width)]
    return story

# =========================
# Public builders
# =========================

def build_pdf(input_path: str, output_path: str, title: str, use_landscape: bool = False):
    with open(input_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    core = extract_core_fields(raw_data)

    pagesize = landscape(A4) if use_landscape else A4
    doc=SimpleDocTemplate(output_path, pagesize=pagesize, leftMargin=18*mm, rightMargin=18*mm,
                          topMargin=25*mm, bottomMargin=18*mm, title=title)
    story = _build_story(core, title, doc.width)
    doc.build(story, onFirstPage=lambda c,d: header_footer(c,d,title),
                    onLaterPages=lambda c,d: header_footer(c,d,title))

def build_pdf_from_json(input_data: Any, output_path: str, title: str, use_landscape: bool = False):
    core = extract_core_fields(input_data)
    pagesize = landscape(A4) if use_landscape else A4
    doc=SimpleDocTemplate(output_path, pagesize=pagesize, leftMargin=18*mm, rightMargin=18*mm,
                          topMargin=25*mm, bottomMargin=18*mm, title=title)
    story = _build_story(core, title, doc.width)
    doc.build(story, onFirstPage=lambda c,d: header_footer(c,d,title),
                    onLaterPages=lambda c,d: header_footer(c,d,title))

def build_pdf_bytes_from_file(input_path: str, title: str, use_landscape: bool = False) -> bytes:
    with open(input_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    core = extract_core_fields(raw_data)

    pagesize = landscape(A4) if use_landscape else A4
    buf = io.BytesIO()
    doc=SimpleDocTemplate(buf, pagesize=pagesize, leftMargin=18*mm, rightMargin=18*mm,
                          topMargin=25*mm, bottomMargin=18*mm, title=title)
    story = _build_story(core, title, doc.width)
    doc.build(story, onFirstPage=lambda c,d: header_footer(c,d,title),
                    onLaterPages=lambda c,d: header_footer(c,d,title))
    return buf.getvalue()

def build_pdf_bytes_from_json(input_data: Any, title: str, use_landscape: bool = False) -> bytes:
    core = extract_core_fields(input_data)
    pagesize = landscape(A4) if use_landscape else A4
    buf = io.BytesIO()
    doc=SimpleDocTemplate(buf, pagesize=pagesize, leftMargin=18*mm, rightMargin=18*mm,
                          topMargin=25*mm, bottomMargin=18*mm, title=title)
    story = _build_story(core, title, doc.width)
    doc.build(story, onFirstPage=lambda c,d: header_footer(c,d,title),
                    onLaterPages=lambda c,d: header_footer(c,d,title))
    return buf.getvalue()

# =========================
# CLI
# =========================

def main():
    ap = argparse.ArgumentParser(description="Strict JSON → PDF report (uses ONLY allowed fields).")
    ap.add_argument("--input","-i", required=True, help="Path to JSON file.")
    ap.add_argument("--output","-o", default="report.pdf", help="Output PDF path.")
    ap.add_argument("--title","-t", default="Network Report", help="Title on the report.")
    ap.add_argument("--landscape", action="store_true", help="Use landscape page orientation.")
    args = ap.parse_args()
    build_pdf(args.input, args.output, args.title, use_landscape=args.landscape)
    print(f"[+] Wrote {args.output}")

if __name__ == "__main__":
    main()