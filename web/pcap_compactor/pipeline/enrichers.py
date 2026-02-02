"""
Protocol enrichers (minimal, practical).

Each protocol adds exactly one high-signal field:
- HTTP: extract & tokenize URI path/query tokens.
- FTP : count command verbs (USER, PASS, STOR, RETR).
- SMB : count command codes (coarse heuristic).

Payload previews are OPTIONAL. If upstream attached small previews to the
GroupAggregate as `_payload_up` / `_payload_dn` (List[bytes]), we scan them.
Otherwise, we do nothing and return flags=False.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

from ..dto import GroupAggregate


def enrich_group(agg: GroupAggregate) -> Dict[str, bool]:
    """
    Apply protocol-specific enrichment to a GroupAggregate (in place).

    Returns a dict of flags indicating which protocol sections were updated:
      {"http": bool, "ftp": bool, "smb": bool}
    """
    updated = {"http": False, "ftp": False, "smb": False}

    up_bytes: List[bytes] = getattr(agg, "_payload_up", []) or []
    dn_bytes: List[bytes] = getattr(agg, "_payload_dn", []) or []
    previews = up_bytes + dn_bytes
    if not previews:
        return updated  # graceful noop

    svc = (agg.key.service or "").lower()

    if svc == "http":
        toks = _http_extract_uri_tokens(previews)
        if toks:
            agg.http_uri_tokens = toks
            updated["http"] = True
    elif svc == "ftp":
        counts = _ftp_command_counts(previews)
        if counts:
            agg.ftp_cmd_counts = counts
            updated["ftp"] = True
    elif svc == "smb":
        counts = _smb_command_counts(previews)
        if counts:
            agg.smb_cmd_counts = counts
            updated["smb"] = True

    return updated


# --- HTTP --------------------------------------------------------------------


def _http_extract_uri_tokens(previews: Iterable[bytes], max_tokens: int = 256) -> List[str]:
    methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
    tokens: List[str] = []

    for blob in previews:
        if not blob:
            continue
        # First line only
        line = blob.split(b"\r\n", 1)[0]
        if not any(line.startswith(m) for m in methods):
            continue

        # Extract target between first space and " HTTP/"
        space1 = line.find(b" ")
        if space1 <= 0:
            continue
        space2 = line.find(b" HTTP/", space1 + 1)
        target = line[space1 + 1 :] if space2 == -1 else line[space1 + 1 : space2]

        tokens.extend(_split_http_target_to_tokens(target))
        if len(tokens) >= max_tokens:
            break

    return tokens[:max_tokens]


def _split_http_target_to_tokens(target: bytes) -> List[str]:
    try:
        s = target.decode("utf-8", errors="ignore")
    except Exception:
        s = ""
    seps = "/?&=+%.:-_#"
    trans = {ord(c): " " for c in seps}
    s = s.translate(trans).lower()
    raw = s.split()
    toks: List[str] = []
    for t in raw:
        t = t.strip()
        if t:
            toks.append(t)
    return toks


# --- FTP ---------------------------------------------------------------------


def _ftp_command_counts(previews: Iterable[bytes]) -> Dict[str, int]:
    verbs = (b"USER", b"PASS", b"STOR", b"RETR")
    counts: Dict[str, int] = {}
    for blob in previews:
        if not blob:
            continue
        for line in blob.split(b"\r\n"):
            U = line.upper()
            for v in verbs:
                if U.startswith(v + b" "):
                    key = v.decode("ascii")
                    counts[key] = counts.get(key, 0) + 1
    return counts


# --- SMB ---------------------------------------------------------------------


def _smb_command_counts(previews: Iterable[bytes]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for blob in previews:
        if not blob or len(blob) < 8:
            continue

        # SMB2 (0xFE 'S' 'M' 'B')
        if blob[:4] == b"\xfeSMB" and len(blob) >= 16:
            cmd = blob[12]
            key = f"SMB2_{cmd}"
            counts[key] = counts.get(key, 0) + 1
            continue

        # SMB1 (0xFF 'S' 'M' 'B'); command byte at offset 4
        if blob[:4] == b"\xffSMB" and len(blob) >= 8:
            cmd = blob[4]
            key = f"SMB1_{cmd}"
            counts[key] = counts.get(key, 0) + 1
            continue

    return counts