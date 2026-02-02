"""
Packet reader: yields minimal PacketRecord objects from a PCAP/PCAPNG byte stream.

- No deep parsing, minimal payload retention.
- Extract exactly what upstream stages need:
  ts, src_ip, dst_ip, src_port, dst_port, transport, tcp_flags (if TCP), length,
  and a SMALL optional payload preview for TCP (first N bytes).

Implementation notes:
- Tries dpkt.pcap.Reader first, then falls back to dpkt.pcapng.Reader.
- Handles Ethernet frames with optional 802.1Q VLAN tags.
- Supports IPv4 and IPv6; non-IP frames are ignored.
"""

from __future__ import annotations

from typing import Iterable, Iterator, Optional, Tuple

import dpkt  # type: ignore
import socket

from ..dto import PacketRecord, SegmentHandle, Transport

# Keep memory bounded: capture at most this many bytes from TCP payload per packet
_PREVIEW_LEN = 256


def iter_packets(bytestream, seg: SegmentHandle) -> Iterable[PacketRecord]:
    """
    Iterate PacketRecord objects from an open segment byte stream.

    Parameters
    ----------
    bytestream : file-like
        Binary readable stream for the (decompressed) segment bytes.
    seg : SegmentHandle
        Segment metadata (used only for context; not required for parsing).

    Yields
    ------
    PacketRecord
        Minimal per-packet structure for downstream processing.
    """
    reader = _open_any_pcap_reader(bytestream)
    if reader is None:
        return  # nothing to yield

    # dpkt readers are iterable: (ts, buf)
    for ts, buf in reader:
        rec = _parse_packet(ts, buf)
        if rec is not None:
            yield rec


# === Helpers ===


def _open_any_pcap_reader(bytestream) -> Optional[Iterator[Tuple[float, bytes]]]:
    """
    Try dpkt.pcap.Reader; if it fails, try dpkt.pcapng.Reader.
    Returns an iterator of (timestamp, raw_frame_bytes) tuples or None on failure.
    """
    # dpkt readers consume the stream; we assume a fresh stream per call.
    try:
        return dpkt.pcap.Reader(bytestream)
    except Exception:
        # Reset is not guaranteed; attempt pcapng on the same stream may fail if unread.
        # In practice, bytestream for gzip/zstd is not seekable; re-open is handled upstream.
        try:
            return dpkt.pcapng.Reader(bytestream)
        except Exception:
            return None


def _parse_packet(ts: float, buf: bytes) -> Optional[PacketRecord]:
    """
    Parse a single L2 frame into a PacketRecord. Returns None if non-IP or unsupported.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None

    # Handle optional 802.1Q VLAN (0x8100): unwrap inner Ethernet if present.
    if eth.type == dpkt.ethernet.ETH_TYPE_8021Q and hasattr(eth.data, "data"):
        # eth.data is dpkt.vlan.VLAN; inner payload is another Ethernet-like with .type & .data
        inner = eth.data
        try:
            # Some captures embed the original L3 directly after VLAN
            proto_type = getattr(inner, "type", None)
            payload = getattr(inner, "data", None)
        except Exception:
            proto_type, payload = None, None
    else:
        proto_type = eth.type
        payload = eth.data

    if proto_type == dpkt.ethernet.ETH_TYPE_IP:
        return _parse_ipv4(ts, payload, len(buf))
    if proto_type == dpkt.ethernet.ETH_TYPE_IP6:
        return _parse_ipv6(ts, payload, len(buf))

    # Non-IP frames are ignored
    return None


def _parse_ipv4(ts: float, ip, frame_len: int) -> Optional[PacketRecord]:
    try:
        src_ip = socket.inet_ntop(socket.AF_INET, ip.src)
        dst_ip = socket.inet_ntop(socket.AF_INET, ip.dst)
    except Exception:
        return None

    # Transport
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        return _from_tcp(ts, src_ip, dst_ip, ip.tcp, frame_len)
    if ip.p == dpkt.ip.IP_PROTO_UDP:
        return _from_udp(ts, src_ip, dst_ip, ip.udp, frame_len)

    return _other_transport(ts, src_ip, dst_ip, frame_len)


def _parse_ipv6(ts: float, ip6, frame_len: int) -> Optional[PacketRecord]:
    try:
        src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
    except Exception:
        return None

    # IPv6 next header
    nh = ip6.nxt
    if nh == dpkt.ip.IP_PROTO_TCP:
        return _from_tcp(ts, src_ip, dst_ip, ip6.data, frame_len)
    if nh == dpkt.ip.IP_PROTO_UDP:
        return _from_udp(ts, src_ip, dst_ip, ip6.data, frame_len)

    return _other_transport(ts, src_ip, dst_ip, frame_len)


def _from_tcp(ts: float, src_ip: str, dst_ip: str, tcp, frame_len: int) -> Optional[PacketRecord]:
    try:
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = int(tcp.flags)
        payload = bytes(tcp.data) if tcp.data else b""
        preview = payload[:_PREVIEW_LEN] if payload else None
    except Exception:
        return None
    return PacketRecord(
        ts=float(ts),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=_t("tcp"),
        tcp_flags=flags,
        length=frame_len,
        payload_preview=preview,
    )


def _from_udp(ts: float, src_ip: str, dst_ip: str, udp, frame_len: int) -> Optional[PacketRecord]:
    try:
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    except Exception:
        return None
    return PacketRecord(
        ts=float(ts),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=_t("udp"),
        tcp_flags=None,
        length=frame_len,
        payload_preview=None,
    )


def _other_transport(ts: float, src_ip: str, dst_ip: str, frame_len: int) -> PacketRecord:
    return PacketRecord(
        ts=float(ts),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=0,
        dst_port=0,
        transport=_t("other"),
        tcp_flags=None,
        length=frame_len,
        payload_preview=None,
    )


def _t(name: str) -> Transport:
    if name == "tcp":
        return "tcp"
    if name == "udp":
        return "udp"
    return "other"