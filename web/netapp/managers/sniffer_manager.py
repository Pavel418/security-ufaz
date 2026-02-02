"""
Thread-safe sniffer orchestration, telemetry, and summary persistence.

This module manages rolling packet capture (segment-by-segment) and provides:
- live telemetry snapshots for the UI,
- a summary of the most recent capture session,
- an optional synchronous snapshot capture,
- a basic PCAP inspection helper used when analyzing saved captures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import logging
import threading
import time

from scapy.all import rdpcap, IP, TCP, UDP, ICMP  # type: ignore[import-untyped]

from ..packet_sniffer import PacketSniffer
from ..utils import utcnow_iso


@dataclass
class SnifferManager:
    """
    Orchestrates rolling captures in background segments and exposes:
      - start()/stop() to control capture,
      - telemetry_snapshot() for live stats,
      - summarize_and_persist() to persist timeseries + return summary,
      - capture_snapshot() for a short, blocking capture,
      - basic_pcap_analysis() for post-hoc PCAP summaries.

    Rolling capture design:
      * Each segment runs up to max_duration seconds and writes 'capture_*.pcap'.
      * When a segment ends (or stop is requested), state is updated accordingly.
    """
    logger: logging.Logger
    log_dir: Path
    default_iface: str
    max_duration: int

    thread: Optional[threading.Thread] = None
    sniffer: Optional[PacketSniffer] = None
    active: bool = False
    start_time: Optional[float] = None
    error: Optional[str] = None
    last_pcap_file: Optional[Path] = None
    packet_history: List[Dict[str, float]] = field(default_factory=list)

    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    # ---------------------------- Control plane ----------------------------

    def start(self, interface: Optional[str] = None) -> Tuple[bool, str]:
        """
        Start rolling capture on a background thread.

        Returns:
            (ok, message)
        """
        with self._lock:
            if self.active:
                return False, "Sniffing already active"

            iface = interface or self.default_iface
            self.active = True
            self.error = None
            self.packet_history.clear()
            self.start_time = time.time()

            def runner() -> None:
                try:
                    while True:
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        output_file = self.log_dir / f"capture_{ts}.pcap"

                        self.logger.info("Starting capture on %s", iface)

                        # Fresh sniffer for each segment
                        self.sniffer = PacketSniffer(iface, self.logger)
                        self.sniffer.stop_sniffing = False  # ensure clean state

                        # Run one segment (blocks until duration elapsed or stop requested)
                        self.sniffer.capture_packets(self.max_duration, str(output_file))

                        # Segment finished — record it
                        with self._lock:
                            self.last_pcap_file = output_file

                        self.logger.info("Capture segment finished: %s", output_file.name)

                        # Stop requested during this segment?
                        if getattr(self.sniffer, "stop_sniffing", False):
                            with self._lock:
                                self.active = False
                            break

                        # Continue next segment unless an error was set
                        with self._lock:
                            if self.error:
                                self.active = False
                                break
                            self.active = True

                except PermissionError as e:
                    self.logger.error("Permission denied: %s", e)
                    with self._lock:
                        self.error = "Permission denied. Try elevated privileges (e.g., sudo)."
                        self.active = False
                except Exception as e:
                    self.logger.exception("Error during capture")
                    with self._lock:
                        self.error = f"Error: {e}"
                        self.active = False

            self.thread = threading.Thread(target=runner, daemon=True)
            self.thread.start()
            return True, f"Started capturing on {iface}"

    def stop(self) -> int:
        """
        Signal the sniffer to stop the current segment.
        Returns the number of packets captured in the current segment (if available).
        """
        with self._lock:
            if not self.active or not self.sniffer:
                return 0
            self.logger.info("Stopping capture…")
            self.sniffer.stop_sniffing = True
            self.active = False
            return self.sniffer.packet_count

    # ----------------------------- Telemetry ------------------------------

    def telemetry_snapshot(self) -> Dict[str, object]:
        """
        Return current telemetry. If inactive or errored, returns zeros plus flags.
        """
        with self._lock:
            if self.error:
                return {
                    "timestamp": utcnow_iso(),
                    "total_packets": 0,
                    "packets_per_second": 0.0,
                    "bandwidth": 0.0,
                    "elapsed_time": 0.0,
                    "active": False,
                    "error": self.error,
                }

            if self.active and self.sniffer:
                pkt_count = self.sniffer.packet_count
                elapsed = max(1e-9, (time.time() - (self.start_time or time.time())))
                pps = pkt_count / elapsed
                mbps = (pps * 1500 * 8) / 1_000_000  # rough estimate

                point = {
                    "timestamp": utcnow_iso(),
                    "packet_count": pkt_count,
                    "packets_per_second": round(pps, 2),
                    "bandwidth_mbps": round(mbps, 2),
                }
                self.packet_history.append(point)

                return {
                    "timestamp": utcnow_iso(),
                    "total_packets": pkt_count,
                    "packets_per_second": point["packets_per_second"],
                    "bandwidth": point["bandwidth_mbps"],
                    "elapsed_time": round(elapsed, 1),
                    "active": True,
                }

            # inactive & no error
            return {
                "timestamp": utcnow_iso(),
                "total_packets": 0,
                "packets_per_second": 0.0,
                "bandwidth": 0.0,
                "elapsed_time": 0.0,
                "active": False,
            }

    # --------------------------- Persistence/UI ---------------------------

    def summarize_and_persist(self) -> Dict[str, object]:
        """
        Persist the timeseries packet history to JSON and return summary metrics
        for the just-finished rolling capture session.
        """
        with self._lock:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_name = f"network_analysis_{ts}.json"
            json_path = self.log_dir / json_name

            bw = [d.get("bandwidth_mbps", 0.0) for d in self.packet_history]
            pps = [d.get("packets_per_second", 0.0) for d in self.packet_history]
            approx_duration = float(len(self.packet_history))  # ~1 Hz points

            total_packets = self.sniffer.packet_count if self.sniffer else 0
            analysis = {
                "total_packets_captured": total_packets,
                "capture_duration": round(approx_duration, 1),
                "data_points": len(self.packet_history),
                "average_bandwidth_mbps": round(sum(bw) / len(bw), 2) if bw else 0.0,
                "peak_bandwidth_mbps": round(max(bw), 2) if bw else 0.0,
                "min_bandwidth_mbps": round(min(bw), 2) if bw else 0.0,
                "avg_packets_per_second": round(sum(pps) / len(pps), 2) if pps else 0.0,
                "peak_packets_per_second": round(max(pps), 2) if pps else 0.0,
                "pcap_file": self.last_pcap_file.name if self.last_pcap_file else None,
                "analysis_file": json_name,
            }

            with json_path.open("w", encoding="utf-8") as f:
                json.dump(self.packet_history, f, indent=2)

            return analysis

    # ------------------------- Saved PCAP utilities ------------------------

    @staticmethod
    def basic_pcap_analysis(pcap_path: Path) -> Dict[str, object]:
        """
        Return basic protocol & endpoint stats for a PCAP file.
        Intended for “Analyze Saved Capture” workflow.
        """
        packets = rdpcap(str(pcap_path))
        proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        ip_src: Dict[str, int] = {}
        ip_dst: Dict[str, int] = {}
        total_bytes = 0

        for pkt in packets:
            total_bytes += len(pkt)
            if pkt.haslayer(TCP):
                proto_counts["TCP"] += 1
            elif pkt.haslayer(UDP):
                proto_counts["UDP"] += 1
            elif pkt.haslayer(ICMP):
                proto_counts["ICMP"] += 1
            else:
                proto_counts["Other"] += 1

            if pkt.haslayer(IP):
                s = pkt[IP].src
                d = pkt[IP].dst
                ip_src[s] = ip_src.get(s, 0) + 1
                ip_dst[d] = ip_dst.get(d, 0) + 1

        top_src = sorted(ip_src.items(), key=lambda x: x[1], reverse=True)[:5]
        top_dst = sorted(ip_dst.items(), key=lambda x: x[1], reverse=True)[:5]
        total_mb = total_bytes / (1024 * 1024)

        return {
            "total_packets": len(packets),
            "total_size_mb": round(total_mb, 2),
            "protocol_distribution": proto_counts,
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_src],
            "top_destination_ips": [{"ip": ip, "count": c} for ip, c in top_dst],
            "unique_sources": len(ip_src),
            "unique_destinations": len(ip_dst),
        }

    def capture_snapshot(self, duration: int, interface: Optional[str] = None) -> Path:
        """
        Create a fresh PCAP synchronously (blocking) and return its path.

        If rolling capture is active, it is paused for the duration of the snapshot,
        then resumed afterwards.

        NOTE: Requires capture privileges (same as normal capture).
        """
        iface = interface or self.default_iface
        snapshot_name = f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        out_path = self.log_dir / snapshot_name

        # Pause rolling capture if active
        was_active = False
        thread_ref = None
        with self._lock:
            was_active = bool(self.active and self.sniffer)
            thread_ref = self.thread

        if was_active:
            # Signal stop and wait a short grace period for the current segment to close
            self.stop()
            if thread_ref:
                thread_ref.join(timeout=max(2, min(duration, 10)))  # avoid long blocking

        # Take a short, standalone snapshot (blocking)
        snap = PacketSniffer(iface, self.logger)
        self.logger.info("Snapshot capture: %ss on %s -> %s", duration, iface, out_path.name)
        try:
            snap.stop_sniffing = False
            snap.capture_packets(duration, str(out_path))
            with self._lock:
                self.last_pcap_file = out_path
            self.logger.info("Snapshot done: %s (packets=%s)", out_path.name, snap.packet_count)
        except PermissionError as e:
            self.logger.error("Snapshot permission error: %s", e)
            raise
        except Exception as e:
            self.logger.exception("Snapshot capture failed")
            raise

        # Resume rolling capture if we paused it
        if was_active:
            self.logger.info("Resuming rolling capture on %s", iface)
            self.start(interface=iface)

        return out_path