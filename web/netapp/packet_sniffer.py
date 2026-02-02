"""
packet_sniffer.py

A small utility for capturing packets from a given network interface using Scapy.
"""

from __future__ import annotations

import logging
import os
import time
from typing import List

from scapy.all import sniff, wrpcap, get_if_list


class PacketSniffer:
    """Capture packets from a given network interface and write them to a PCAP file.

    This class provides a simple interface over Scapy's `sniff` to capture packets for
    a fixed duration, report live capture counts, and persist the result to disk.

    Attributes:
        interface: Name of the network interface to capture from (e.g., "eth0").
        logger: A `logging.Logger` instance used for progress and status messages.
        stop_sniffing: Flag consulted by Scapy's `stop_filter`; toggled on interrupts.
        packet_count: Counter incremented for each packet observed during capture.
    """

    @staticmethod
    def list_interfaces() -> List[str]:
        """Return a list of available network interfaces.

        Returns:
            A list of interface names available to Scapy. If Scapy raises,
            an empty list is returned.

        Note:
            On some platforms, capturing may require elevated privileges.
        """
        try:
            return get_if_list()
        except Exception:
            return []

    def __init__(self, interface: str, logger: logging.Logger) -> None:
        """Initialize a sniffer bound to a specific interface.

        Args:
            interface: Network interface to sniff on.
            logger: Logger to use for output.

        Raises:
            ValueError: If the provided interface is not present on the host.
            TypeError: If `logger` is not a `logging.Logger` instance.
        """
        if not isinstance(logger, logging.Logger):
            raise TypeError("logger must be an instance of logging.Logger")

        available = self.list_interfaces()
        if available and interface not in available:
            raise ValueError(
                f"Interface '{interface}' not found. Available: {', '.join(available)}"
            )

        self.interface: str = interface
        self.logger: logging.Logger = logger
        self.stop_sniffing: bool = False
        self.packet_count: int = 0

    def _count_packets(self, _packet) -> None:
        """Increment internal packet counter (used as `prn` callback)."""
        self.packet_count += 1

    def capture_packets(self, duration: int, output_file: str) -> int:
        """Capture packets for a fixed duration and write them to a PCAP file.

        This method runs a blocking capture for `duration` seconds. While capturing,
        it logs the number of packets seen once per second. On completion, the
        captured packets are written to `output_file` in PCAP format.

        Args:
            duration: Number of seconds to capture. Must be > 0.
            output_file: Path to the output PCAP file (e.g., "capture.pcap").

        Returns:
            The number of packets captured.

        Raises:
            ValueError: If `duration` ≤ 0 or `output_file` directory is not writable.
            OSError: If writing the PCAP fails.
        """
        if duration <= 0:
            raise ValueError("duration must be a positive integer (seconds)")

        # Validate that the output directory exists and is writable
        out_dir = os.path.dirname(os.path.abspath(output_file)) or "."
        if not os.path.exists(out_dir):
            raise ValueError(f"Output directory does not exist: {out_dir}")
        if not os.access(out_dir, os.W_OK):
            raise ValueError(f"Output directory is not writable: {out_dir}")

        self.stop_sniffing = False
        self.packet_count = 0
        self.logger.info(
            "Capturing packets on '%s' for %d seconds…", self.interface, duration
        )

        start_time = time.time()

        try:
            # Start timed sniff. `stop_filter` allows an early stop if we toggle the flag.
            packets = sniff(
                iface=self.interface,
                timeout=duration,
                prn=self._count_packets,
                stop_filter=lambda _x: self.stop_sniffing,
            )

            # Live progress: report once per second until duration elapses.
            # Note: sniff(timeout=duration) already blocks ~duration seconds.
            # This loop is primarily for logging responsiveness if the system clock shifts.
            while True:
                elapsed = time.time() - start_time
                if elapsed >= duration:
                    break
                self.logger.info("Packets captured so far: %d", self.packet_count)
                # Sleep the remaining fraction to the next whole second to reduce spam.
                sleep_for = max(0.2, 1.0 - (elapsed % 1.0))
                time.sleep(sleep_for)

            # Persist results
            try:
                wrpcap(output_file, packets)
            except Exception as e:
                raise OSError(f"Failed to write PCAP to '{output_file}': {e}") from e

            total = len(packets)
            self.logger.info("Saved %d packets to %s", total, output_file)
            return total

        except KeyboardInterrupt:
            # Allow graceful interrupt and write whatever we have so far (if any).
            self.stop_sniffing = True
            self.logger.info("Capture interrupted by user (KeyboardInterrupt).")
            # Best-effort: try to write partial capture if available.
            try:
                if "packets" in locals() and packets:
                    wrpcap(output_file, packets)
                    self.logger.info(
                        "Saved partial capture (%d packets) to %s",
                        len(packets),
                        output_file,
                    )
                    return len(packets)
            except Exception:
                self.logger.warning("Failed to save partial capture after interrupt.")
            return 0