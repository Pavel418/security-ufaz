"""
Scan handling: rule gate + Isolation Forest split.

Responsibilities (minimal):
- Track per-source fan-out within the hour (unique destinations/ports).
- Compute a single discriminative feature: syn_only_ratio.
- Identify scan-candidates via a simple rule (> threshold unique destinations).
- Split candidates into:
    * repetitive probes (to be collapsed into ScanSummary)
    * outliers (kept for full enrichment/emission)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Set, Tuple

from sklearn.ensemble import IsolationForest  # type: ignore

from ..dto import PacketRecord, ScanSummary
from .grouping import GroupKey

_TCP_SYN = 0x02
_TCP_ACK = 0x10


@dataclass
class _SourceStats:
    unique_dsts: Set[str]
    unique_ports: Set[int]
    # For syn_only_ratio: SYN-without-ACK packets vs total TCP packets
    syn_only_pkts: int
    tcp_pkts: int
    # Keep a small sample of (dst, port) pairs for summary
    sample_targets: List[Tuple[str, int]]


class ScanGate:
    """
    Maintains per-source fan-out statistics and performs the scan split.

    Usage:
        gate = ScanGate(...)
        gate.observe_packet(pkt, key)
        candidates = gate.candidates()
        repetitive, outliers = gate.split_repetitive_vs_outliers()
    """

    def __init__(
        self,
        *,
        threshold_unique_dsts: int = 50,
        iforest_contamination: float = 0.14,
        iforest_estimators: int = 256,
        iforest_random_state: int | None = 42,
        sample_targets_cap: int = 20,
    ) -> None:
        self._threshold = int(threshold_unique_dsts)
        self._cont = float(iforest_contamination)
        self._n_estimators = int(iforest_estimators)
        self._random_state = iforest_random_state
        self._sample_cap = int(sample_targets_cap)
        self._by_src: Dict[str, _SourceStats] = {}

    # --- observation ---

    def observe_packet(self, pkt: PacketRecord, key: GroupKey) -> None:
        """Update per-source stats with a single packet."""
        src = key.src_ip  # observe by source (attacker perspective)
        s = self._by_src.get(src)
        if s is None:
            s = _SourceStats(unique_dsts=set(), unique_ports=set(), syn_only_pkts=0, tcp_pkts=0, sample_targets=[])
            self._by_src[src] = s

        # fan-out
        s.unique_dsts.add(key.dst_ip)
        s.unique_ports.add(int(key.dst_port))
        if len(s.sample_targets) < self._sample_cap:
            s.sample_targets.append((key.dst_ip, int(key.dst_port)))

        # SYN-only ratio (SYN set and ACK not set)
        if pkt.tcp_flags is not None:
            s.tcp_pkts += 1
            flags = int(pkt.tcp_flags)
            if (flags & _TCP_SYN) and not (flags & _TCP_ACK):
                s.syn_only_pkts += 1

    # --- candidate selection ---

    def candidates(self) -> List[str]:
        """Return source IPs that exceed the unique destination threshold."""
        out: List[str] = []
        for src, s in self._by_src.items():
            if len(s.unique_dsts) > self._threshold:
                out.append(src)
        return out

    # --- split: repetitive vs outliers ---

    def split_repetitive_vs_outliers(self) -> Tuple["RepetitiveSet", Set[str]]:
        """
        Run Isolation Forest on syn_only_ratio for scan-candidates.

        Returns
        -------
        repetitive : RepetitiveSet
            Iterable of ScanSummary for sources considered 'repetitive probes'.
            Also exposes .source_ips for quick membership tests.
        outlier_sources : Set[str]
            Source IPs considered outliers (kept for full processing).
        """
        cands = self.candidates()
        if not cands:
            return RepetitiveSet([], set()), set()

        # Build feature vector: syn_only_ratio per candidate
        X = []
        sources: List[str] = []
        ratios: Dict[str, float] = {}
        for src in cands:
            s = self._by_src[src]
            ratio = float(s.syn_only_pkts) / float(s.tcp_pkts) if s.tcp_pkts > 0 else 0.0
            ratios[src] = ratio
            X.append([ratio])
            sources.append(src)

        # If too few points for IF to be meaningful, treat all as outliers
        if len(X) < 3:
            return RepetitiveSet([], set()), set(sources)

        iforest = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._cont,
            random_state=self._random_state,
        )
        labels = iforest.fit_predict(X)  # 1 = inlier (repetitive), -1 = outlier (interesting)

        repetitive_summaries: List[ScanSummary] = []
        repetitive_sources: Set[str] = set()
        outliers: Set[str] = set()

        for src, lbl in zip(sources, labels):
            s = self._by_src[src]
            if lbl == 1:
                repetitive_sources.add(src)
                repetitive_summaries.append(
                    ScanSummary(
                        src_ip=src,
                        window=(0, 0),  # window is filled by orchestrator if desired; not essential here
                        unique_dsts=len(s.unique_dsts),
                        unique_ports=len(s.unique_ports),
                        syn_only_ratio=ratios[src],
                        sample_targets=list(s.sample_targets),
                    )
                )
            else:
                outliers.add(src)

        return RepetitiveSet(repetitive_summaries, repetitive_sources), outliers


class RepetitiveSet:
    """
    Container returned by split_repetitive_vs_outliers() that is:
    - Iterable over ScanSummary (so you can `for summary in repetitive:`)
    - Also exposes `.source_ips` (set) for quick membership tests.
    """

    def __init__(self, summaries: List[ScanSummary], source_ips: Set[str]) -> None:
        self._summaries = summaries
        self.source_ips = source_ips

    def __iter__(self) -> Iterable[ScanSummary]:
        return iter(self._summaries)

    def __len__(self) -> int:
        return len(self._summaries)