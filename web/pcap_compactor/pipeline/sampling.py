"""
Binomial sampling for HTTP URI tokens.

Goal:
- Keep semantic signal while bounding token count.
- Always keep a small security-critical lexicon.
- Apply simple binomial sampling to the rest with probability p so that
  the expected number of kept tokens ≈ budget.

Public API:
- apply_http_binomial_sampling(agg, budget, always_keep) -> bool
"""

from __future__ import annotations

import random
from typing import Iterable, List, Set

from ..dto import GroupAggregate


def apply_http_binomial_sampling(
    agg: GroupAggregate, *, budget: int = 40, always_keep: Iterable[str] = ()
) -> bool:
    """
    In-place binomial sampling of agg.http_uri_tokens.

    Parameters
    ----------
    agg : GroupAggregate
        Aggregate potentially containing `http_uri_tokens`.
    budget : int
        Target cap for number of tokens kept (approximate expectation).
    always_keep : Iterable[str]
        Tokens that must be preserved regardless of sampling.

    Returns
    -------
    bool
        True if sampling logic was applied (tokens present and sampling performed),
        False otherwise.
    """
    tokens = agg.http_uri_tokens
    if not tokens or budget <= 0:
        return False

    ak_set: Set[str] = set(always_keep)
    if not ak_set:
        ak_set = set()

    # Partition tokens into always-keep and others (preserve original order)
    ak_tokens: List[str] = []
    other_tokens: List[str] = []
    for t in tokens:
        (ak_tokens if t in ak_set else other_tokens).append(t)

    # If we're already within budget, keep as-is.
    if len(tokens) <= budget:
        return False

    # Compute sampling probability for "other" tokens to meet expected budget.
    remaining_budget = max(0, budget - len(ak_tokens))
    if len(other_tokens) == 0:
        # Only always-keep tokens exist; enforce hard cap if needed.
        agg.http_uri_tokens = ak_tokens[:budget]
        return True

    p = min(1.0, float(remaining_budget) / float(len(other_tokens))) if remaining_budget > 0 else 0.0

    sampled: List[str] = []
    if p >= 1.0:
        sampled = list(other_tokens)
    elif p <= 0.0:
        sampled = []
    else:
        # Binomial draw per token, stable order
        for t in other_tokens:
            if random.random() < p:
                sampled.append(t)

    # Merge: always-keep first (in original order), then sampled others.
    combined = ak_tokens + sampled

    # Enforce a hard cap just in case randomness overshoots marginally.
    if len(combined) > budget:
        combined = combined[:budget]

    agg.http_uri_tokens = combined
    return True