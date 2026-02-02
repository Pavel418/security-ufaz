# README

## What this project does

Analyzes security log files with a multi-step LLM workflow to infer likely MITRE ATT&CK techniques, score their relevance/impact, and produce a clean, validated summary per input.

## How it works (high level)

1. **Discover & parse inputs**: Load all `*.txt` files, each containing a single JSON log payload.
2. **Context extraction**: Use an LLM to summarize the environment, activity, and anomalies from the raw log.
3. **Technique mapping**: Run multiple “expert” prompts in parallel to propose ATT&CK technique+tactic candidates; score and consolidate to a single JSON list.
4. **Validation & synthesis**: Cross-check candidates against MITRE metadata (technique names, allowed tactics), then ask the LLM to refine and normalize results.
5. **Ranking & output**: Normalize `relevance` and `impact`, compute a combined `score`, sort, and write a structured JSON report per input (with step timings and token usage).

## Inputs

* Folder of `*.txt` files; each file contains one JSON object representing a log record or event.

## Outputs

* One JSON result per input with:

  * Final ranked techniques (technique ID, tactic, justification, relevance, impact, score)
  * Any validation notes (e.g., unknown technique, tactic mismatch)
  * Lightweight telemetry (durations, token counts)

## Key behaviors

* Robust JSON parsing and recovery of imperfect LLM outputs
* Parallel “experts” for breadth + scoring for consistency
* Idempotent/resumable processing across runs