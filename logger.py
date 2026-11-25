# logger.py
"""
Session logging - produces both a structured JSON log and a human-readable
plaintext summary for each simulation session, written to ./output/.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

JSON_LOG_PATH = Path("./output/ranmimic_log.json")
PLAINTEXT_LOG_PATH = Path("./output/ranmimic_report.txt")


def start_session(mode: str, target: str) -> dict:
    """
    Called at the start of main.py's run. Returns the initial run_log dict
    that gets passed through simulator.run(), scorer.score_session(), and
    ioc_gen.generate_ioc_report() — each adds its own fields to it.
    """
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "target": target,
    }


def finalize_session(run_log: dict) -> None:
    """
    Called in main.py's finally block, after the simulation (and scoring/
    IOC steps, if they ran successfully) are complete. Writes both JSON and
    plaintext logs. Safe to call even on a partially-populated run_log
    (e.g. if an exception occurred mid-run) — uses .get() with defaults
    throughout so a missing field doesn't crash logging itself.
    """
    run_log["finalized_at"] = datetime.now(timezone.utc).isoformat()

    _write_json_log(run_log)
    _write_plaintext_log(run_log)


def _write_json_log(run_log: dict) -> None:
    JSON_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    # results/before_snapshots/after_snapshots can contain Path objects as
    # dict keys, which json.dumps can't serialize directly — convert keys
    # to strings for the JSON log. The in-memory run_log itself is left
    # untouched (scorer.py etc. have already consumed what they need by
    # this point, since finalize_session runs last).
    serializable = _make_json_safe(run_log)

    JSON_LOG_PATH.write_text(json.dumps(serializable, indent=2))


def _make_json_safe(obj):
    """Recursively converts Path keys/values and other non-JSON types to strings."""
    if isinstance(obj, dict):
        return {str(k): _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_make_json_safe(v) for v in obj]
    if hasattr(obj, "_fspath_"):  # Path-like objects
        return str(obj)
    return obj


def _write_plaintext_log(run_log: dict) -> None:
    lines = []
    lines.append("=" * 60)
    lines.append("RANMIMIC - SESSION LOG")
    lines.append("=" * 60)
    lines.append(f"Started:          {run_log.get('started_at', 'unknown')}")
    lines.append(f"Finalized:        {run_log.get('finalized_at', 'unknown')}")
    lines.append(f"Mode:             {run_log.get('mode', 'unknown')}")
    lines.append(f"Target:           {run_log.get('target', 'unknown')}")
    lines.append("")
    lines.append(f"Files total:      {run_log.get('files_total', 'n/a')}")
    lines.append(f"Files affected:   {run_log.get('files_affected', 'n/a')}")
    lines.append(f"Files per sec:    {run_log.get('files_per_sec', 'n/a')}")
    lines.append(f"Ransom note:      {'YES' if run_log.get('note_dropped') else 'no'}")
    lines.append("=" * 60)

    PLAINTEXT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    PLAINTEXT_LOG_PATH.write_text("\n".join(lines))