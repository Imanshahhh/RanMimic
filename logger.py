# logger.py
"""
Session logging - timestamped JSON + plaintext output.
STUB VERSION — minimal implementation to unblock testing.
Full version (commit #7) will add proper file output.
"""

from datetime import datetime, timezone


def start_session(mode: str, target: str) -> dict:
    return {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "target": target,
    }


def finalize_session(run_log: dict) -> None:
    # STUB — real version will write run_log to ./output/ranmimic_log.json
    # and a plaintext summary, per the project spec.
    print(f"[logger] Session finalized (stub — no file written yet): {run_log.get('mode')}")