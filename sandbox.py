# sandbox.py
"""
Sandbox management - creates dummy victim files for simulation, and
tracks enough session state to support full restore (whether triggered
normally, via --restore, or via the kill switch on Ctrl+C).
"""

import os
import json
import random
import string
from pathlib import Path
from datetime import datetime, timezone

SESSION_STATE_FILE = Path("./output/session_state.json")

DUMMY_FILE_TYPES = {
    ".txt": lambda: _random_text(2000),
    ".docx": lambda: _random_bytes(5000),   # not a real docx structure, just bytes for entropy purposes
    ".jpg": lambda: _random_bytes(8000),
    ".pdf": lambda: _random_bytes(6000),
}

DEFAULT_FILE_COUNT = 20


def _random_text(length: int) -> bytes:
    chars = string.ascii_letters + string.digits + " \n.,;:"
    return "".join(random.choice(chars) for _ in range(length)).encode("utf-8")


def _random_bytes(length: int) -> bytes:
    """
    Simulates realistic binary file content (docx/jpg/pdf) with moderate
    entropy (~6.5-7.0 bits/byte) rather than pure random noise (~8.0),
    since real compressed/structured binary files are not maximally random.
    """
    chunk = os.urandom(64)  # a repeating "structure" pattern
    repeats = (length // len(chunk)) + 1
    structured = (chunk * repeats)[:length]
    # mix in some genuine randomness so it's not perfectly repetitive either
    noise_portion = os.urandom(length // 4)
    result = bytearray(structured)
    for i, b in enumerate(noise_portion):
        result[i] = b
    return bytes(result)


def prepare(target: Path, file_count: int = DEFAULT_FILE_COUNT, seed: int = None) -> list[Path]:
    """
    Create the sandbox directory (if needed) and populate it with dummy
    victim files of varied types. Returns the list of created file paths.

    Idempotent-ish: if the sandbox already has files from a prior run that
    was never restored, this will NOT silently add to them — it refuses,
    to avoid corrupting a half-finished session's restore data.
    """
    target.mkdir(parents=True, exist_ok=True)

    if seed is not None:
        random.seed(seed)

    existing = [f for f in target.iterdir() if f.is_file()]
    if existing and SESSION_STATE_FILE.exists():
        raise RuntimeError(
            f"Sandbox at '{target}' already has an unrestored session "
            f"({len(existing)} files found, session_state.json present). "
            f"Run 'python main.py --restore' first before starting a new session."
        )
    # Clear any leftover files from a prior (already-restored) session
    # before generating a fresh set — prevents silent accumulation across runs.
    for f in existing:
        f.unlink()

    created = []
    for i in range(file_count):
        ext = random.choice(list(DUMMY_FILE_TYPES.keys()))
        filename = f"victim_file_{i:03d}{ext}"
        filepath = target / filename
        content = DUMMY_FILE_TYPES[ext]()
        filepath.write_bytes(content)
        created.append(filepath)

    _save_session_state(target, created)
    return created


def _save_session_state(target: Path, files: list[Path]) -> None:
    SESSION_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target.resolve()),
        "original_files": [str(f.resolve()) for f in files],
        "renamed_files": [],  # populated by simulator.py as it operates
        "restored": False,
    }
    SESSION_STATE_FILE.write_text(json.dumps(state, indent=2))


def load_session_state() -> dict | None:
    if not SESSION_STATE_FILE.exists():
        return None
    return json.loads(SESSION_STATE_FILE.read_text())


def update_session_state(**updates) -> None:
    state = load_session_state()
    if state is None:
        raise RuntimeError("No active session state found to update.")
    state.update(updates)
    SESSION_STATE_FILE.write_text(json.dumps(state, indent=2))


def restore_session(target: Path) -> None:
    """
    Reverses a simulation session: decrypts/renames files back (via
    simulator.restore, called from here to avoid a circular import issue
    at module load time) and clears session state.

    Safe to call even if no session is active — it will just report that
    there's nothing to restore, rather than erroring.
    """
    state = load_session_state()
    if state is None:
        print(f"[sandbox] No active session found for '{target}'. Nothing to restore.")
        return

    if state.get("restored"):
        print("[sandbox] Session already marked as restored. Nothing to do.")
        return

    # local import to avoid circular dependency: simulator imports sandbox too
    import simulator
    simulator.restore(state)

    update_session_state(restored=True)
    SESSION_STATE_FILE.unlink(missing_ok=True)
    print("[sandbox] Session state cleared. Restore complete.")