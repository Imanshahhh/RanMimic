# scorer.py
"""
Behavioral scoring engine - takes raw signals from entropy.py (entropy
delta, chi-square shift), simulator.py (rename count, files/sec, note
presence) and produces a weighted risk score.

Design principle: this module receives signals, not the mode that
produced them. It must discriminate ransomware-pattern behavior from
benign file churn using only what a real detection tool would observe
on disk — it never "knows" which --mode flag was used. This is what
makes the score meaningful rather than a fixed checklist.
"""

from dataclasses import dataclass, field
from pathlib import Path

import entropy

# ---------------------------------------------------------------------------
# Weight configuration - each signal contributes up to its max, SCALED by
# how strongly it was observed, not as a flat all-or-nothing bonus.
# ---------------------------------------------------------------------------
WEIGHTS = {
    "rename_ratio": 20,      # proportion of files renamed with suspicious extension
    "entropy_delta": 25,     # mean entropy increase across affected files
    "chi_square_shift": 20,  # mean shift toward uniform distribution
    "ransom_note": 20,       # flat bonus - presence is a near-certain signal
    "file_speed": 15,        # files/sec relative to a baseline
}

# Calibration constants - tuned against expected AES-256-CBC behavior.
# Encrypted data approaches ~8.0 bits/byte entropy; typical office/image
# files sit in the 3.5-7.5 range depending on compression already present.
ENTROPY_DELTA_SATURATION = 3.0   # delta at/above this = full 25 pts
SPEED_BASELINE_FILES_PER_SEC = 10.0  # at/above this = full 15 pts

RISK_BANDS = [
    (85, 100, "CRITICAL"),
    (60, 84, "HIGH"),
    (30, 59, "MEDIUM"),
    (0, 29, "LOW"),
]


@dataclass
class ScoreBreakdown:
    rename_points: float = 0.0
    entropy_points: float = 0.0
    chi_square_points: float = 0.0
    note_points: float = 0.0
    speed_points: float = 0.0
    total: float = 0.0
    risk_band: str = "LOW"
    raw_signals: dict = field(default_factory=dict)


def _scale(value: float, saturation: float, max_points: float) -> float:
    """
    Linear scaling capped at max_points once value reaches saturation.
    This is the core mechanism that makes scoring proportional instead
    of binary (">threshold ? full_points : 0").
    """
    if saturation <= 0:
        return 0.0
    ratio = min(max(value / saturation, 0.0), 1.0)
    return ratio * max_points


def _risk_band(total: float) -> str:
    for low, high, label in RISK_BANDS:
        if low <= total <= high:
            return label
    return "UNKNOWN"


def score_session(
    before_snapshots: dict,
    after_snapshots: dict,
    renamed_files: list[dict],
    note_dropped: bool,
    files_per_sec: float,
    total_files: int,
) -> ScoreBreakdown:
    """
    Main scoring entry point. Takes raw observable signals (not the mode
    that produced them) and returns a weighted breakdown.

    before_snapshots / after_snapshots: {Path: entropy.analyze_file() result}
    dicts produced by simulator.run() — precomputed, not re-read from disk.
    renamed_files: from simulator's run_log results
    """
    entropy_deltas = []
    chi_square_shifts = []

    for path, before in before_snapshots.items():
        after = after_snapshots.get(path, {"entropy": None, "chi_square": None})
        delta = entropy.compute_delta(before, after)

        if delta["entropy_delta"] is not None and abs(delta["entropy_delta"]) > 0.01:
            entropy_deltas.append(delta["entropy_delta"])
        if delta["p_value_shift"] is not None and abs(delta["p_value_shift"]) > 0.0001:
            chi_square_shifts.append(delta["p_value_shift"])

    mean_entropy_delta = sum(entropy_deltas) / len(entropy_deltas) if entropy_deltas else 0.0
    mean_chi_shift = sum(chi_square_shifts) / len(chi_square_shifts) if chi_square_shifts else 0.0

    rename_ratio = len(renamed_files) / total_files if total_files else 0.0

    breakdown = ScoreBreakdown()
    breakdown.rename_points = _scale(rename_ratio, 1.0, WEIGHTS["rename_ratio"])
    breakdown.entropy_points = _scale(mean_entropy_delta, ENTROPY_DELTA_SATURATION, WEIGHTS["entropy_delta"])
    # chi-square shift: a POSITIVE shift (p-value increasing) = moving toward
    # uniform/random = more suspicious. Negative or near-zero shift scores 0.
    breakdown.chi_square_points = _scale(max(mean_chi_shift, 0.0), 0.5, WEIGHTS["chi_square_shift"])
    breakdown.note_points = WEIGHTS["ransom_note"] if note_dropped else 0.0
    breakdown.speed_points = _scale(files_per_sec, SPEED_BASELINE_FILES_PER_SEC, WEIGHTS["file_speed"])

    breakdown.total = round(
        breakdown.rename_points
        + breakdown.entropy_points
        + breakdown.chi_square_points
        + breakdown.note_points
        + breakdown.speed_points,
        2,
    )
    breakdown.risk_band = _risk_band(breakdown.total)

    breakdown.raw_signals = {
        "rename_ratio": round(rename_ratio, 3),
        "mean_entropy_delta": round(mean_entropy_delta, 3),
        "mean_chi_square_shift": round(mean_chi_shift, 5),
        "note_dropped": note_dropped,
        "files_per_sec": round(files_per_sec, 2),
    }

    return breakdown


def print_report(breakdown: ScoreBreakdown) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="RanMimic Behavioral Risk Score")

    table.add_column("Signal", style="cyan")
    table.add_column("Points", justify="right")
    table.add_column("Max", justify="right", style="dim")

    table.add_row("File rename ratio", f"{breakdown.rename_points:.1f}", str(WEIGHTS["rename_ratio"]))
    table.add_row("Entropy delta", f"{breakdown.entropy_points:.1f}", str(WEIGHTS["entropy_delta"]))
    table.add_row("Chi-square shift", f"{breakdown.chi_square_points:.1f}", str(WEIGHTS["chi_square_shift"]))
    table.add_row("Ransom note", f"{breakdown.note_points:.1f}", str(WEIGHTS["ransom_note"]))
    table.add_row("File ops speed", f"{breakdown.speed_points:.1f}", str(WEIGHTS["file_speed"]))

    console.print(table)
    console.print(f"\n[bold]Total Risk Score: {breakdown.total}/100 — {breakdown.risk_band}[/bold]")