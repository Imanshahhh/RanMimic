
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

IOC_REPORT_PATH = Path("./output/ioc_report.txt")
IOC_REPORT_JSON_PATH = Path("./output/ioc_report.json")


def _hash_file(filepath: Path) -> dict:
    """Returns MD5 and SHA256 hashes for a file - standard IOC fields."""
    try:
        data = filepath.read_bytes()
    except (FileNotFoundError, PermissionError):
        return {"md5": None, "sha256": None}

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def generate_ioc_report(run_log: dict, breakdown) -> dict:
    """
    Builds the IOC report structure from the completed run_log and
    scorer.ScoreBreakdown. Writes both a JSON and plaintext version to
    ./output/, and returns the dict for programmatic use/testing.
    """
    affected_results = run_log.get("results", [])
    renamed = [r for r in affected_results if r["renamed"]]

    extensions_changed = sorted({
        Path(r["current"]).suffix for r in renamed
    })

    file_hashes = []
    for r in affected_results:
        current_path = Path(r["current"])
        if current_path.exists():
            hashes = _hash_file(current_path)
            file_hashes.append({
                "file": str(current_path),
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
            })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": run_log.get("mode"),
        "target": run_log.get("target", "unknown"),
        "summary": {
            "total_files": run_log.get("files_total", 0),
            "files_affected": run_log.get("files_affected", 0),
            "files_renamed": len(renamed),
            "extensions_observed": extensions_changed,
            "ransom_note_dropped": run_log.get("note_dropped", False),
            "files_per_second": run_log.get("files_per_sec", 0.0),
        },
        "risk_assessment": {
            "total_score": breakdown.total,
            "risk_band": breakdown.risk_band,
            "signal_breakdown": {
                "rename_points": breakdown.rename_points,
                "entropy_points": breakdown.entropy_points,
                "chi_square_points": breakdown.chi_square_points,
                "note_points": breakdown.note_points,
                "speed_points": breakdown.speed_points,
            },
            "raw_signals": breakdown.raw_signals,
        },
        "file_hashes": file_hashes,
    }

    _write_json(report)
    _write_plaintext(report)
    return report


def _write_json(report: dict) -> None:
    IOC_REPORT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    IOC_REPORT_JSON_PATH.write_text(json.dumps(report, indent=2))


def _write_plaintext(report: dict) -> None:
    lines = []
    lines.append("=" * 60)
    lines.append("RANMIMIC - IOC / DETECTION REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated:        {report['generated_at']}")
    lines.append(f"Mode:             {report['mode']}")
    lines.append(f"Target:           {report['target']}")
    lines.append("")
    lines.append("-- SUMMARY --")
    s = report["summary"]
    lines.append(f"Total files:      {s['total_files']}")
    lines.append(f"Files affected:   {s['files_affected']}")
    lines.append(f"Files renamed:    {s['files_renamed']}")
    lines.append(f"Extensions seen:  {', '.join(s['extensions_observed']) or 'none'}")
    lines.append(f"Ransom note:      {'YES' if s['ransom_note_dropped'] else 'no'}")
    lines.append(f"Speed (files/s):  {s['files_per_second']}")
    lines.append("")
    lines.append("-- RISK ASSESSMENT --")
    r = report["risk_assessment"]
    lines.append(f"Total score:      {r['total_score']}/100")
    lines.append(f"Risk band:        {r['risk_band']}")
    lines.append("Signal breakdown:")
    for k, v in r["signal_breakdown"].items():
        lines.append(f"  {k:20s} {v}")
    lines.append("")
    lines.append("-- FILE HASHES (first 10 shown) --")
    for entry in report["file_hashes"][:10]:
        lines.append(f"  {entry['file']}")
        lines.append(f"    MD5:    {entry['md5']}")
        lines.append(f"    SHA256: {entry['sha256']}")
    if len(report["file_hashes"]) > 10:
        lines.append(f"  ... and {len(report['file_hashes']) - 10} more (see ioc_report.json)")
    lines.append("=" * 60)

    IOC_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    IOC_REPORT_PATH.write_text("\n".join(lines))