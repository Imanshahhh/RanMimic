# main.py
"""
RanMimic - Ransomware Behavior Simulator
Educational tool for validating detection capabilities (AV/EDR/monitoring).
Operates ONLY within a sandboxed directory structure. See README.md for
Rules of Engagement and ethical guardrails.
"""

import argparse
import sys
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

import killswitch
import sandbox
import simulator
import ioc_gen
import logger as ranmimic_logger

console = Console()

DEFAULT_SANDBOX = Path("./sandbox").resolve()
BLOCKED_HINTS = ["windows", "system32", "/etc", "/home", "c:\\users", "/root"]

LEGAL_BANNER = """
[bold red]RANMIMIC - RANSOMWARE BEHAVIOR SIMULATOR[/bold red]
[yellow]FOR AUTHORIZED EDUCATIONAL / DEFENSIVE TESTING USE ONLY[/yellow]

This tool simulates ransomware-pattern file system behavior for the purpose
of validating security monitoring and detection capabilities.

Under the Computer Crimes Act 1997 (Malaysia) and equivalent legislation,
unauthorized access to or modification of computer material is a criminal
offence. By proceeding, you confirm that:

  1. You own, or have EXPLICIT WRITTEN AUTHORIZATION to test, the target
     directory.
  2. The target directory contains no real/production data.
  3. You understand this tool's actions are logged and auditable.
  4. You accept full responsibility for its use.

This tool will NOT run without your explicit confirmation below.
"""


def show_legal_banner() -> bool:
    console.print(Panel(LEGAL_BANNER, border_style="red"))
    response = console.input(
        "\n[bold]Type [green]I AGREE[/green] to proceed, or anything else to abort:[/bold] "
    )
    if response.strip() != "I AGREE":
        console.print("[red]Confirmation not received. Aborting.[/red]")
        return False
    return True


def validate_scope(target: Path) -> bool:
    """
    Default-safe scope enforcement: ./sandbox/ is allowed automatically.
    Anything else requires an explicit typed CONFIRM, and is still rejected
    outright if it matches an obvious system-path pattern.
    """
    resolved = target.resolve()

    lowered = str(resolved).lower()
    if any(hint in lowered for hint in BLOCKED_HINTS):
        console.print(
            f"[bold red]REFUSED:[/bold red] '{resolved}' matches a protected "
            f"system path pattern. RanMimic will not operate here under any "
            f"confirmation."
        )
        return False

    if resolved == DEFAULT_SANDBOX:
        return True  # safe default, no extra prompt needed

    console.print(
        f"[yellow]Non-default target requested: {resolved}[/yellow]"
    )
    response = console.input(
        "[bold]Type CONFIRM to proceed against this non-default path:[/bold] "
    )
    if response.strip() != "CONFIRM":
        console.print("[red]Scope not confirmed. Aborting.[/red]")
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ranmimic",
        description="RanMimic - Ransomware Behavior Simulator (educational/sandboxed use only)",
        epilog="Examples:\n"
               "  python main.py --mode ransomware\n"
               "  python main.py --mode benign --dry-run\n"
               "  python main.py --restore\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["benign", "partial", "ransomware"],
        default="ransomware",
        help="Behavior mode to simulate (default: ransomware)",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=str(DEFAULT_SANDBOX),
        help="Target directory (default: ./sandbox/). Non-default paths require confirmation.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without modifying any files.",
    )
    parser.add_argument(
        "--restore",
        action="store_true",
        help="Restore files from a previous run using your recovery password.",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible test runs (e.g. --seed 42). Omit for real randomness.",
    )

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    killswitch.register(on_abort=lambda: handle_abort(args))

    if not show_legal_banner():
        sys.exit(1)

    target = Path(args.target)

    if args.restore:
        sandbox.restore_session(target)
        console.print("[green]Restore complete. Exiting.[/green]")
        return

    if not validate_scope(target):
        sys.exit(1)

    if args.dry_run:
        console.print(
            Panel(
                f"[bold]DRY RUN[/bold]\n"
                f"Mode: {args.mode}\n"
                f"Target: {target.resolve()}\n"
                f"No files will be created, encrypted, or modified.",
                border_style="cyan",
            )
        )
        return

    run_log = ranmimic_logger.start_session(mode=args.mode, target=str(target.resolve()))

    try:
        sandbox.prepare(target, seed=args.seed)
        run_log = simulator.run(target, mode=args.mode, run_log=run_log)

        import scorer
        breakdown = scorer.score_session(
            before_snapshots=run_log["before_snapshots"],
            after_snapshots=run_log["after_snapshots"],
            renamed_files=[r for r in run_log["results"] if r["renamed"]],
            note_dropped=run_log["note_dropped"],
            files_per_sec=run_log["files_per_sec"],
            total_files=run_log["files_total"],
        )
        scorer.print_report(breakdown)

        ioc_gen.generate_ioc_report(run_log, breakdown)
        console.print(f"[dim]IOC report written to ./output/ioc_report.txt[/dim]")

    except KeyboardInterrupt:
        handle_abort(args)
    finally:
        ranmimic_logger.finalize_session(run_log)


def handle_abort(args):
    console.print("\n[bold red]Abort signal received. Auto-restoring sandbox...[/bold red]")
    sandbox.restore_session(Path(args.target))
    console.print("[green]Sandbox restored. Clean exit.[/green]")
    sys.exit(0)


if __name__ == "__main__":
    main()