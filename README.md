# RanMimic — Ransomware Behavior Simulator

**Category:** 7 — Malware (Behavior Sandbox Runner)
**Language:** Python 3.10+

## Objective

Simulate ransomware file-system behavior inside a controlled sandbox, with variable attack modes, to help defenders validate whether their security tools (AV, EDR, monitoring) can distinguish real ransomware-pattern activity from benign file churn.

## Legal Notice

This tool is intended **strictly for use in a controlled, isolated lab environment** by the project author for academic purposes under UniKL MIIT IDB301. Running this tool against any file system without explicit authorization is illegal under the **Computer Crimes Act 1997 (Malaysia)** and equivalent laws elsewhere. On startup, the tool displays a legal disclaimer and requires the user to type `I AGREE` before any operation proceeds.

## Tools Used

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.10+ | Core programming language |
| VS Code | Latest | Code editor |
| Git | Latest | Version control |
| GitHub | — | Public repository hosting |
| pip | Latest | Python dependency manager |
| Windows 10/11 | — | Development and demo environment |

## Dependencies (`requirements.txt`)

```
cryptography>=41.0.0
scipy>=1.11.0
rich>=13.0.0
```

## Project Structure

```
RanMimic/
├── main.py
├── sandbox.py
├── simulator.py
├── entropy.py
├── scorer.py
├── ioc_gen.py
├── logger.py
├── killswitch.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── sandbox/          ← auto-created, dummy files live here
└── output/           ← auto-created, logs and reports saved here
    ├── ranmimic_log.json
    ├── ranmimic_report.txt
    ├── ioc_report.txt
    └── salt.bin
```

| File | Purpose |
|---|---|
| `main.py` | Entry point, CLI, legal banner, CCA confirmation, scope confirmation |
| `sandbox.py` | Create and restore dummy victim files |
| `simulator.py` | AES encryption, mass rename, mock ransom note, threaded ops, mode-based behavior variation |
| `entropy.py` | Shannon entropy + Chi-Square calculator, before/after delta |
| `scorer.py` | Behavioral scoring engine (weighted, discriminative), risk rating output |
| `ioc_gen.py` | IOC and detection report generator |
| `logger.py` | Timestamped action log, JSON + plaintext output |
| `killswitch.py` | Ctrl+C handler, auto-restore on abort |

## How It Works

1. **Legal banner + CCA 1997 confirmation** — user must type `I AGREE` to proceed.
2. **Scope check** — defaults to `./sandbox/` (proceeds automatically); any `--target` outside the sandbox requires typing `CONFIRM`.
3. **Mode selection** (`--mode`):
   - `ransomware` — full attack pattern (encrypt all, rename all, drop note, high speed)
   - `partial` — encrypts/renames a subset of files, variable speed (early-stage detection scenario)
   - `benign` — touches/rewrites files without encryption or renaming (false-positive-prone backup/sync activity)
4. **Recovery password** set by the user; PBKDF2-HMAC-SHA256 (600,000 iterations) derives an AES-256 key from the password + random salt. Salt saved to `./output/salt.bin`.
5. **Dummy victim files** created in the sandbox (`.txt`, `.docx`, `.jpg`, `.pdf` with random content).
6. **Entropy + Chi-Square measured** before the simulation.
7. **Simulation runs** (threaded), shaped by the selected mode (encryption, renaming, ransom note — see mode table above). Shadow copy deletion is logged only, never executed.
8. **Entropy + Chi-Square measured again**; delta calculated per file.
9. **Behavioral scoring engine** runs (weighted, mode-agnostic):
   - % of files renamed → up to 20 pts
   - Mean entropy delta > threshold → up to 25 pts
   - Chi-square distribution shift → up to 20 pts
   - Ransom note present → +20 pts flat
   - File ops/sec > baseline → up to 15 pts
   - Outputs Risk Score: XX/100 with a risk band (Low/Medium/High/Critical)
10. **IOC report generated** (`./output/ioc_report.txt`) — file extensions changed, entropy thresholds, note filename, file hashes (MD5, SHA256).
11. **JSON + plaintext log saved** to `./output/`.
12. **Restore option** — re-enter password, key rederived from password + salt, files decrypted and renamed back, ransom note removed, salt deleted.

## Why the Mode System Matters

A scorer that scores every run ~100/100 isn't measuring anything — it's a checklist that always passes because the simulator and scorer are colluding. By running `benign`, `partial`, and `ransomware` modes and scoring all three with the same engine, RanMimic demonstrates that the scorer actually discriminates real ransomware-pattern behavior from ordinary file churn. This is also the strongest "original algorithm" evidence for the report: a small table of scores across modes is proof the engine works, not just an assertion that it does.

## Attack Lifecycle Mapping (MITRE ATT&CK)

| Phase | ATT&CK Technique | What RanMimic Does |
|---|---|---|
| Discovery | T1083 (File and Directory Discovery) | Scans sandbox, counts and categorizes dummy files |
| Resource Development | — | Derives AES-256 key via PBKDF2, generates random salt |
| Execution | T1106 (Native API) / threaded ops | Encrypts files, renames to `.locked`, drops mock note |
| Impact | T1486 (Data Encrypted for Impact) | Core simulated behavior, scored by the engine |
| Impact (logged only) | T1490 (Inhibit System Recovery) | Shadow copy deletion — logged, never executed |
| Recovery | — | Restores all files using password + salt, deletes artifacts |

## Key Technical Features

| Feature | Detail |
|---|---|
| Encryption | AES-256-CBC via `cryptography` library |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt |
| Entropy analysis | Shannon entropy + Chi-Square on each file before and after |
| Behavioral scoring | Weighted, proportionally-scaled score; mode-blind design for discriminative validity |
| IOC generation | Extension list, entropy thresholds, note filename, MD5 + SHA256 hashes |
| Threading | `concurrent.futures.ThreadPoolExecutor` for parallel file ops |
| Scope enforcement | Default-safe (`./sandbox/`), explicit confirm required to escalate scope |
| Output | JSON log + plaintext report saved to `./output/` |

## CLI Usage

```bash
# Default run — uses ./sandbox/, ransomware mode
python main.py

# Select a behavior mode
python main.py --mode benign
python main.py --mode partial
python main.py --mode ransomware

# Custom target folder (requires explicit CONFIRM prompt)
python main.py --target "C:\TestFolder"

# Dry run — shows what would happen without doing it
python main.py --dry-run

# Restore mode — decrypt and restore all files
python main.py --restore

# Help
python main.py --help
```

## Ethical Guardrails

| Requirement | Implementation |
|---|---|
| Legal disclaimer | Startup banner cites Computer Crimes Act 1997 (Malaysia) |
| Authorization | User must type `I AGREE` before any operation |
| Safe defaults | Defaults to `./sandbox/`; non-default targets require typed `CONFIRM` |
| Scope enforcement | Default-allow only for `./sandbox/`; everything else gated, not blocklisted |
| Kill switch | Ctrl+C triggers auto-restore and clean exit via signal handler |
| Data handling | No network calls, all output local to `./output/` only |
| Shadow copy | Logged only, never executed |
| Dry run | `--dry-run` flag shows simulation plan without touching files |
| Responsible disclosure | See below |

## Responsible Disclosure

If you discover a vulnerability or misuse potential in this tool itself, please report it via [GitHub Security Advisory](../../security/advisories) on this repository, or contact the author directly at [your contact email].

## Limitations

- Simulates file-system behavior only — not process injection or memory techniques
- Cannot test network-based C2 detection
- Shadow copy deletion is logged only, never executed
- Scoring thresholds are heuristic, not trained on a labeled dataset — future work could calibrate against real sample telemetry
- Designed for controlled lab environments only
- Tested on Windows 10/11

## License

MIT License — see [LICENSE](./LICENSE) for details.