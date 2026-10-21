# CastorPollux

<img src="work/assets/castorpollux-gemini.png" alt="Castor and Pollux Gemini mark" width="160">

CastorPollux is a Windows desktop workbench for investigating binaries. It runs Ghidra and REA to collect disassembly, functions, cross-references, and reconstructed C-like pseudocode, then can ask an installed Codex, Claude Code, OpenCode, or local Ollama agent to review the saved evidence for possible vulnerabilities. Its output includes searchable evidence, coverage, logs, structured findings, and reports.

## What it does

1. **Analyze:** Choose a binary and output folder. CastorPollux verifies and copies the input, runs Ghidra headless exports, asks REA to analyze and decompile procedures through its Ghidra provider, and saves `rea-pseudocode.c`, `rea-decompilation.json`, a snapshot, supplemental exports, a Ghidra project, logs, and `manifest.json`.
2. **Inspect:** Search functions, strings, imports, calls, cross-references, and reconstructed code in the GUI. REA Actions gives direct buttons for overview, search, decompilation, instructions, references, and traces. Coverage shows which procedures succeeded or failed and a heuristic confidence label. History reopens and resumes jobs.
3. **Review:** Use **Analyze → Agent Review** or review a saved investigation. The app scopes and stages text evidence for the selected agent, shows live output, and saves findings with exact citations and a decompilation coverage warning when appropriate. It asks the agent to examine privilege escalation, buffer overflow, command injection, and other evidence-backed risks. Findings include root cause, data flow, counter-evidence, prerequisites, impact, remediation, validation guidance, explicit confidence reasons, bounded reconstructed-code excerpts, per-finding static call-path images, and a saved analyst confirmation checklist.
4. **Validate leads:** When enough evidence exists, an agent can suggest a bounded local Python proof-of-concept candidate. CastorPollux checks its syntax and includes it in Findings and report exports. Valid Python text is also saved under `proofs-of-concept/`. **CastorPollux never runs or verifies candidate scripts.** A candidate is a review aid, not proof of a vulnerability.
5. **Export:** JSON, Markdown, HTML, CSV, PDF, and SARIF reports; verified investigation bundles; batch/CI summaries. Findings can be triaged, suppressed with expiry, compared across builds, and checked against a known-answer corpus.
6. **Inspect third-party leads:** Open Libraries & CVEs to see saved binary fingerprints and opt in to exact-version NVD CPE lookups. Confirm library inclusion and advisory applicability manually.

REA/Ghidra output is *reconstructed pseudocode*, not the original source. Missing code, guessed types, and decompiler errors can affect every conclusion. The Windows Sandbox runtime trace feature is **UNTESTED** in this build.

Coverage exports `source-map.csv` and `source-map.json`: saved pseudocode line ranges mapped to procedure addresses and available Ghidra symbols. The current export does not contain original source-file line numbers.

## Install and first run

When a release is published, download `CastorPollux.exe` and `CastorPollux-SHA256.txt` from its **GitHub Release**. Check the digest in PowerShell:

```powershell
(Get-FileHash .\CastorPollux.exe -Algorithm SHA256).Hash
Get-Content .\CastorPollux-SHA256.txt
```

Run the EXE and allow time for first-launch extraction. Choose a test binary you are authorized to inspect and an existing output folder. For a combined run, select an installed/authenticated agent on Agent Review, review the evidence preview and report formats, then click **Analyze → Agent Review**. Agent access and any cloud data transfer depend on the selected CLI; the original binary and Ghidra project are not staged for cloud review. Use local Ollama if its separate installation and model are suitable for sensitive evidence.

If `ghidra_status` is `failed`, open **History → LOGS → ghidra.log** and inspect `manifest.json` for `ghidra_exit_code`, `ghidra_exports`, and `ghidra_failure_reason`. Fix the logged cause and use **RESUME**. REA decompilation is recorded separately; check Coverage and `rea-pseudocode.c` before assuming no code was reconstructed.

## Repository guide

| Document | Contents |
|---|---|
| [In-app help](docs/HELP.html) and [full guide](docs/HELP.md) | Task-focused examples in HTML and detailed reference guidance |
| [In-app About](docs/ABOUT.html) and [architecture](docs/ABOUT.md) | Purpose, pipeline, limitations, privacy, optional features |
| [Related tools](docs/ALTERNATIVES.md) | Ghidra, BinDiff, Binary Ninja and IDA overlap |
| [Build from source](docs/BUILD.md) | Required tools, pinned upstream inputs, exact release layout |
| [Publish to GitHub](docs/GITHUB_PUBLISHING.md) | Safe source push and separate release asset upload |
| [Release notes](docs/RELEASE_NOTES.md) | Current changes and verification |
| [Credits and notices](third_party/CREDITS.md) | Upstream projects and license locations |
| [Commercial license audit](docs/COMMERCIAL_LICENSE_AUDIT.md) | Outstanding third-party redistribution obligations |

Application source, build scripts, bundled About content, editable Help content, and focused tests live in `work/`. `outputs/` holds the release document templates required by the build script. Downloaded engine archives, runtime trees, investigations, and built EXEs are intentionally absent from Git. See [BUILD.md](docs/BUILD.md).

