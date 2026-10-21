# About CastorPollux

CastorPollux is a Windows desktop application for investigating binaries and reviewing possible software vulnerabilities. It uses Ghidra and REA to reconstruct C-like pseudocode, save searchable evidence, and show how much of a binary was successfully decompiled. Its optional agent review examines that evidence for possible vulnerabilities and creates cited findings and reports.

The Analyze workspace shows scan status, stage progress, and an activity log. Investigations, Coverage, Evidence Lab, Graph Lab, Call Paths, Data Flow, Findings, Compare, and Dashboards help you inspect and validate results. History reopens saved work and preserves logs and retry attempts. Component health checks and settings show the state of analysis engines and optional agents.

The interface includes searchable Credits with bundled license details, adjustable text size, a High Contrast theme, visible keyboard focus, resizable evidence panes, and saved layout presets. It restores the last selected workspace without starting a scan and can optionally reopen selected tabs. After an interrupted session, a recovery prompt offers History or a user-triggered scan resume. Ctrl+K opens a searchable command palette with saved actions and clearable history; F1 opens help for the current screen.

The About page is read-only in the application. Project files are at [github.com/jasonbernier/CastorPollux](https://github.com/jasonbernier/CastorPollux); the Windows executable will be available from its Releases page when a release is published. Third-party sources and licenses are listed on the Credits page.

The Castor and Pollux Gemini artwork represents two linked stars and appears in the navigation, About screen, and Windows application icon.

## What happens when you analyze a binary

CastorPollux copies the chosen binary into a new investigation folder and verifies its SHA-256 hash. Ghidra imports and analyzes it, and REA uses Ghidra to inspect and decompile the procedures it finds. CastorPollux saves REA's reconstructed code in `rea-pseudocode.c`, with a procedure-by-procedure record in `rea-decompilation.json`. It also saves Ghidra exports, REA evidence, a snapshot, logs, and a manifest so the work can be reopened or resumed.

The reconstructed code is pseudocode, not the original source code. Names, types, control flow, and missing functions may differ from the original program.

## Agent review

When you choose Analyze → Agent Review, or run a review from a saved investigation, CastorPollux checks that REA produced reconstructed code. You can review all reconstructed procedures or select functions or modules/namespaces. For Codex, Claude Code, and OpenCode, CastorPollux gives the installed agent a temporary copy of the scoped reconstructed code and supporting text exports. The original binary and Ghidra project are excluded. You can instead choose a downloaded local Ollama model; CastorPollux sends bounded code chunks only to the loopback server on this PC. The selected agent inspects the evidence for possible vulnerabilities and CastorPollux saves its structured findings in the report formats you choose.

Cloud agent CLIs are installed and authenticated separately. They may send staged evidence to their providers. A local Ollama model requires a separately installed Ollama server and downloaded model. CastorPollux's local client only contacts 127.0.0.1; for strict offline operation, disable Ollama's cloud features in its own server configuration. Agent findings are leads for human validation, not proof of a vulnerability.

Daybreak Blue is an optional Codex review setting, off by default. For best security review results, use a Daybreak-enabled model when your account has approved access. Standard Codex and the other supported agents remain available without this setting. Selecting it requests Daybreak Blue with `gpt-6-sol`; it does not provide Daybreak access.

The Coverage page lists the outcome for each procedure. Findings lets you click report citations to see reconstructed code and cross-references, record triage decisions and notes, and reopen earlier review runs.

Findings now explains the evidence behind each agent confidence label, includes bounded report-ready REA code excerpts, and saves a separate call-path image for every finding. A six-step confirmation checklist can be completed and saved per finding; completing it records analyst work but does not automatically prove a vulnerability. Coverage can export `source-map.csv` and `source-map.json`, mapping saved pseudocode line ranges to binary addresses and available Ghidra symbols. These are reconstructed-code maps, not original source-file line maps.

Data Flow scans successful REA reconstructions for simple variable assignments from input APIs to risky APIs. It records candidate source-to-sink paths in `data-flow.json`; pointer aliases and cross-function transfer require manual review. Custom JSON rules define sources, sinks, and sanitizer names; sanitizer behavior is only approximated. Compare includes new, recurring, and absent findings when both builds have saved agent reports. Findings also stores named reviewers, assignees, and an append-only local decision log in `findings-audit.jsonl`.

Test Corpus stores confirmed expected findings for known binaries and evaluates saved reviews for matches and misses. Mark a case complete only after fully adjudicating its expected answers; only complete cases count unexpected findings as false positives. Investigations displays the target binary's Windows Authenticode status and signer when available. A valid signature identifies a signer but does not establish that the software is safe.

Analyze can optionally pass a local PDB or DWARF debug file to Ghidra before analysis. CastorPollux checks the PDB GUID and age or ELF GNU build ID against the binary before accepting the file, then saves its hash and reports the attempted import. Function names from Ghidra symbols are preferred in saved coverage and agent scope when REA used an anonymous name. Runtime Trace prepares a Windows Sandbox session with networking and clipboard disabled and the target mapped read-only. **The Windows Sandbox execution feature is untested in this build.** It samples child processes and TCP metadata and can compare broad behavior categories with static leads. The trace timeline links observed events to candidate pseudocode and cross-references by behavior category; those links do not prove a function executed.

Bundles export an investigation to a ZIP with a per-file SHA-256 manifest, verify every entry, and import only after verification. Plugins are declarative JSON files for extra flow rules, review guidance, and Markdown report templates. They do not execute code. Plugin rules and prompts are recorded with each new review.

Agent Review flags reports when procedure coverage falls below the chosen threshold or reconstructed code is too short. Cloud review has a staged evidence preview and optional redaction of token-like strings, email addresses, and user-entered literal terms. Redaction changes only the temporary files sent to cloud agents. When high or critical findings are reported, an optional, separately installed RetDec CLI independently decompiles the saved binary for manual comparison. A matching location is not proof that a vulnerability exists.

Agent Review can export SARIF 2.1.0 alongside JSON, Markdown, HTML, CSV, and PDF. Data Flow lets you edit a candidate rules file, test it against manually labeled complete cases in the known-answer corpus, and enable it only when the candidate does not add false positives or missed flows. Unpack accepts ZIP, TAR, GZIP, and XZ archives and can carve structurally valid PE/ELF images from raw firmware; other firmware filesystems and compression formats may be missed. Extracted files are never executed by the unpacker.

## Local workflow and sources

Binary analysis runs locally. Release sources are contacted when you check for or install component updates. Saved investigations stay in the output folder you choose; updated components and job history live under `%LOCALAPPDATA%\CastorPollux`.

CastorPollux builds on REA, Ghidra, Eclipse Temurin, Node.js, Python, CustomTkinter, and other open-source projects. Open Sources & Credits for links, licenses, and notices.

Components can export a software inventory with versions, hashes, licenses, and Windows signature status. A publisher signing script is provided for releases, but signatures require a certificate configured by the distributor; an unsigned build is reported as unsigned. Batch mode runs multiple binaries from a JSON configuration and writes a machine-readable summary with CI exit codes.

The in-app About text is bundled with the application and cannot be edited from the GUI.
