# CastorPollux 1.0.0 — first release

CastorPollux is a Windows desktop workbench for binary investigation. The self-extracting EXE bundles the GUI, REA, Ghidra, Temurin JDK, and Node.js. Codex, Claude Code, OpenCode, Ollama, and RetDec are optional separate installations.

The first release uses the CastorPollux name and Gemini twin-star artwork throughout the GUI, executable icon, package, and documentation. Existing local settings and investigation history are imported on first run when available.

## Included workflows

- Analyze a binary with Ghidra and REA; save reconstructed pseudocode, disassembly, references, coverage, logs, engine status, and a resumable investigation manifest.
- Run a scoped defensive agent review of reconstructed evidence and export cited findings as JSON, Markdown, HTML, CSV, PDF, or SARIF.
- Inspect agent confidence rationales alongside citation and decompiler checks; include bounded code excerpts, per-finding static call-path PNGs, and saved analyst confirmation checklists. Export reconstructed-source line maps with available Ghidra symbols.
- Search and visualize functions, data flow, calls, graph evidence, coverage, library leads, build differences, and scan dashboards. Export a shareable HTML dashboard snapshot.
- Use drag and drop or browsing, batch jobs, scan progress and stage estimates, a searchable and bookmarkable activity log, History timelines, and optional desktop notifications.
- Customize the interface with searchable Credits and bundled license text, adjustable text size, High Contrast and visible keyboard focus, resizable evidence panes, saved layouts, configurable shortcuts with conflict detection, autosaved form drafts, an unsaved-edits indicator, passive workspace restore, optional tab reopening, an interrupted-session recovery prompt with per-stage log previews and resume choices, a command palette with saved actions and clearable history, and screen-specific help.
- Check component health, record a software inventory, verify release digests, and inspect third-party credits and licenses.

## Review limits

Reconstructed code can omit or misrepresent program behavior. Static and agent findings require human validation. Python proof-of-concept candidates are not executed or verified by CastorPollux. Windows Sandbox runtime tracing is **UNTESTED**. The release attestation is unsigned unless a distributor applies and verifies a publisher signature. Review the commercial license audit and third-party terms before distribution.
