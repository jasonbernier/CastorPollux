# CastorPollux Help

## Find your way around

The left navigation groups screens into Start, Explore, Tools, and System. Analyze has Target, Options, and Activity tabs; its scan controls and progress stay visible above them. Settings has Appearance, Symbols, and Engines. Use the DAY/NIGHT header button or choose a theme in Settings.

Drop one binary on the window to select it, or use BROWSE FILE. Drop several regular files to queue them in Batch Jobs; click RUN BATCH when ready. The target border highlights during a drag. Choose an existing output folder before scanning. CastorPollux makes an investigation folder beneath it.

The scan card shows its state, overall completion percentage, current stage, elapsed time, and an estimated remaining time. Engine stages without progress callbacks use recent timing estimates, so the estimate can change. When the scan ends, the card shows COMPLETE, INCOMPLETE, or STOPPED. Agent review remains marked REVIEWING until its report is saved.

Activity supports search, error and stage filters, bookmarks, and right-click Copy selected, Copy all, and Select all. History shows a compact scan timeline with links to detailed dashboards. In Settings → Appearance, you can enable optional Windows notifications for long scans.

Shortcuts: Ctrl+O browse for a binary; Ctrl+Shift+O choose an output folder; Ctrl+Enter Analyze; Ctrl+Shift+Enter Analyze → Agent Review; Ctrl+B Batch Jobs; Ctrl+H History; Ctrl+F Activity search; F1 Help; Esc cancel the current task.

## Customize your workspace

In **Settings → Appearance**, choose a theme including **High Contrast**, select a text size from 85% to 150%, and save. The app redraws its controls with the new font size. Open **Credits** and type a project or license term to filter the cards. **LICENSE DETAILS** opens bundled text inside the app for included components; separately installed tools show a link to their own project. **OPEN FULL NOTICES** opens the complete copied notice set.

Drag the divider between the result list and code in **Investigations**, between pseudocode and disassembly in **Evidence Lab**, or between findings, evidence, and detail in **Findings**. Click **SAVE LAYOUT**, enter a short name, and then select that preset under **Settings → Appearance**. The built-in Balanced, Code focus, and Results focus layouts are available there too. Pane positions apply when those screens are opened next.

CastorPollux restores the last selected screen, investigation, input file, and output folder on startup when they still exist. Restoring a workspace never starts a scan or review. Enable **Reopen selected tabs from the last session** in Settings → Appearance if you also want the last Analyze, Dashboards, and Settings tab restored. This option starts off. Tab selections are validated against those screens' fixed tab names.

If the application ended unexpectedly, a recovery prompt appears at the next start. Choose **OPEN HISTORY** to inspect the last scan's timeline and logs, **RESUME LAST SCAN** to restart the latest incomplete saved analysis, or **LATER** to stay on Analyze. Nothing resumes until you click Resume. A normal application close does not show this prompt next time.

Press **Ctrl+K** for the command palette. Type an action name or a keyword such as `decompile`, `interrupted`, or `licenses`. Click **☆ SAVE** beside a result to keep it near the top. Choose **Saved actions** to search saved commands or **Recent commands** to browse command history. Selecting an action adds it to recent history. **CLEAR HISTORY** removes recent actions after confirmation while retaining saved actions. The palette stores only IDs of built-in actions, not file paths or arbitrary commands. Click **? HELP HERE** or press **F1** for instructions related to the screen you are using. Buttons can be reached with Tab and activated with Enter or Space; a bright ring shows keyboard focus.

## Explore dashboards and share a snapshot

Open **Dashboards** and select an investigation. **Overview** summarizes scan state and coverage; **Performance** shows stage durations and recent trends; **Resources** displays sampled Ghidra and REA CPU and memory use; **Quality** combines coverage and engine outcomes. A resumed scan keeps separate timing attempts. Resource sampling can miss short peaks, and older investigations may have no samples. Use the CSV export for metrics or **SHAREABLE HTML** for a single offline file with embedded charts. The HTML snapshot omits reconstructed code, logs, binary hashes, process IDs, and absolute paths; review the snapshot before sharing it.

## Explore graph and imported evidence

Open **Graph Lab** for saved Ghidra SSA/P-code def-use edges, possible pointer aliases, virtual-call and jump-table leads, and disputed call edges. Select an edge or function to inspect its supporting evidence. **Call Paths** visualizes saved direct calls and marks indirect candidates with confidence labels; an inferred edge is a lead for manual review, not proof that a runtime call occurred. **Evidence Lab** searches indexed pseudocode, maps saved source lines to candidate binary addresses, and places REA code beside Ghidra disassembly. A disagreement heatmap highlights places to inspect manually rather than proving a decompiler is wrong.

Import OpenVEX or CycloneDX VEX statements, an SBOM, or address-based fuzz coverage through the related evidence tools. Confirm the supplied file and its source before trusting it. A pinned SBOM SHA-256 proves only that the imported bytes match the recorded digest; it does not authenticate the producer. Fuzz coverage overlays show addresses observed in the supplied data and should be checked against the matching binary build.

## Review libraries, advisories, and changed builds

Open **Libraries & CVEs** to inspect local static-library fingerprints and imported DLL signature information. An explicit known-vulnerability lookup queries exact-version CPE advisory leads; cached responses can be reused offline with their age shown. Library fingerprints, advisory matches, static call paths, and build-configuration rules are leads. Confirm the embedded library code, affected configuration, and relevant function reachability before treating an advisory as applicable. Import an SPDX or CycloneDX SBOM to compare declared libraries with detected leads and inspect any identity differences.

Use **Compare** to select two saved investigations. Review matched and changed functions, basic-block differences, candidate type-signature changes, and recurring or resolved findings. Function matching is heuristic when symbols are stripped. A patch impact map and verification checklist point to changed flows that merit a new scan and manual review.

## Troubleshooting examples

### Example: analyze and review a Windows program

1. Open Analyze and choose `C:\\Windows\\System32\\where.exe` as a small practice target.
2. Choose an existing empty or reusable output parent folder such as `C:\\Users\\You\\Documents\\CastorPollux investigations`.
3. Select Codex as the agent. On Agent Review, use AUTO DETECT and select report formats, then return to Analyze.
4. Click ANALYZE → AGENT REVIEW. Watch the stage percentage and activity log. Ghidra first exports supplemental evidence; REA reconstructs `rea-pseudocode.c`; Codex then reads a temporary copy of that source and selected context files.
5. Open Findings to inspect each cited location. In History, use LOGS to inspect `ghidra.log`, `rea.log`, `rea-decompile.log`, and `codex-review.log` if a stage stops.

### Example: optional symbol lookup fails

If the activity log says symbol lookup failed, analysis continues without symbols. Open History, select the job, and read its latest warning or `errors.jsonl`. Inspect `manifest.json` → `symbol_download` for the specific error. In Settings, confirm the HTTPS base URL is approved; then verify network access and whether the binary contains a PDB GUID/age or ELF build ID. You can also use a matching local symbol file on a new scan. A symbol file with the wrong identity is rejected.

### Example: resume an interrupted job

After an unexpected application exit, use the recovery prompt to open History or resume the latest incomplete scan. You can also open History manually, select the **interrupted** filter, then click RESUME. CastorPollux checks that the saved binary still matches its SHA-256 and reuses completed Ghidra/REA stages and REA procedure checkpoints. If RESUME is absent, the saved binary may be missing. OPEN and LOGS let you inspect the remaining evidence.

### Example: investigate a reported credential

Open Secret Leads and inspect the redacted type, location, and digest. Click OPEN on the investigation and search the cited procedure in Investigations. Determine whether the value is a test fixture, decoy, or active secret through an authorized process. The secret scanner never writes a full matched value to `secret-evidence.json`; the underlying pseudocode and strings exports may still contain it, so handle investigation bundles accordingly.

## 1. First launch and orientation

1. Open `CastorPollux.exe`. Because it is a self-extracting application, its first launch can take longer than later launches.
2. Use the left navigation to open Analyze, Batch Jobs, History, Investigations, REA Actions, REA Console, Compare, Agent Review, Components, About, Help, and Credits.
3. The footer shows the current stage. During REA decompilation its progress bar and activity log show how many procedures have been processed.
4. Ghidra, REA, Java, and Node.js are bundled. An AI agent CLI is separate: install and sign in to Codex, Claude Code, or OpenCode before requesting its review.
5. Choose an output folder with enough free space. A large target may create a large Ghidra project, source export, and logs.

## 2. Analyze a binary

1. On Analyze, select BROWSE FILE and choose the binary you are authorized to inspect.
2. Select CHOOSE FOLDER and choose an existing output directory. CastorPollux creates a timestamped investigation subfolder there; it does not overwrite the chosen binary.
3. Click ANALYZE to generate evidence, or select an agent and click ANALYZE → AGENT REVIEW to continue directly to a vulnerability report.
4. Watch the activity log and footer. First, CastorPollux verifies a saved copy of the binary. Ghidra then imports and analyzes it. REA collects summary evidence and decompiles its listed local procedures in batches.
5. Click OPEN OUTPUT after the folder has been created to inspect saved files. If a stage fails, available output and logs stay in the investigation folder.
6. CANCEL requests cancellation of the current process. Reopen History and choose RESUME to continue an interrupted investigation.

## 3. What the analysis produces

`source-binary.*` is the verified copy of the target. `manifest.json` records the SHA-256 hash, component versions, stage statuses, and warnings. `GhidraProject` is the saved Ghidra analysis project.

`rea-pseudocode.c` is the main reconstructed code produced through REA and Ghidra. `rea-decompilation.json` records individual procedure results and coverage. `rea-decompilation-progress.json` checkpoints completed batches so a resumed job can skip procedures that already succeeded. `rea-decompile.log` records decompilation diagnostics. This source-like output is pseudocode, not the original source tree.

`pseudocode.c`, `disassembly.txt`, `functions.csv`, `strings.csv`, `imports.csv`, `xrefs.csv`, `calls.csv`, and related files are supplemental Ghidra exports. `rea-evidence.json` and `rea-snapshot.json` are REA evidence and reusable snapshot data. `ghidra.log` and `rea.log` help diagnose failed stages. The investigation folder also contains an HTML analysis report.

The file inventory can vary with binary format and engine output. Use the manifest and logs to determine whether a stage completed and whether procedure coverage is partial.

## 4. Run an agent vulnerability review

### Data flow, finding history, and triage

After REA decompilation, open **Data Flow** to see candidate input-to-risky-operation paths. Each lead cites a reconstructed function address and source/sink lines. **Rebuild Flow Leads** updates `data-flow.json` for older investigations. The scanner follows simple local assignments; it does not resolve pointer aliasing, sanitizers, or transfer between procedures. Review the cited code before treating a lead as a vulnerability.

On **Compare**, choose an older and newer investigation. When both have structured agent reviews, the report also lists new, recurring, and findings absent from the newer report. An absent finding does not prove a fix. Compare analysis scope and decompilation coverage first.

On **Findings**, enter a reviewer name and optional assignee/team, choose a decision, add a note, and click **Save Triage**. The current state is saved in `findings-triage.json`; every saved decision is appended to `findings-audit.jsonl`. Store shared investigation folders with appropriate access controls. This is a local audit log, not a tamper-proof or synchronized team service.

On **Test Corpus**, select a corpus JSON path. Confirm findings in the Findings page, then click **Add Confirmed** to save expected finding signatures for the selected binary hash. For a fully adjudicated case, check **All expected findings labeled** before adding it; this also permits a known-benign case with zero expected findings. Edit the JSON directly to add independently verified missed findings. Click **Evaluate History** to score matching saved investigations and write `known-answer-evaluation.json`. Incomplete cases contribute to recall but do not count unlabeled output as false positives. The matching is heuristic and depends on equivalent review scope.

On **Investigations**, look for **Target Signature** below the selected investigation path. `Valid` means Windows verified an Authenticode signature for the saved PE file; `NotSigned`, an error, or `not_applicable` are shown separately. The signer and certificate details are also in `manifest.json` for new analyses. This check does not assess trustworthiness or vulnerabilities.

To review an existing investigation, open Agent Review, select its folder, then choose Codex, Claude Code, or OpenCode. Use AUTO DETECT to locate the selected CLI, or BROWSE to point to its executable. Choose one or more JSON, Markdown, HTML, CSV, PDF, and SARIF formats, then click RUN REVIEW. The Analyze → Agent Review button performs analysis and this review in one action using the current agent and format selections.

Daybreak Blue is optional and off by default. For best security review results, use a Daybreak-enabled model by selecting **Use Daybreak Blue** when your Codex account has approved access; otherwise leave it off and use standard Codex or another agent. You can select the same option on Analyze before the one-click workflow or on Agent Review before a saved investigation. CastorPollux requests `gpt-6-sol` with the `daybreak_blue` access program when selected. The switch does not grant access: if your account lacks it, the review can fail while the completed decompilation remains saved. Daybreak is available only with Codex in this app; changing to another agent clears the selection.

Review requires nonempty `rea-pseudocode.c` and a matching REA decompilation record. If they are missing, open History and RESUME the investigation. REA procedure failures are noted as coverage limits. Supplemental exports can add context, but they do not replace the REA reconstructed source.

For Codex, CastorPollux stages the reconstructed source, selected CSV/text exports, and a filtered manifest under `%LOCALAPPDATA%\CastorPollux\ReviewStaging`. It starts the detected Codex CLI with a read-only sandbox, a JSON output schema, and a review prompt on standard input. It does not stage the original binary or Ghidra project. The temporary staging folder is removed when review ends. Claude Code and OpenCode use their own installed CLIs with the same static evidence goal.

The agent CLI uses its own sign-in and may send staged evidence to a remote service. Check your organization's rules before reviewing confidential binaries. Review output is saved as `security-report.*` in the investigation folder. Read evidence, confidence, limitations, and suggested validation steps; a model finding is a hypothesis until confirmed.

## 5. Browse saved evidence

### Review finding evidence and confirm it

After Agent Review, open **Findings** and select a finding. **Confidence reasons** explains which citations resolved to REA procedures, each cited procedure's decompiler confidence, whether a named-entry static call path was found, and what remains unverified. The agent's confidence label is shown separately and is not automatically promoted to a verified result.

Choose **REPORT CODE EXCERPTS** to view short, numbered slices of saved REA pseudocode with the reconstructed-source SHA-256. A slice is marked as an exact cited procedure line only when that line can be resolved; otherwise it is labeled function context. Reports include these excerpts in Markdown, HTML, PDF, JSON, CSV, and SARIF. They are reconstructed code, not the program's original source.

Choose **VIEW FINDING CALL PATH** for that finding's PNG diagram. A route is drawn only when saved direct calls connect a named entry procedure to the cited function. If no route is established, the image says so; this does not prove the function is unreachable. The image is stored in `finding-assets/` and included beside the report. Earlier review runs retain their own image copies in ReviewHistory.

Choose **CONFIRMATION CHECKLIST** to record six analyst checks: target identity and scope, pseudocode versus disassembly, the specific trust boundary, alternate branches and counter-evidence, an authorized isolated validation, and a rescan after remediation. Click **SAVE CHECKLIST** to store progress in `finding-confirmation.json`. Checked boxes document work performed; they do not change a finding to confirmed automatically.

On **Coverage**, choose **SOURCE MAP** to export a CSV. The investigation also saves `source-map.csv` and `source-map.json` after REA decompilation. Each row maps a range of lines in `rea-pseudocode.c` to a binary procedure address and available Ghidra symbol name, namespace, and symbol origin. Ghidra's current symbol export has no original source-file line table, so this map does not identify original C/C++ file locations. Confirm symbol identity and matching build before using names in a report.

Open Investigations and select a saved folder. Search Functions, Strings, Imports, Xrefs, Calls, REA Code, or supplemental Pseudocode. Choose a row to see its details. Function rows can show matching reconstructed code and incoming/outgoing call references. Search terms are case-insensitive; code searches look for matching lines. Open Folder gives access to the full files when the in-app preview is limited.

REA Code is the decompilation used for Agent Review. The Pseudocode category is the separate direct Ghidra export. A code search is most useful with a function name, API name, string, or address fragment.

## 6. Run focused REA queries

Open REA Query, select a saved investigation, choose Search, Function, Decompile, or Xrefs, and enter a value. Search accepts a text pattern. Function and Decompile accept a procedure name or address. Xrefs accepts an address or symbol name. Click RUN REA QUERY. The result appears in the app and is saved under `rea-queries/` for later inspection. CastorPollux supplies the saved target and snapshot to REA.

For Decompile, enter a real function name or address such as `0x140001010`. The app passes it as REA's named `--procedure` argument. An empty or invalid selector cannot identify a procedure and will produce an error.

## 7. Use the full REA console

REA Console exposes the entire REA command-line interface. Select an investigation and enter arguments as a JSON array, for example `["--help"]` or `["decompile", "{binary}", "--procedure=0x140001010", "--provider", "ghidra", "--format", "json", "--snapshot", "{snapshot}"]`. The `{binary}` and `{snapshot}` placeholders expand to that investigation's saved paths. Arguments are passed directly to REA without a shell. Output is saved under `rea-console/`.

The console is intended for users familiar with REA. Some REA commands can do more than static inspection; read a command's help and arguments before running it. If a command fails, inspect its saved log and confirm that required selectors or options are present.

## 8. Reopen and resume work

History lists recorded investigation folders with Ghidra, REA evidence, decompilation, and review status. OPEN selects a folder for browsing. RESUME uses its verified saved binary and reuses completed stages; REA decompilation checkpoints let it skip successfully reconstructed procedures. If the source binary copy is missing or its hash has changed, the job cannot safely resume. REVIEW opens Agent Review for that investigation.

An interrupted job may contain partial evidence even when a final report is unavailable. The activity log, manifest, and stage logs show what completed. After an update or crash, use RESUME before starting a new investigation if you want to preserve the prior folder.

## 9. Compare two builds

Open Compare, select two saved investigation folders, and choose a destination for comparison output. Run the comparison to create JSON, Markdown, and HTML reports showing changes in functions, strings, imports, and calls. Anonymous function matching is heuristic, so inspect the underlying code and addresses before concluding that a function was added, removed, or changed. Comparisons summarize evidence differences; they are not a security verdict by themselves.

## 10. Manage components

Components lists Ghidra, Temurin JDK, REA, and Node.js versions. CHECK UPDATES queries upstream release sources. UPDATE installs one compatible component; UPDATE ALL processes available compatible updates. HEALTH tests the selected active component. ROLL BACK activates a retained prior version if available. Review results after updating by resuming or rerunning an investigation. The component center updates engines, not the CastorPollux desktop EXE.

## 11. Reports and troubleshooting

The Agent Review page controls export formats. JSON preserves the structured result. Markdown and HTML are easy to read or share. CSV contains a findings table. PDF is useful for distribution. SARIF 2.1.0 is for security dashboards and CI; it includes evidence artifact names and cited lines when the agent provides them. Select at least one format before review. The app saves `security-report.*`, the request, schema, raw agent result, and an agent log in the investigation folder.

If Codex is not found, install/sign in to the Codex CLI or use BROWSE to select its executable. AUTO DETECT checks your PATH and common Windows installation locations again. If an agent exits with an error, read its `*-review.log`. The binary is not included in the staged agent files.

Agent reviews are requested for a **defensive outcome**: identify, validate, report, and help remediate potential vulnerabilities. The temporary staging folder includes `evidence-index.json` and `manifest.json`, which list files actually available to the agent. Optional files such as `known-vulnerabilities.json` may be absent when no advisory scan was saved; their absence is not evidence that the binary has no known vulnerabilities. The prompt tells the agent to check for each optional file before reading it and to avoid assuming `rg`, Python, or unrestricted PowerShell methods are installed. If `codex-review.log` shows a failed search command, inspect the staged-file list and the final review result; a shell-tool failure alone is not a finding about the binary.

If REA decompilation fails, inspect `rea-decompile.log` and the manifest. Check that the target is a format REA and Ghidra can analyze, then choose RESUME in History. If only some procedures succeed, the report marks coverage as partial. If a query reports a missing procedure, provide an address or name from the Functions list and retry.

For component or extraction problems, use Components → HEALTH and review the relevant Ghidra or REA log. Sources & Credits contains upstream links and the bundled licenses.

An opt-in symbol-server HTTP 404 means that server has no matching file for the binary identity. Analysis continues without downloaded symbols, and `manifest.json` records `symbol_download.status` as `not_found`. Other lookup errors remain visible in diagnostics.

## 12. Inspect and export decompilation coverage

Open Coverage, choose a saved investigation, and review every inventoried REA procedure. The summary counts successful, failed, and pending procedures. Search by name, address, module/namespace, section, or error, and filter by status. Select a procedure to read its reconstructed code or failure detail. EXPORT CSV saves the coverage table for outside analysis. While a job is interrupted, pending procedures come from its batch checkpoint; RESUME can complete them.

## 13. Follow report evidence and triage findings

Open Findings, choose an investigation and a review run, then select a finding. Click an evidence citation in the middle column to jump to its matching REA pseudocode and saved cross-references in the right panel. When the citation includes a line number, the cited file excerpt appears too. If the model cites a function inaccurately, inspect the saved file before accepting the claim.

Choose Unreviewed, Confirmed, False Positive, or Needs More Evidence, enter an analyst note, and click SAVE TRIAGE. Decisions are stored in `findings-triage.json` in the investigation folder. A new review archives the preceding structured result and selected report files under `ReviewHistory`; choose an earlier run from the review picker. Triage is separate from the model's report and does not change the original finding text.

## 14. Scope a review and inspect its prompt

On Agent Review, set Scope to All, Functions, or Modules. For Functions, enter exact function names or addresses separated by commas, such as `FUN_140001010, 0x1400010f0`. For Modules, enter one or more module/namespace names shown by OPTIONS. Modules here are Ghidra symbol namespaces within the analyzed binary; CastorPollux does not decompile imported DLLs as part of that target. A selected scope must contain at least one successful REA decompilation.

Scoped cloud reviews stage only the selected REA procedure bodies and matching function, call, and reference rows. A full review stages the broader supplemental exports. Click PROMPT PREVIEW to see the exact base request plus the selected scope before running. The request, scope, and structured response are saved with the investigation after a successful review.

## 15. Review with a local Ollama model

Install Ollama separately and download a model appropriate for code review. Start its local server on `127.0.0.1:11434`. On Agent Review, choose `ollama`, click CHECK LOCAL MODELS, select a downloaded model, choose scope and report formats, then click RUN REVIEW. The client rejects cloud-tagged models and sends requests only to the loopback address. It divides the selected reconstructed code into bounded chunks and asks for a structured JSON result for each chunk; the final report combines findings and states local model limits.

Ollama must have enough memory and context length for the chosen model. For strict offline assurance, disable Ollama cloud features in Ollama's server settings before starting it. A local model's capabilities vary; review every cited function and limit carefully. The CastorPollux EXE does not bundle Ollama or model weights.

## 16. Review history, prompt records, and model output

After a successful review, `security-review-data.json` always stores the structured report used by the Findings page, even if JSON is not one of the selected export formats. `security-review-request.txt` contains the exact base agent request and scope. `security-review-scope.json` lists the chosen addresses. `security-review-raw.json` preserves the agent result. Agent logs record errors or execution details. Re-running a review copies the preceding records and report exports into a timestamped `ReviewHistory` folder before writing the new run.

## 17. Coverage quality threshold

On Agent Review, enter a minimum coverage percentage from 0 to 100. The default is 80. The report compares successfully reconstructed procedures with the complete REA procedure inventory and also requires at least 1,000 reconstructed source characters. If either condition fails, the quality gate is marked WARNING in JSON, Markdown, HTML, PDF, and CSV exports. A warning does not hide the available findings; it tells you that the review may have missed code. Use Coverage to inspect failed procedures and History to resume an incomplete job.

## 18. Independent RetDec comparison

Install RetDec separately if you want a second decompiler. On Agent Review, choose its `retdec-decompiler.exe` or leave the field empty to search PATH. With **RetDec check for high findings** enabled, CastorPollux runs RetDec locally after an agent reports a high or critical finding. It saves `retdec-secondary.c`, `retdec-secondary.log`, and `second-decompiler-check.json`. The check is limited to saved binaries of at most 100 MiB and five minutes. If RetDec is missing or fails, the report says so. A matched address or function name is only a place to compare the outputs manually; it does not confirm the finding. RetDec is not bundled and retains its own license.

## 19. Preview and redact cloud evidence

On Agent Review, choose a scope and click **EVIDENCE PREVIEW** before running Codex, Claude Code, or OpenCode. The preview lists the temporary files the agent can read and shows a bounded sample of their content. **Redact cloud evidence** is on by default. It masks token-like assignments, Bearer tokens, email addresses, and any extra comma-separated literal terms you enter. Redaction applies to the staged copies only, so the saved original evidence remains available locally. Inspect the preview: pattern matching cannot catch every secret and may remove evidence needed for a finding. Ollama uses the separate local review path and is not changed by this cloud control.

## 20. Software inventory and signing status

On Components, click **EXPORT INVENTORY** to save active versions, executable hashes, licenses, paths, and Authenticode status. **APP SIGNATURE** shows the EXE's Windows signature status. The release package includes `CastorPollux-Software-Inventory.json`, and `work/release_sign.py` can sign and verify a built EXE when a publisher certificate, SignTool, and timestamp URL are configured. The current release is unsigned unless its inventory reports a valid signature. Component updates continue to use upstream HTTPS release sources and published SHA-256 or package integrity checks; those checks are not publisher signatures. Do not describe an update as signed unless a signing process and verification have actually succeeded.

## 21. Batch and CI execution

On **Batch Jobs**, add several binaries, choose an existing output folder and optional review agent, then click **RUN BATCH**. The queue runs sequentially to avoid conflicting Ghidra sessions, and a JSON summary and log are saved in the chosen folder. Agent Review controls such as coverage, redaction, formats, Daybreak, and RetDec also apply to GUI batches.

For CI, copy `CastorPollux-Batch-Example.json`, set an existing output directory and one or more input binaries, then run `CastorPollux.exe --batch config.json`. It writes a JSON summary after each job and a log beside it; exit code 0 means all requested jobs completed, 2 means a job failed or a requested quality gate warned, and 3 means the configuration was invalid. Use `fail_on_quality: true` for a CI gate. Paths in the configuration can be absolute or relative to the configuration file. `CastorPollux-CI-Example.ps1` shows a Windows CI invocation. Because the GUI EXE has no console window, CI should read the summary and log rather than rely on standard output.

## 22. Customize data-flow rules

Open Data Flow and click **EDIT RULES**. CastorPollux creates a candidate copy of `%LOCALAPPDATA%\CastorPollux\data-flow-rules.json` so changes are inactive while you edit. Sources are objects with a `name` and `output`: use `"return"` when the API returns untrusted data, or a zero-based argument number when it writes into a buffer. Sinks are API names. Sanitizers use the same output syntax; an assignment from a return sanitizer clears the assigned variable, and an argument sanitizer clears the named argument. On **Test Corpus**, choose a corpus, select a known investigation, enter the manually adjudicated expected flows as JSON, tick **All expected findings labeled**, and click **SAVE FLOW ANSWERS**. Each flow answer needs `function`, `source_api`, and `sink_api`; use `[]` for a known negative. At least one labeled complete case must have saved REA coverage. Save the candidate JSON, then click **TEST CORPUS** on Data Flow. The candidate passes only if it does not increase false positives or misses compared with active rules. Click **ENABLE TESTED** to rerun the check and activate the exact tested file. Directly editing the active JSON outside CastorPollux bypasses this gate and is unsupported. Click **REBUILD FLOW LEADS** to update the selected investigation using active rules. This is a name-based, intra-procedure heuristic; verify whether a sanitizer actually removes the relevant risk.

## 23. Load local PDB or DWARF symbols

On Analyze, select an optional local `.pdb` file or ELF/DWARF debug sidecar before starting a new investigation. CastorPollux reads the PE CodeView RSDS GUID and age and compares them with the MSF 7 PDB identity; for ELF, it compares the GNU build ID in the target and sidecar. It rejects missing or mismatched identities before copying the symbols or starting Ghidra. It does not download symbols automatically, and older/non-MSF PDBs or ELF files without build IDs cannot pass this strict check. The accepted file is copied under `Symbols/`, hashed, and supplied to Ghidra's PDB or DWARF analyzer. `manifest.json` records the identity and hash. Check `ghidra.log`, `functions.csv`, and Coverage to confirm whether names were applied; an identity match alone does not guarantee successful import. REA still reconstructs pseudocode through its own Ghidra-backed session, so Ghidra names are shown as aliases in the coverage list and scoped agent evidence when REA retained an anonymous function name. For batch jobs, set `"symbols"` in the JSON configuration to a local file path; the same file applies to each queued binary, so use separate configurations if binaries need different symbol files.

## 24. Prepare an isolated runtime trace

**The Windows Sandbox execution feature is untested in this build.** Open Runtime Trace for a saved Windows binary, enter arguments as a JSON string array, set a timeout from 5 to 600 seconds, and click **PREPARE JOB**. CastorPollux copies only the verified binary and its monitor script into `RuntimeTraces/<time>/input` and creates `CastorPolluxTrace.wsb`. Inspect that configuration, then click **LAUNCH SANDBOX** on a computer with Windows Sandbox enabled. The configuration disables networking, clipboard, graphics acceleration, and device sharing; the binary input folder is read-only. A separate folder is writable so the sandbox can save `trace.json`. When the run finishes, click **CORRELATE TRACE**. The result matches broad process or network observations to static lead categories and writes `runtime-correlation.json`. Click **TRACE TIMELINE**, select an event, then choose a candidate citation to view REA pseudocode and cross-references. The citation is based on a behavior-category match; it does not prove that a cited function or data path executed. Sandbox availability depends on Windows edition and virtualization. The sandbox can write to its mapped trace output folder, so treat its results as untrusted data.

## 27. Unpack an archive or firmware image

Open **Unpack**, choose a ZIP, TAR, GZIP, XZ, or raw firmware file up to 512 MiB and an empty output directory, then click **UNPACK AND IDENTIFY**. CastorPollux extracts at most 500 files and 1 GiB, rejects archive path traversal, links, special files, encrypted ZIP entries, and duplicate paths, and stops after two nested archive levels. For raw firmware it scans for PE/ELF signatures and carves candidates only when their headers and file-backed ranges are structurally valid. `unpack-manifest.json` records each file's origin, size, and SHA-256. Click a PE/ELF candidate to put it on the Analyze page. The unpacker does not execute extracted files. Filesystem images, UEFI volume internals, proprietary compression, and unrecognized formats may require an external specialist extractor.

## 25. Export, verify, and import a bundle

Open Bundles with a saved investigation selected. **EXPORT CURRENT** writes a ZIP outside the investigation folder, containing the binary, Ghidra project, logs, exports, reports, and a `bundle-manifest.json` with each file's size and SHA-256. **VERIFY ZIP** checks every entry and the saved binary against both manifests. **IMPORT VERIFIED** first verifies again, then extracts into a new folder without overwriting an existing investigation. The ZIP hash displayed after export can be shared out of band to confirm that someone received the same bundle. These checks detect changed bytes; they do not authenticate the sender. Bundle files may contain sensitive binary code, pseudocode, prompts, and reports.

## 26. Add organization plugins

## 28. Evidence Lab: indexed search and linked code

Open a saved investigation, then choose **Evidence Lab**. **INDEX SOURCE** creates a SQLite full-text index for `rea-pseudocode.c`. The index is rebuilt when the source SHA-256 changes. Search terms return source line numbers and a procedure-entry address. Enter a line number and click **MAP TO BINARY** to see whether the address is an exact procedure marker or only a procedure-level anchor. CastorPollux does not claim instruction-level mapping for lines whose export lacks address annotations.

Choose a procedure in the synchronized view to see its REA pseudocode beside saved Ghidra disassembly. Both panes follow the same procedure address. The decompiler heatmap compares Ghidra and REA token sets and highlights absent exports; its score is a heuristic triage measure, not evidence of an incorrect decompilation. Coverage-guided priority ranks failed or low-confidence procedures and API-name cues for review. These scores are also staged in `review-priority.json` for an agent review.

Example: Search `memcpy`, inspect the returned source line, map it to the enclosing procedure, then compare reconstructed code with its assembly before recording a finding. In Findings, citations display CURRENT, STALE, MISSING, or UNVERIFIED badges. **VIEW CODE + ASSEMBLY** opens the selected evidence in Evidence Lab.

## 29. Engine compatibility and limits

**Settings → CHECK ENGINE COMPATIBILITY** launches only version probes and checks file presence, the supported Ghidra release line, JDK 21, Node 20+, and REA package metadata. Every scan runs this check before copying and analyzing the target. The result is saved as `engine-compatibility.json` and in the manifest. A blocked check stops the scan with an explicit error.

Settings also provides Ghidra and REA wall-time limits and managed-heap limits. Ghidra's headless timeout and heap are configured separately from REA's process timeout and Node heap. Heap limits are not a whole-process or child-process memory cap. REA decompilation uses the configured deadline across batches; timeout preserves existing checkpoints for resume.

## 30. Agent command checks and usage

Before cloud review, CastorPollux verifies the selected CLI can start and that its required review flags appear in its local help output. It saves `agent-capabilities.json`. This is a host-side command check; agent sandbox file access is verified during review.

After a scan, the status bar and `agent-usage.json` show Codex's available rate-limit balance, Claude Code's last-review token usage when emitted by its JSON response, and OpenCode's local `stats` when available. Claude Code and OpenCode CLI output does not establish the remaining provider subscription quota; the app labels that balance unavailable instead of guessing it. Missing CLIs are shown as optional and unavailable.

## 31. Diagnostic preview and recovery comparison

When an engine fails, CastorPollux writes `diagnostic-preview.json` from redacted statuses and bounded log tails before asking Codex for a recovery decision. GUI scans show that exact payload and let you send it for diagnosis or skip. Batch scans save the preview and proceed without an interactive gate. Open it later from **History → PREVIEW REDACTED DIAGNOSTICS**. The automatic repair remains bounded to one hash-verified resume. Each attempt is preserved under `RecoveryAttempts/` with its own decision and agent log. **COMPARE RECOVERY ATTEMPTS** shows before/after failure lists across attempts. Treat logs as evidence; the agent cannot install components or modify the binary through this recovery path.

## 32. Corpus calibration and patch verification

**Evidence Lab → CALIBRATION** shows observed precision and recall against adjudicated known-answer cases and observed precision by the agent's confidence labels. Fewer than ten complete cases, or fewer than ten findings in any shown confidence bin, are explicitly marked too small for calibration. Build Compare writes `patch-verification.json` with a checklist for changed functions. Open it with **PATCH CHECKLIST**, then record manual verification of bounds, calls, runtime observations, and related findings. The checklist does not certify a patch.

Open Plugins and click **CREATE SAMPLE**. Edit the example JSON under `%LOCALAPPDATA%\CastorPollux\Plugins`, set `enabled` to `true`, then reload the page. A plugin can add source, sink, and sanitizer API rules; append a review checklist to the agent prompt; and render an extra Markdown report using `{{target}}`, `{{sha256}}`, `{{summary}}`, `{{findings}}`, `{{date}}`, and `{{plugin_id}}`. The app validates plugin IDs and rule names and never runs code from a plugin file. Enabled guidance appears in the saved `security-review-request.txt`, and a template creates `security-report-plugin-<id>.md`. Review the staged evidence preview before sending cloud agents organization-specific guidance.

## 33. Customize shortcuts and recover an interrupted scan

Open **Settings → Shortcuts** to edit the key sequence for each main action. For example, change History from `<Control-h>` to `<Control-Shift-h>`, click **CHECK CONFLICTS**, then **SAVE SETTINGS**. A key sequence must use a modifier such as Control, Shift, or Alt, except F1–F12 and Escape. CastorPollux rejects duplicate assignments and malformed sequences. **RESTORE DEFAULTS** fills the fields with the shipped shortcuts; save to apply them. The header shows **UNSAVED: Settings** while settings changes await saving.

After an interrupted session, the recovery prompt shows each engine stage and a redacted, bounded tail of its saved log or decompilation result. Choose **Ghidra export**, **REA evidence**, or **REA decompilation** to inspect its status. **RESUME SELECTED STAGE** is enabled for the earliest incomplete stage whose prerequisites are complete. Resuming verifies the saved binary hash, reuses successful earlier exports, and continues later incomplete stages. Use **OPEN HISTORY** to inspect full logs and prior recovery attempts. When a scan fails, the diagnostic preview lets you inspect what would be sent to Codex for a bounded recovery decision. Codex can suggest one verified retry; if that does not resolve the issue, CastorPollux asks you to open History for manual inspection.

## 34. Recover autosaved form drafts

CastorPollux saves the Analyze, Agent Review, Batch, and Settings form drafts after a short pause and again when the window closes normally. The header shows **DRAFT PENDING** while an edit is waiting to be saved and **DRAFT AUTOSAVED** after it is written. On restart, the app fills those fields and shows **DRAFT RESTORED**. Restoring a draft never starts a scan, launches a binary, runs an agent, or sends evidence to a cloud service.

Settings drafts remain proposals until you click **SAVE SETTINGS**. The About page is read-only. A restored file path may point to a file that has moved, so verify the input and output paths before running. The per-user file `%LOCALAPPDATA%\CastorPollux\form-drafts.json` contains form choices and paths. It does not save the additional literal redaction terms field, agent credentials, binaries, decompiled source, or review evidence. Protect the Windows account and inspect this local file before sharing it.

