# Graph Lab evidence guide

Graph Lab links REA's reconstructed source to Ghidra's saved decompiler SSA/P-code, disassembly, references, and imported external evidence. It records leads for a human reviewer. It does not prove a vulnerability or silently suppress a finding.

## Open a graph

Analyze a binary, then open **Graph Lab**. Choose the saved investigation. The tabs show def-use edges, possible pointer aliases, virtual-call leads, computed-jump targets, call-edge checks, fuzz hits, overflow leads, VEX, and SBOM integrity. Click a row for its complete saved evidence. Older investigations need another analysis run to create `pcode-ssa.csv`.

Ghidra's decompiler exports at most 10,000 P-code operations per function and 500,000 per investigation. The graph JSON records whether that ceiling was reached. **SSA leads** propagate configured source values to sink calls within a function, with bounded passes and low confidence. Possible pointer aliases use bounded propagation from load/store/indirect-call pointer inputs through COPY, CAST, PTRADD, PTRSUB, and MULTIEQUAL. This is not a full points-to or C++ class-hierarchy solver. For PE x86/x64, Edge checks also decode raw E8 direct calls and E9 tail jumps independently of Ghidra. FF /2 confirms an indirect call site but cannot prove its target. Other formats remain without an independent raw-byte check.

## Import VEX

Import a CycloneDX or SPDX JSON SBOM under **Libraries & CVEs** first. Then use **IMPORT VEX** in Graph Lab. OpenVEX and CycloneDX VEX JSON are accepted. Matching requires the exact SBOM component reference or PURL. Unmatched or poorly justified statements remain visible and do not change the disposition of findings.

## Check SBOM byte integrity

Get the SBOM SHA-256 through a trusted channel, paste it into **TRUSTED SBOM SHA-256**, then click **VERIFY BY DIGEST**. A match binds the imported bytes to that reference. It does **not** authenticate the SBOM publisher; embedded supplier and tool metadata are unverified declarations.

## Overlay fuzz coverage

Convert instrumentation results into address-based JSON:

```json
{
  "binary_sha256": "the 64-character SHA-256 of the analyzed binary",
  "hits": [
    {"address": "0x401000", "count": 12},
    {"address": "0x401014", "count": 3}
  ]
}
```

The import rejects a binary-hash mismatch. It overlays hits on approximate blocks from the saved disassembly. Raw AFL++ edge IDs have no address mapping in this format; convert them with your instrumentation metadata first. An unobserved block may still be reachable.

## Compare types and gate call paths

Compare two investigations and click **TYPE MAP** for inferred decompiler signature changes. CI batch JSON can include:

```json
"call_path_gate": {
  "baseline": "C:/investigations/older-build",
  "sources": ["receive"],
  "sinks": ["copy_into_buffer"]
}
```

The gate compares bounded direct-call paths of at most six functions. New paths set the batch status to `new_call_paths` and exit code 2. Runtime dispatch, inlining, and changed symbol names can affect results. Review the saved `call-path-gate.json` before treating it as a security regression.

## Buffer-boundary triage

Click **SCAN OVERFLOWS**, inspect a cited lead, enter its zero-based number, then click **CREATE BOUNDARY INPUTS**. The three byte files are below, at, and above the fixed array's inferred capacity. They are intentionally unexecuted. Use the target's actual input channel in an isolated environment; save crash logs and link them to pseudocode before reporting. Windows Sandbox support in this build is **UNTESTED**.

## Saved artifacts

`pcode-ssa.csv`, `advanced-graph.json`, `call-edge-checks.json`, `vex-import.json`, `sbom-provenance.json`, `fuzz-coverage.json`, `overflow-leads.json`, `type-signature-diff.json`, and `call-path-gate.json` preserve these results beside the investigation or comparison. Investigation bundles hash every included file for independent integrity checks.
