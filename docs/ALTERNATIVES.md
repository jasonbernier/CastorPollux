# Related binary-analysis tools

CastorPollux combines REA/Ghidra reconstruction, saved evidence, agent review, CVE leads, and report workflows in one Windows desktop package. Other tools cover substantial parts of this workflow; compare their current editions and licenses before choosing one.

| Tool | Strong overlap | Difference from CastorPollux's packaged workflow |
|---|---|---|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Decompilation, disassembly, Function ID, Version Tracking, scripts | CastorPollux bundles Ghidra, adds REA and a guided multi-agent review/report layer. |
| [BinDiff](https://github.com/google/bindiff) | Function matching and patch comparison across binaries | Focuses on high-quality binary diffing and uses a separate disassembler. CastorPollux's built-in matching is more limited. |
| [Binary Ninja 6.0](https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html) | Decompilation, Binary Similarity, first-party MCP access for agents | Its matching and analysis stack differ; Binary Similarity is documented as an Ultimate feature. |
| [IDA and Lumina](https://hex-rays.com/lumina) | Decompilation, function recognition, metadata transfer | CastorPollux uses REA/Ghidra and a separate report workflow rather than IDA databases or Lumina. |
| [Binarly Transparency Platform](https://www.binarly.io/features) | Binary and firmware risk analysis, SBOM validation, exploit-aware scoring, release controls | Binarly already covers many supply-chain and reachability ideas. CastorPollux focuses on a local, inspectable REA-to-agent workflow and saved evidence. |
| [angr](https://docs.angr.io/) | Program analysis and symbolic execution | CastorPollux's boundary inputs and static leads do not replace angr's path constraints or execution models. |

CastorPollux's function matching uses normalized reconstructed code and conservative ambiguity checks. It is not a replacement for mature graph-based diffing such as BinDiff. The Graph Lab adds visible SSA edges, VEX claims, fuzz overlays, and a raw-byte PE edge check, but these are not unique capabilities across the market. A promising product direction is the integrated chain from a review claim to pseudocode, disassembly, independent checks, test input, and CI decision. An agent's finding is a lead until verified against the binary and its execution context.
