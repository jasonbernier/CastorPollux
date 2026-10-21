# Build CastorPollux on Windows

This repository contains CastorPollux application source and build scripts. The large upstream runtime inputs are deliberately excluded from Git. The current release recipe expects a prepared Windows x64 build workspace; it is **not yet a one-command clean-room build**. Keep the exact fetched artifacts and their checksums with each release record.

## Prerequisites

- Windows x64, Python 3.12, and enough disk space for the 1 GB class self-extracting EXE plus PyInstaller intermediates and extracted engines.
- Install Python build packages: `py -3.12 -m pip install -r requirements-build.txt`.
- Prepare the following exact relative paths under the repository root before invoking PyInstaller:

| Path | Input | Expected SHA-256 / identity |
|---|---|---|
| `work/archives/ghidra_12.1.4_PUBLIC_20260921.zip` | Official Ghidra 12.1.4 Windows release archive | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| `work/archives/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip` | Official Eclipse Temurin JDK 21.0.12.1+1 Windows x64 archive | `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e` |
| `work/runtime/node.exe` | Official Node.js 24.19.0 Windows x64 executable | `3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237` |
| `work/runtime/node_modules/rea-agents/scripts/rea.mjs` | `rea-agents` 6.5.0 plus its installed npm dependency tree | Script SHA-256 `526105418604cc6e5a202a6275b700814e27450bfaffd45e7510530ba669de8d` |
| `work/runtime/pnpm/` | Local pnpm 11 distribution and dependencies | Compare release `CastorPollux-License-Inventory.json` and software inventory |

Fetch upstream components from their official publishers: [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases), [Eclipse Temurin](https://adoptium.net/temurin/releases/), [Node.js](https://nodejs.org/en/download), [REA](https://github.com/morluto/rea), and [pnpm](https://pnpm.io/installation). Verify published signatures/checksums as available and also compare the listed hashes with `Get-FileHash` before building. The release inventory records versions and the shipped tree; an independently regenerated lockfile and fully automated dependency bootstrap are still needed for stronger reproducibility.

The checked-in `outputs/` folder contains small documentation templates and license notices required by `work/CastorPollux.spec` and `work/build_release.py`. The build generates the EXE, inventory, attestation, hash file, source ZIP, and package ZIP there. Do not edit generated hashes by hand.

The checked-in `work/assets/castorpollux-gemini.png` and `work/assets/CastorPollux.ico` are required build inputs. PyInstaller embeds the icon in the EXE and includes the PNG for the navigation and About screen.

## Build and test

From the repository root in PowerShell:

```powershell
py -3.12 -m pip install -r requirements-build.txt
py -3.12 work/test_castorpollux_v220.py
py -3.12 work/test_castorpollux_v230.py
py -3.12 work/test_castorpollux_v240.py
py -3.12 work/test_castorpollux_brand.py
py -3.12 work/build_release.py
Get-FileHash .\outputs\CastorPollux.exe -Algorithm SHA256
Get-Content .\outputs\CastorPollux-SHA256.txt
```

`build_release.py` runs PyInstaller using `work/CastorPollux.spec`, copies `dist/CastorPollux.exe` into `outputs/`, and produces both release ZIPs. `SOURCE_DATE_EPOCH` can be set before the build to stabilize ZIP timestamps and attestation time. Byte-for-byte reproducibility has not been independently confirmed across separate machines. Signing requires a distributor certificate and `CASTORPOLLUX_SIGNING_THUMBPRINT`; `--require-signature` rejects an unsigned EXE.

For a quick source syntax check: `py -3.12 -m compileall -q work`. A meaningful engine smoke test requires the prepared runtime and a permitted sample binary. Review `ghidra.log`, `rea.log`, `manifest.json`, procedure coverage, and generated `rea-pseudocode.c` before promoting a release. Agent review needs a separately installed and authenticated CLI or local Ollama model and should be tested with a controlled sample.

## Source layout and redistribution

The large engine ZIPs and runtime trees stay outside Git; the self-extracting EXE and optional `CastorPollux-Package.zip` belong in a GitHub Release. Do not commit investigations or generated reports because they may include proprietary code, credentials, or candidate scripts. Consult [the commercial audit](COMMERCIAL_LICENSE_AUDIT.md) before public binary distribution. Its listed third-party source and notice obligations remain unresolved for paid redistribution; an unsigned local attestation is not a release signature.
