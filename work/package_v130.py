"""Create the user-facing CastorPollux archives."""

from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED, ZIP_STORED
from datetime import datetime, timezone
import os
import shutil

root = Path(__file__).resolve().parent.parent
output = root / "outputs"
source_files = {
    "castorpollux.py": root / "work/castorpollux.py",
    "castorpollux_core.py": root / "work/castorpollux_core.py",
    "castorpollux_workspace.py": root / "work/castorpollux_workspace.py",
    "castorpollux_rea.py": root / "work/castorpollux_rea.py",
    "castorpollux_review.py": root / "work/castorpollux_review.py",
    "castorpollux_report_evidence.py": root / "work/castorpollux_report_evidence.py",
    "rea_binary_studio.py": root / "work/rea_binary_studio.py",
    "scripts/ExportBinaryStudio.java": root / "work/scripts/ExportBinaryStudio.java",
    "scripts/CastorPolluxSymbols.java": root / "work/scripts/CastorPolluxSymbols.java",
    "scripts/TraceInSandbox.ps1": root / "work/scripts/TraceInSandbox.ps1",
    "CastorPollux.spec": root / "work/CastorPollux.spec",
    "content/about.html": root / "work/content/about.html",
    "content/help.html": root / "work/content/help.html",
    "castorpollux_html.py": root / "work/castorpollux_html.py",
    "assets/castorpollux-gemini.png": root / "work/assets/castorpollux-gemini.png",
    "assets/CastorPollux.ico": root / "work/assets/CastorPollux.ico",
    "CastorPollux-README.md": output / "CastorPollux-README.md",
    "CastorPollux-Dashboard-Example.html": output / "CastorPollux-Dashboard-Example.html",
    "CastorPollux-Graph-Lab-Guide.md": output / "CastorPollux-Graph-Lab-Guide.md",
    "CastorPollux-CREDITS.md": output / "CastorPollux-CREDITS.md",
    "CastorPollux-Codex-Prompt.txt": output / "CastorPollux-Codex-Prompt.txt",
    "CastorPollux-Software-Inventory.json": output / "CastorPollux-Software-Inventory.json",
    "CastorPollux-Batch-Example.json": output / "CastorPollux-Batch-Example.json",
    "CastorPollux-CI-Example.ps1": output / "CastorPollux-CI-Example.ps1",
    "castorpollux_quality.py": root / "work/castorpollux_quality.py",
    "castorpollux_batch.py": root / "work/castorpollux_batch.py",
    "castorpollux_integrity.py": root / "work/castorpollux_integrity.py",
    "castorpollux_flow.py": root / "work/castorpollux_flow.py",
    "castorpollux_tracking.py": root / "work/castorpollux_tracking.py",
    "castorpollux_plugins.py": root / "work/castorpollux_plugins.py",
    "castorpollux_bundle.py": root / "work/castorpollux_bundle.py",
    "castorpollux_runtime.py": root / "work/castorpollux_runtime.py",
    "castorpollux_symbols.py": root / "work/castorpollux_symbols.py",
    "castorpollux_sarif.py": root / "work/castorpollux_sarif.py",
    "castorpollux_unpack.py": root / "work/castorpollux_unpack.py",
    "castorpollux_similarity.py": root / "work/castorpollux_similarity.py",
    "castorpollux_findings.py": root / "work/castorpollux_findings.py",
    "castorpollux_settings.py": root / "work/castorpollux_settings.py",
    "castorpollux_drafts.py": root / "work/castorpollux_drafts.py",
    "castorpollux_ui_state.py": root / "work/castorpollux_ui_state.py",
    "castorpollux_secrets.py": root / "work/castorpollux_secrets.py",
    "castorpollux_patch.py": root / "work/castorpollux_patch.py",
    "castorpollux_diagnostics.py": root / "work/castorpollux_diagnostics.py",
    "castorpollux_poc.py": root / "work/castorpollux_poc.py",
    "castorpollux_binary_profile.py": root / "work/castorpollux_binary_profile.py",
    "castorpollux_evidence_tools.py": root / "work/castorpollux_evidence_tools.py",
    "castorpollux_matching.py": root / "work/castorpollux_matching.py",
    "castorpollux_applicability.py": root / "work/castorpollux_applicability.py",
    "castorpollux_callpaths.py": root / "work/castorpollux_callpaths.py",
    "castorpollux_consistency.py": root / "work/castorpollux_consistency.py",
    "castorpollux_interflow.py": root / "work/castorpollux_interflow.py",
    "castorpollux_blocks.py": root / "work/castorpollux_blocks.py",
    "castorpollux_indirect.py": root / "work/castorpollux_indirect.py",
    "castorpollux_sbom.py": root / "work/castorpollux_sbom.py",
    "castorpollux_advanced.py": root / "work/castorpollux_advanced.py",
    "castorpollux_inputs.py": root / "work/castorpollux_inputs.py",
    "castorpollux_changegate.py": root / "work/castorpollux_changegate.py",
    "castorpollux_overflow.py": root / "work/castorpollux_overflow.py",
    "castorpollux_pecheck.py": root / "work/castorpollux_pecheck.py",
    "castorpollux_recovery.py": root / "work/castorpollux_recovery.py",
    "castorpollux_usage.py": root / "work/castorpollux_usage.py",
    "castorpollux_intelligence.py": root / "work/castorpollux_intelligence.py",
    "castorpollux_preflight.py": root / "work/castorpollux_preflight.py",
    "castorpollux_metrics.py": root / "work/castorpollux_metrics.py",
    "castorpollux_dashboard_export.py": root / "work/castorpollux_dashboard_export.py",
    "castorpollux_drop.py": root / "work/castorpollux_drop.py",
    "castorpollux_ui_support.py": root / "work/castorpollux_ui_support.py",
    "release_attestation.py": root / "work/release_attestation.py",
    "release_license_inventory.py": root / "work/release_license_inventory.py",
    "CastorPollux-License-Inventory.json": output / "CastorPollux-License-Inventory.json",
    "CastorPollux-Commercial-License-Audit.md": output / "CastorPollux-Commercial-License-Audit.md",
    "release_sign.py": root / "work/release_sign.py",
    "release_inventory.py": root / "work/release_inventory.py",
    "build_release.py": root / "work/build_release.py",
    "build_github_archive.py": root / "work/build_github_archive.py",
    "test_castorpollux_v190.py": root / "work/test_castorpollux_v190.py",
    "test_castorpollux_v200.py": root / "work/test_castorpollux_v200.py",
    "test_castorpollux_v210.py": root / "work/test_castorpollux_v210.py",
    "test_castorpollux_v220.py": root / "work/test_castorpollux_v220.py",
    "test_castorpollux_v230.py": root / "work/test_castorpollux_v230.py",
    "test_castorpollux_v240.py": root / "work/test_castorpollux_v240.py",
    "test_castorpollux_v250.py": root / "work/test_castorpollux_v250.py",
    "test_castorpollux_v260.py": root / "work/test_castorpollux_v260.py",
    "test_castorpollux_v270.py": root / "work/test_castorpollux_v270.py",
    "test_castorpollux_v280.py": root / "work/test_castorpollux_v280.py",
    "test_castorpollux_v281.py": root / "work/test_castorpollux_v281.py",
    "test_castorpollux_v290.py": root / "work/test_castorpollux_v290.py",
    "test_castorpollux_v300.py": root / "work/test_castorpollux_v300.py",
    "test_castorpollux_v310.py": root / "work/test_castorpollux_v310.py",
    "test_castorpollux_v320.py": root / "work/test_castorpollux_v320.py",
    "test_castorpollux_v330.py": root / "work/test_castorpollux_v330.py",
    "test_castorpollux_v340.py": root / "work/test_castorpollux_v340.py",
    "test_castorpollux_report_evidence.py": root / "work/test_castorpollux_report_evidence.py",
    "test_castorpollux_v100.py": root / "work/test_castorpollux_v100.py",
    "test_castorpollux_brand.py": root / "work/test_castorpollux_brand.py",
    "test_castorpollux_v100_ui.py": root / "work/test_castorpollux_v100_ui.py",
    "test_castorpollux_packaged_v100.py": root / "work/test_castorpollux_packaged_v100.py",
    "CastorPollux-Advisory-Rules-Example.json": output / "CastorPollux-Advisory-Rules-Example.json",
}

epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
stamp = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc).timetuple()[:6]


def add(archive, path, name, compression):
    info = ZipInfo(name, date_time=stamp)
    info.compress_type = compression
    info.external_attr = 0o644 << 16
    with path.open("rb") as source, archive.open(info, "w", force_zip64=True) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)

with ZipFile(output / "CastorPollux-Source.zip", "w", ZIP_DEFLATED, compresslevel=6) as archive:
    for name, path in sorted(source_files.items()):
        add(archive, path, name, ZIP_DEFLATED)

with ZipFile(output / "CastorPollux-Package.zip", "w") as archive:
    for name in ("CastorPollux.exe", "CastorPollux-README.md", "CastorPollux-Dashboard-Example.html",
                 "CastorPollux-CREDITS.md",
                 "CastorPollux-Graph-Lab-Guide.md",
                 "CastorPollux-Codex-Prompt.txt", "CastorPollux-SHA256.txt",
                 "CastorPollux-Software-Inventory.json", "CastorPollux-Batch-Example.json",
                 "CastorPollux-License-Inventory.json", "CastorPollux-Commercial-License-Audit.md",
                 "CastorPollux-CI-Example.ps1", "CastorPollux-Flow-Rules-Example.json",
                 "CastorPollux-Plugin-Example.json", "CastorPollux-Advisory-Rules-Example.json"):
        add(archive, output / name, name, ZIP_STORED if name.endswith(".exe") else ZIP_DEFLATED)
    add(archive, output / "CastorPollux-Release-Attestation.json", "CastorPollux-Release-Attestation.json", ZIP_DEFLATED)
    for name in ("castorpollux-gemini.png", "CastorPollux.ico"):
        add(archive, root / "work/assets" / name, name, ZIP_DEFLATED)
    for path in sorted((output / "CastorPollux-Licenses").iterdir()):
        if path.is_file():
            add(archive, path, "CastorPollux-Licenses/" + path.name, ZIP_DEFLATED)

print("Created source and package archives")
