"""Compile and invoke the optional Ghidra symbol pre-script headlessly."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from castorpollux_core import ComponentStore

store = ComponentStore()
ghidra, jdk, _, _ = store.analysis_paths(lambda _: None, lambda: False)
with tempfile.TemporaryDirectory(prefix="castorpollux-symbols-") as temp:
    root = Path(temp)
    source = Path(r"C:\Windows\System32\where.exe")
    pdb = root / "sample.pdb"
    pdb.write_bytes(b"invalid-test-pdb")
    exports = root / "exports"
    exports.mkdir()
    project = root / "project"
    project.mkdir()
    env = os.environ.copy()
    env.update({"JAVA_HOME": str(jdk), "GHIDRA_INSTALL_DIR": str(ghidra),
                "GHIDRA_HEADLESS_MAXMEM": "2G"})
    env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
    command = [str(ghidra / "support" / "analyzeHeadless.bat"), str(project), "Analysis",
               "-import", str(source), "-scriptPath", str(Path(__file__).parent / "scripts"),
               "-preScript", "CastorPolluxSymbols.java", "pdb", str(pdb),
               "-postScript", "ExportBinaryStudio.java", str(exports),
               "-analysisTimeoutPerFile", "120"]
    result = subprocess.run(command, env=env, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180)
    combined = result.stdout + result.stderr
    assert "CASTORPOLLUX_SYMBOLS PDB configured" in combined, combined[-6000:]
    assert (exports / "functions.csv").is_file(), combined[-6000:]
    dwarf = root / "sample.debug"
    dwarf.write_bytes(b"invalid-test-dwarf")
    dwarf_project = root / "dwarf-project"
    dwarf_project.mkdir()
    dwarf_exports = root / "dwarf-exports"
    dwarf_exports.mkdir()
    dwarf_command = [str(ghidra / "support" / "analyzeHeadless.bat"), str(dwarf_project), "Analysis",
                     "-import", str(source), "-scriptPath", str(Path(__file__).parent / "scripts"),
                     "-noanalysis", "-preScript", "CastorPolluxSymbols.java", "dwarf", str(dwarf),
                     "-postScript", "ExportBinaryStudio.java", str(dwarf_exports)]
    dwarf_result = subprocess.run(dwarf_command, env=env, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=180)
    combined = dwarf_result.stdout + dwarf_result.stderr
    assert "CASTORPOLLUX_SYMBOLS DWARF search configured" in combined, combined[-6000:]
    print("Ghidra PDB and DWARF symbol pre-script paths completed")
