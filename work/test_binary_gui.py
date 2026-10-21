import json
import os
import sys
import tempfile
import time
from pathlib import Path

base = Path(__file__).parent / "testlibs"
sys.path[:0] = [str(base), str(base / "win32"), str(base / "win32" / "lib"), str(base / "pythonwin")]
os.add_dll_directory(str(base / "pywin32_system32"))

from pywinauto import Application, keyboard, mouse

app = Application(backend="win32").connect(title="REA Binary Studio")
dialog = app.top_window()
dialog.set_focus()
rect = dialog.rectangle()
target = r"C:\Windows\System32\where.exe"
destination = Path(tempfile.mkdtemp(prefix="castorpollux-packaged-test-"))
mouse.click(coords=(rect.left + 200, rect.top + 218))
keyboard.send_keys(target, with_spaces=True)
mouse.click(coords=(rect.left + 200, rect.top + 309))
keyboard.send_keys("^a")
keyboard.send_keys(str(destination), with_spaces=True)
mouse.click(coords=(rect.left + 100, rect.top + 426))

started = time.time()
for _ in range(180):
    folders = sorted(destination.glob("where-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if folders and (folders[0] / "manifest.json").exists():
        manifest = json.loads((folders[0] / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("finished_at"):
            print(json.dumps({"output": str(folders[0]), "ghidra_status": manifest["ghidra_status"],
                              "rea_status": manifest["rea_status"]}))
            dialog.close()
            break
    time.sleep(1)
else:
    raise RuntimeError("Packaged GUI did not finish within three minutes")
