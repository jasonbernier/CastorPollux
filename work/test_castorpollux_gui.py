import json
import os
import sys
import time
from pathlib import Path

base = Path(__file__).parent / "testlibs"
sys.path[:0] = [str(base), str(base / "win32"), str(base / "win32" / "lib"), str(base / "pythonwin")]
os.add_dll_directory(str(base / "pywin32_system32"))

from pywinauto import Desktop, keyboard, mouse

window = next(w for w in Desktop(backend="win32").windows() if "CastorPollux  |" in w.window_text())
window.set_focus()
rect = window.rectangle()
mouse.click(coords=(rect.left + 88, rect.top + 182))
mouse.click(coords=(rect.left + 370, rect.top + 270))
keyboard.send_keys(r"C:\Windows\System32\where.exe", with_spaces=True)
destination = Path(__file__).parent / "castorpollux-packaged-output"
destination.mkdir(exist_ok=True)
mouse.click(coords=(rect.left + 370, rect.top + 370))
keyboard.send_keys("^a")
keyboard.send_keys(str(destination.resolve()), with_spaces=True)
mouse.click(coords=(rect.left + 320, rect.top + 450))
started = time.time()
for _ in range(180):
    folders = sorted(destination.glob("where-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if folders and (folders[0] / "manifest.json").exists():
        manifest = json.loads((folders[0] / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("finished_at"):
            print(json.dumps({"output": str(folders[0]), "ghidra_status": manifest["ghidra_status"],
                              "rea_status": manifest["rea_status"], "versions": manifest["versions"]}))
            break
    time.sleep(1)
else:
    raise RuntimeError("Packaged analysis did not finish within three minutes")
