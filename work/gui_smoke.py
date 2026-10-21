import os
import sys
import time
from pathlib import Path

base = Path(__file__).parent / "testlibs"
sys.path[:0] = [str(base), str(base / "win32"), str(base / "win32" / "lib"), str(base / "pythonwin")]
os.add_dll_directory(str(base / "pywin32_system32"))

from pywinauto import Application, keyboard

app = Application(backend="win32").connect(title_re=r"REA Desktop - REA 6\.5\.0")
dialog = app.top_window()
dialog.set_focus()
rect = dialog.rectangle()
from pywinauto import mouse
mouse.click(coords=(rect.left + 200, rect.top + 198))
target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll")
keyboard.send_keys(str(target), with_spaces=True)
mouse.click(coords=(rect.left + 73, rect.top + 522))

result_dir = Path(os.environ["LOCALAPPDATA"]) / "REA Desktop" / "Results"
started = time.time()
for _ in range(60):
    files = sorted(result_dir.glob(f"{target.stem}-*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    if files and files[0].stat().st_mtime >= started - 2 and files[0].stat().st_size > 0:
        print(files[0])
        print(files[0].stat().st_size)
        dialog.close()
        break
    time.sleep(1)
else:
    raise RuntimeError("GUI did not produce a result within 60 seconds")
