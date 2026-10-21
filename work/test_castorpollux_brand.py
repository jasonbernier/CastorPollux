"""Brand, artwork, and prior-user-data checks for the 1.0.0 release."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from castorpollux_core import APP_NAME, APP_VERSION, home


class BrandTests(unittest.TestCase):
    def test_identity_and_artwork(self):
        self.assertEqual((APP_NAME, APP_VERSION), ("CastorPollux", "1.0.0"))
        asset = Path(__file__).parent / "assets" / "castorpollux-gemini.png"
        icon = asset.with_name("CastorPollux.ico")
        with Image.open(asset) as graphic, Image.open(icon) as windows_icon:
            self.assertEqual(graphic.mode, "RGBA")
            self.assertEqual(windows_icon.format, "ICO")
            self.assertGreaterEqual(graphic.size[0], 256)

    def test_previous_investigations_migrate(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / "HexVigil"
            legacy.mkdir()
            (legacy / "investigations.json").write_text("[]", encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": directory}):
                current = home()
            self.assertEqual(current.name, "CastorPollux")
            self.assertEqual((current / "investigations.json").read_text(encoding="utf-8"), "[]")
            self.assertFalse(legacy.exists())

    def test_existing_new_folder_imports_missing_history(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            legacy = base / "HexVigil"
            legacy.mkdir()
            (legacy / "investigations.json").write_text("[]", encoding="utf-8")
            current = base / "CastorPollux"
            current.mkdir()
            (current / "settings.json").write_text('{"theme":"Daylight"}', encoding="utf-8")
            with patch.dict(os.environ, {"LOCALAPPDATA": directory}):
                self.assertEqual(home(), current)
            self.assertEqual((current / "investigations.json").read_text(encoding="utf-8"), "[]")
            self.assertEqual((current / "settings.json").read_text(encoding="utf-8"),
                             '{"theme":"Daylight"}')
            self.assertTrue((current / ".legacy-migration-complete").is_file())


if __name__ == "__main__":
    unittest.main()
