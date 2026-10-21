"""Hash-verified, portable investigation bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath

from castorpollux_core import APP_VERSION, sha256

MANIFEST = "bundle-manifest.json"


def export_bundle(folder: Path, destination: Path) -> dict:
    folder, destination = Path(folder).resolve(), Path(destination).resolve()
    investigation = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if not destination.parent.is_dir():
        raise ValueError("Choose an existing output folder for the bundle")
    if destination == folder or folder in destination.parents:
        raise ValueError("Save the bundle outside the investigation folder")
    files = sorted(path for path in folder.rglob("*") if path.is_file())
    if any(path.is_symlink() for path in files):
        raise ValueError("Investigation contains symlinks; bundle export requires regular files")
    records = [{"path": path.relative_to(folder).as_posix(), "bytes": path.stat().st_size,
                "sha256": sha256(path)} for path in files]
    manifest = {"schema": 1, "application_version": APP_VERSION,
                "created_at": datetime.now().astimezone().isoformat(),
                "investigation_name": folder.name,
                "binary_sha256": investigation["sha256"], "files": records}
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as archive:
            archive.writestr(MANIFEST, json.dumps(manifest, indent=2))
            for path in files:
                name = "investigation/" + path.relative_to(folder).as_posix()
                archive.write(path, name, compress_type=zipfile.ZIP_DEFLATED, compresslevel=4)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {"bundle": str(destination), "sha256": sha256(destination),
            "files": len(files), "binary_sha256": investigation["sha256"]}


def _safe_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and \
           "\\" not in value and ":" not in value and not value.startswith("/")


def verify_bundle(bundle: Path) -> dict:
    bundle = Path(bundle).resolve()
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or MANIFEST not in names:
            raise ValueError("Bundle has duplicate entries or no manifest")
        if len(names) > 100_001:
            raise ValueError("Bundle has too many entries")
        manifest = json.loads(archive.read(MANIFEST))
        if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), list):
            raise ValueError("Unsupported bundle manifest")
        expected = {"investigation/" + record["path"] for record in manifest["files"]}
        if set(names) != expected | {MANIFEST}:
            raise ValueError("Bundle entries do not match its manifest")
        for record in manifest["files"]:
            path = record.get("path", "")
            if not _safe_path(path) or not re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")):
                raise ValueError("Bundle contains an unsafe or invalid file record")
            entry = archive.getinfo("investigation/" + path)
            if entry.is_dir() or entry.file_size != record.get("bytes"):
                raise ValueError(f"Bundle size mismatch: {path}")
            digest = hashlib.sha256()
            with archive.open(entry) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != record["sha256"]:
                raise ValueError(f"Bundle hash mismatch: {path}")
        saved = json.loads(archive.read("investigation/manifest.json"))
        if saved.get("sha256") != manifest.get("binary_sha256"):
            raise ValueError("Bundle target hash does not match its investigation manifest")
        binary = next((record for record in manifest["files"]
                       if record["path"] == saved.get("saved_binary")), None)
        if not binary or binary["sha256"] != saved["sha256"]:
            raise ValueError("Bundle target binary failed manifest verification")
        return {"status": "verified", "bundle": str(bundle), "sha256": sha256(bundle),
                "files": len(manifest["files"]), "binary_sha256": saved["sha256"],
                "investigation_name": manifest.get("investigation_name", "investigation")}


def import_bundle(bundle: Path, destination_parent: Path) -> Path:
    result = verify_bundle(bundle)
    parent = Path(destination_parent).resolve()
    if not parent.is_dir():
        raise ValueError("Choose an existing folder for the imported investigation")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", result["investigation_name"]).strip("._") or "investigation"
    destination = parent / name
    if destination.exists():
        raise FileExistsError("An investigation with this name already exists in the destination")
    temporary = Path(tempfile.mkdtemp(prefix="castorpollux-import-", dir=parent))
    try:
        with zipfile.ZipFile(bundle) as archive:
            manifest = json.loads(archive.read(MANIFEST))
            for record in manifest["files"]:
                target = temporary / record["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open("investigation/" + record["path"]) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
