"""Inventory license declarations and legal files inside the shipped component tree."""

from __future__ import annotations

import hashlib
import ast
import importlib.metadata
import json
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from release_attestation import build_time


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(root: Path) -> Path:
    root = Path(root).resolve()
    def packages(modules: Path) -> list[dict]:
        found = []
        for directory in modules.iterdir():
            children = list(directory.iterdir()) if directory.name.startswith("@") else [directory]
            for child in children:
                package = child / "package.json"
                if not package.is_file():
                    continue
                data = json.loads(package.read_text(encoding="utf-8"))
                notices = sorted(path.name for path in child.iterdir() if path.is_file() and
                                 (path.name.lower().startswith(("license", "copying", "notice"))))
                found.append({"name": data.get("name", child.name), "version": data.get("version", ""),
                              "declared_license": data.get("license", "UNKNOWN"),
                              "package_json_sha256": _digest(package.read_bytes()),
                              "local_notice_files": notices})
        return sorted(found, key=lambda item: item["name"].casefold())
    npm = packages(root / "work/runtime/node_modules")
    pnpm = packages(root / "work/runtime/pnpm/dist/node_modules")
    nested_npm = []
    npm_root = root / "work/runtime/node_modules"
    for package in npm_root.rglob("package.json"):
        relative = package.relative_to(npm_root)
        parts = relative.parts
        if ".pnpm" in parts or len(parts) == 2 or (parts[0].startswith("@") and len(parts) == 3):
            continue
        try:
            metadata = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if metadata.get("name") and metadata.get("version"):
            nested_npm.append({"name": metadata["name"], "version": metadata["version"],
                               "declared_license": metadata.get("license", "UNKNOWN"),
                               "path": relative.as_posix(),
                               "package_json_sha256": _digest(package.read_bytes())})
    nested_npm.sort(key=lambda item: item["path"])
    vendor = [{"path": str(path.relative_to(root / "work/runtime/pnpm")).replace("\\", "/"),
               "sha256": _file_digest(path)} for path in
              sorted((root / "work/runtime/pnpm/dist/vendor").rglob("*")) if path.is_file()]
    ghidra_archive = next((root / "work/archives").glob("ghidra_*.zip"))
    jdk_archive = next((root / "work/archives").glob("OpenJDK*.zip"))
    archives = {}
    for name, path, predicate in (
        ("ghidra", ghidra_archive, lambda item: item.endswith("LICENSE.txt") or
         "/licenses/" in item or item.endswith(("/LICENSE", "/NOTICE", "/DISCLAIMER"))),
        ("temurin", jdk_archive, lambda item: "/legal/" in item and not item.endswith("/"))):
        with zipfile.ZipFile(path) as archive:
            entries = [{"path": item.filename, "sha256": _digest(archive.read(item))}
                       for item in archive.infolist() if not item.is_dir() and predicate(item.filename)]
        archives[name] = {"archive": path.name, "archive_sha256": _file_digest(path),
                          "legal_files": entries, "legal_file_count": len(entries)}
    licensing = root / "outputs/CastorPollux-Licenses"
    documents = [{"path": path.name, "sha256": _digest(path.read_bytes())}
                 for path in sorted(licensing.iterdir()) if path.is_file()]
    toc = root / "build/CastorPollux/Analysis-00.toc"
    frozen = []
    if toc.is_file():
        analysis = ast.literal_eval(toc.read_text(encoding="utf-8"))
        names = set()
        for index in (11, 14, 15, 18):
            for item in analysis[index]:
                if len(item) > 1 and isinstance(item[1], str) and "site-packages\\" in item[1].lower():
                    names.add(item[1].lower().split("site-packages\\", 1)[1].split("\\", 1)[0])
        for name in sorted(names):
            distribution = "Pillow" if name == "pil" else "charset-normalizer" if name == "charset_normalizer" else name
            try:
                metadata = importlib.metadata.metadata(distribution)
                frozen.append({"name": distribution, "version": metadata.get("Version", ""),
                               "declared_license": metadata.get("License-Expression") or metadata.get("License", "UNKNOWN")})
            except importlib.metadata.PackageNotFoundError:
                frozen.append({"name": distribution, "version": "", "declared_license": "UNKNOWN"})
    data = {"generated_at": build_time(),
            "scope": "Files embedded in the CastorPollux build; optional agent CLIs and separately installed tools are not bundled.",
            "npm_packages": npm, "npm_count": len(npm),
            "npm_nested_packages": nested_npm, "npm_nested_count": len(nested_npm),
            "npm_declared_license_counts": dict(sorted(Counter(str(item["declared_license"]) for item in npm).items())),
            "pnpm_embedded_packages": pnpm, "pnpm_embedded_count": len(pnpm),
            "pnpm_vendor_files": vendor,
            "frozen_python_packages": frozen,
            "component_archives": archives, "sidecar_license_documents": documents,
            "note": "A package.json declaration alone does not settle all copyright and redistribution duties; inspect the bundled notices and source obligations before commercial release."}
    target = root / "outputs/CastorPollux-License-Inventory.json"
    target.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return target


if __name__ == "__main__":
    print(generate(Path(__file__).resolve().parent.parent))
