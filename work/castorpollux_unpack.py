"""Bounded, nonexecuting archive extraction and firmware executable carving."""

from __future__ import annotations

import gzip
import json
import lzma
import re
import struct
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath

from castorpollux_core import sha256

MAX_INPUT = 512 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024 * 1024
MAX_FILES = 500
MAX_DEPTH = 2


def _safe_name(name: str) -> Path:
    normalized = name.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if not parts or normalized.startswith("/") or any(part in ("..", ".") for part in parts):
        raise ValueError("Archive contains an unsafe path")
    if any(":" in part or re.search(r"[<>\"|?*]", part) for part in parts):
        raise ValueError("Archive contains an unsafe Windows filename")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if any(part.rstrip(". ") != part or part.split(".")[0].upper() in reserved for part in parts):
        raise ValueError("Archive contains a reserved Windows filename")
    return Path(*parts)


def _format(path: Path) -> str:
    with path.open("rb") as stream:
        head = stream.read(6)
    if head[:2] == b"MZ":
        return "PE"
    if head[:4] == b"\x7fELF":
        return "ELF"
    return "other"


def _carve_length(blob: bytes, offset: int, kind: str) -> int:
    available = len(blob) - offset
    if kind == "PE" and available >= 256:
        pe = struct.unpack_from("<I", blob, offset + 60)[0]
        if pe + 24 > available or blob[offset + pe:offset + pe + 4] != b"PE\0\0":
            return 0
        count, optional_size = struct.unpack_from("<H", blob, offset + pe + 6)[0], struct.unpack_from("<H", blob, offset + pe + 20)[0]
        if count < 1 or count > 96 or optional_size < 96 or pe + 24 + optional_size + count * 40 > available:
            return 0
        end = pe + 24 + optional_size + count * 40
        for i in range(count):
            section = offset + pe + 24 + optional_size + i * 40
            raw_size, pointer = struct.unpack_from("<II", blob, section + 16)
            end = max(end, pointer + raw_size)
        return end if end <= available else 0
    if kind == "ELF" and available >= 64 and blob[offset + 4] in (1, 2) and blob[offset + 5] in (1, 2):
        endian = "<" if blob[offset + 5] == 1 else ">"
        is32 = blob[offset + 4] == 1
        fmt = endian + ("HHIIIIIHHHHHH" if is32 else "HHIQQQIHHHHHH")
        try:
            header = struct.unpack_from(fmt, blob, offset + 16)
            phoff, shoff = header[4], header[5]
            phsize, phnum, shsize, shnum = header[8], header[9], header[10], header[11]
            if phnum > 1024 or shnum > 65535:
                return 0
            end = max(16 + struct.calcsize(fmt), phoff + phsize * phnum, shoff + shsize * shnum)
            for i in range(phnum):
                at = offset + phoff + i * phsize
                part = struct.unpack_from(endian + ("I" if is32 else "Q"), blob, at + (4 if is32 else 8))[0]
                length = struct.unpack_from(endian + ("I" if is32 else "Q"), blob, at + (16 if is32 else 32))[0]
                end = max(end, part + length)
            for i in range(shnum):
                at = offset + shoff + i * shsize
                section_type = struct.unpack_from(endian + "I", blob, at + 4)[0]
                if section_type != 8:
                    part, length = (struct.unpack_from(endian + "II", blob, at + 16) if is32 else
                                    struct.unpack_from(endian + "QQ", blob, at + 24))
                    end = max(end, part + length)
            return end if 0 < end <= available else 0
        except (struct.error, IndexError):
            return 0
    return 0


def unpack_binary(source: Path, destination: Path) -> dict:
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_file() or source.stat().st_size > MAX_INPUT:
        raise ValueError("Input must be a file of at most 512 MiB")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("Choose an empty output directory")
    destination.mkdir(parents=True, exist_ok=True)
    files = []
    budget = MAX_OUTPUT
    hashes: dict[str, str] = {}
    paths: set[str] = set()
    bytes_saved = 0

    def save(relative: Path, reader, size: int, origin: str):
        nonlocal budget, bytes_saved
        if len(files) >= MAX_FILES or size > budget or size < 0:
            raise ValueError("Unpack limit exceeded (500 files or 1 GiB extracted)")
        target = destination / relative
        if relative.as_posix() in paths or target.exists():
            raise ValueError(f"Duplicate extracted path: {relative}")
        paths.add(relative.as_posix())
        target.parent.mkdir(parents=True, exist_ok=True)
        remaining = size
        with target.open("wb") as output:
            while remaining:
                chunk = reader.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("Truncated archive member")
                output.write(chunk)
                remaining -= len(chunk)
        budget -= size
        digest = sha256(target)
        kind = _format(target)
        stored = hashes.get(digest)
        row = {"path": relative.as_posix(), "bytes": size, "sha256": digest,
               "format": kind, "origin": origin}
        if stored is not None:
            target.unlink()
            row["duplicate_of"] = stored
            row["stored_path"] = stored
            bytes_saved += size
            target = destination / stored
        else:
            hashes[digest] = relative.as_posix()
            row["stored_path"] = relative.as_posix()
        files.append(row)
        return target

    def extract(path: Path, prefix: Path, depth: int):
        if depth > MAX_DEPTH:
            return False
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for item in archive.infolist():
                    if item.is_dir():
                        continue
                    if item.flag_bits & 1 or (item.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError("Encrypted entries and links are not supported")
                    with archive.open(item) as stream:
                        target = save(prefix / _safe_name(item.filename), stream, item.file_size, str(path))
                    if depth < MAX_DEPTH:
                        extract(target, prefix / _safe_name(item.filename).with_suffix(""), depth + 1)
            return True
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                for item in archive:
                    if item.isdir():
                        continue
                    if not item.isfile():
                        raise ValueError("Archive links and special files are not supported")
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise ValueError("Cannot read archive member")
                    with stream:
                        target = save(prefix / _safe_name(item.name), stream, item.size, str(path))
                    if depth < MAX_DEPTH:
                        extract(target, prefix / _safe_name(item.name).with_suffix(""), depth + 1)
            return True
        suffix = path.suffix.lower()
        if suffix in (".gz", ".xz"):
            opener = gzip.open if suffix == ".gz" else lzma.open
            # Read in chunks through the bounded save path; compressed size is not an output bound.
            with opener(path, "rb") as stream:
                chunks = []
                total = 0
                while True:
                    chunk = stream.read(min(1024 * 1024, budget + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > budget:
                        raise ValueError("Unpack size limit exceeded")
                    chunks.append(chunk)
            from io import BytesIO
            target = save(prefix / _safe_name(path.stem), BytesIO(b"".join(chunks)), total, str(path))
            if depth < MAX_DEPTH:
                extract(target, prefix / _safe_name(path.stem).with_suffix(""), depth + 1)
            return True
        return False

    if not extract(source, Path("files"), 0):
        blob = source.read_bytes()
        offsets = sorted(set([index for magic in (b"MZ", b"\x7fELF")
                              for index in _find_all(blob, magic)]))
        for offset in offsets:
            if offset == 0 and len(offsets) == 1 and _format(source) in ("PE", "ELF"):
                continue
            kind = "PE" if blob[offset:offset + 2] == b"MZ" else "ELF"
            length = _carve_length(blob, offset, kind)
            if length:
                from io import BytesIO
                save(Path("carved") / f"{offset:08x}.{kind.lower()}",
                     BytesIO(blob[offset:offset + length]), length, f"{source.name} @ 0x{offset:x}")
    report = {"source": str(source), "source_sha256": sha256(source),
              "created_at": datetime.now().astimezone().isoformat(), "files": files,
              "unique_files": len(hashes), "duplicate_files": len(files) - len(hashes),
              "bytes_saved": bytes_saved,
              "limitations": "Archives: ZIP, TAR, GZIP, XZ. Raw firmware: validated PE/ELF carving only; filesystems, compression formats and UEFI structures may be missed. No extracted file is executed."}
    (destination / "unpack-manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def _find_all(blob: bytes, needle: bytes):
    start = 0
    while (offset := blob.find(needle, start)) >= 0:
        yield offset
        start = offset + 1
