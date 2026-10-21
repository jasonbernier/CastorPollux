"""Fail-closed identity checks for local PDB and ELF debug companions."""

from __future__ import annotations

import struct
import uuid
import hashlib
import os
import urllib.request
import json
import shutil
from datetime import timedelta
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from rea_binary_studio import sha256


def _read_at(stream, offset: int, size: int, file_size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > file_size:
        raise ValueError("Symbol or binary header points outside the file")
    stream.seek(offset)
    value = stream.read(size)
    if len(value) != size:
        raise ValueError("Truncated symbol or binary header")
    return value


def _pdb_identity(path: Path) -> tuple[str, int]:
    size = path.stat().st_size
    with path.open("rb") as f:
        header = _read_at(f, 0, 56, size)
        if not header.startswith(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"):
            raise ValueError("Only MSF 7 PDB files can be verified")
        block, _, count, directory_size, _, map_block = struct.unpack_from("<6I", header, 32)
        if block not in (512, 1024, 2048, 4096) or count * block > size or directory_size > 64 * 1024 * 1024:
            raise ValueError("Invalid PDB block layout")
        blocks = (directory_size + block - 1) // block
        # The MSF block map occupies contiguous blocks when the directory is large.
        indexes = struct.unpack("<" + "I" * blocks, _read_at(f, map_block * block, blocks * 4, size))
        directory = b"".join(_read_at(f, index * block, block, size) for index in indexes)[:directory_size]
        if len(directory) < 12:
            raise ValueError("PDB stream directory is missing")
        streams = struct.unpack_from("<I", directory)[0]
        if streams < 2 or streams > 1_000_000 or len(directory) < 4 + streams * 4:
            raise ValueError("PDB stream table is invalid")
        lengths = struct.unpack_from("<" + "I" * streams, directory, 4)
        cursor = 4 + streams * 4
        info_blocks = []
        for index, length in enumerate(lengths):
            needed = 0 if length == 0xffffffff else (length + block - 1) // block
            if cursor + needed * 4 > len(directory):
                raise ValueError("PDB stream blocks are truncated")
            if index == 1:
                info_blocks = struct.unpack_from("<" + "I" * needed, directory, cursor)
            cursor += needed * 4
        if lengths[1] < 28 or not info_blocks:
            raise ValueError("PDB identity stream is missing")
        info = b"".join(_read_at(f, index * block, block, size) for index in info_blocks)[:28]
        return str(uuid.UUID(bytes_le=info[12:28])), struct.unpack_from("<I", info, 8)[0]


def _pe_codeview(path: Path) -> tuple[str, int, str]:
    size = path.stat().st_size
    with path.open("rb") as f:
        dos = _read_at(f, 0, 64, size)
        if dos[:2] != b"MZ":
            raise ValueError("PDB symbols require a PE binary")
        pe = struct.unpack_from("<I", dos, 60)[0]
        head = _read_at(f, pe, 24, size)
        if head[:4] != b"PE\x00\x00":
            raise ValueError("Invalid PE header")
        sections, optional_size = struct.unpack_from("<HH", head, 6)[0], struct.unpack_from("<H", head, 20)[0]
        optional = _read_at(f, pe + 24, optional_size, size)
        magic = struct.unpack_from("<H", optional)[0]
        data_offset = 112 if magic == 0x20b else 96 if magic == 0x10b else 0
        if not data_offset or len(optional) < data_offset + 8 * 7:
            raise ValueError("PE debug directory is missing")
        debug_rva, debug_size = struct.unpack_from("<II", optional, data_offset + 8 * 6)
        section_table = _read_at(f, pe + 24 + optional_size, sections * 40, size)
        def rva_offset(rva):
            for i in range(sections):
                entry = section_table[i * 40:(i + 1) * 40]
                virtual_size, base, raw_size, raw_offset = struct.unpack_from("<4I", entry, 8)
                if base <= rva < base + max(virtual_size, raw_size) and rva - base < raw_size:
                    return raw_offset + rva - base
            raise ValueError("PE debug RVA is outside file-backed sections")
        if not debug_rva or debug_size < 28 or debug_size > 1024 * 1024:
            raise ValueError("PE has no verifiable CodeView record")
        entries = _read_at(f, rva_offset(debug_rva), debug_size, size)
        for offset in range(0, len(entries) - 27, 28):
            kind, length, _, pointer = struct.unpack_from("<IIII", entries, offset + 12)
            if kind != 2 or length < 24:
                continue
            record = _read_at(f, pointer, min(length, 4096), size)
            if record[:4] == b"RSDS":
                name = record[24:].split(b"\x00", 1)[0].decode("utf-8", "replace").replace("\\", "/").split("/")[-1]
                return str(uuid.UUID(bytes_le=record[4:20])), struct.unpack_from("<I", record, 20)[0], name
        raise ValueError("PE has no RSDS PDB GUID and age")


def _pe_identity(path: Path) -> tuple[str, int]:
    guid, age, _ = _pe_codeview(path)
    return guid, age


def _elf_build_id(path: Path) -> str:
    size = path.stat().st_size
    with path.open("rb") as f:
        ident = _read_at(f, 0, 16, size)
        if ident[:4] != b"\x7fELF" or ident[4] not in (1, 2) or ident[5] not in (1, 2):
            raise ValueError("DWARF sidecars require ELF files with a GNU build ID")
        endian = "<" if ident[5] == 1 else ">"
        fmt = endian + ("HHIIIIIHHHHHH" if ident[4] == 1 else "HHIQQQIHHHHHH")
        header = struct.unpack(fmt, _read_at(f, 16, struct.calcsize(fmt), size))
        phoff, shoff = header[4], header[5]
        phentsize, phnum, shentsize, shnum = header[8], header[9], header[10], header[11]
        spans = []
        if phnum > 65535 or shnum > 65535:
            raise ValueError("Unsupported extended ELF header table")
        for i in range(phnum):
            raw = _read_at(f, phoff + i * phentsize, phentsize, size)
            if struct.unpack_from(endian + "I", raw)[0] == 4:
                off = struct.unpack_from(endian + ("I" if ident[4] == 1 else "Q"), raw,
                                         4 if ident[4] == 1 else 8)[0]
                length = struct.unpack_from(endian + ("I" if ident[4] == 1 else "Q"), raw,
                                            16 if ident[4] == 1 else 32)[0]
                spans.append((off, length))
        for i in range(shnum):
            raw = _read_at(f, shoff + i * shentsize, shentsize, size)
            if struct.unpack_from(endian + "I", raw, 4)[0] == 7:
                off, length = (struct.unpack_from(endian + "II", raw, 16) if ident[4] == 1 else
                               struct.unpack_from(endian + "QQ", raw, 24))
                spans.append((off, length))
        for off, length in spans:
            if length > 16 * 1024 * 1024:
                continue
            notes = _read_at(f, off, length, size)
            pos = 0
            while pos + 12 <= len(notes):
                namesz, descsz, kind = struct.unpack_from(endian + "III", notes, pos)
                pos += 12
                name = notes[pos:pos + namesz]
                pos += (namesz + 3) & ~3
                desc = notes[pos:pos + descsz]
                pos += (descsz + 3) & ~3
                if kind == 3 and name.rstrip(b"\x00") == b"GNU" and desc:
                    return desc.hex()
    raise ValueError("ELF GNU build ID is missing")


def verify_symbols(binary: Path, symbols: Path, kind: str | None = None) -> dict:
    binary, symbols = Path(binary), Path(symbols)
    if kind == "pdb" or (kind is None and symbols.suffix.lower() == ".pdb"):
        target, companion = _pe_identity(binary), _pdb_identity(symbols)
        kind = "pdb"
        identity = {"guid": target[0], "age": target[1]}
    else:
        target, companion = _elf_build_id(binary), _elf_build_id(symbols)
        kind = "dwarf"
        identity = {"build_id": target}
    if target != companion:
        if kind == "pdb" and target[0] == companion[0]:
            raise ValueError(f"PDB identity mismatch: GUID matches, but age differs: binary {target[1]}, sidecar {companion[1]}. "
                             "The symbol file belongs to a different build")
        raise ValueError(f"Symbol identity mismatch: binary {target}, sidecar {companion}")
    return {"kind": kind, "status": "verified", "identity": identity}


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme.lower() != "https":
            raise ValueError("Symbol server redirect must use HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def lookup_symbols(binary: Path, destination: Path, server: str,
                   cache_dir: Path | None = None, cache_days: int = 30,
                   cache_mb: int = 512) -> tuple[Path, dict]:
    """Explicit caller opt-in is required. Validate identity before accepting bytes."""
    binary, destination = Path(binary), Path(destination)
    parsed = urlparse(server.strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Symbol server must be an HTTPS URL without credentials")
    with binary.open("rb") as stream:
        is_pe = stream.read(2) == b"MZ"
    if is_pe:
        guid, age, name = _pe_codeview(binary)
        if not name.lower().endswith(".pdb") or name in (".", "..") or name.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL"}:
            raise ValueError("PE CodeView record has no safe PDB filename for online lookup")
        key = guid.replace("-", "").upper() + format(age, "X")
        url = server.rstrip("/") + "/" + quote(name) + "/" + key + "/" + quote(name)
        expected = {"guid": guid, "age": age}
        kind = "pdb"
    else:
        build_id = _elf_build_id(binary)
        name = build_id + ".debug"
        url = server.rstrip("/") + "/buildid/" + build_id + "/debuginfo"
        expected = {"build_id": build_id}
        kind = "dwarf"
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / name
    temporary = destination / (name + ".download")
    cache_file = cache_meta = None
    if cache_dir is not None and cache_mb > 0:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_file = cache_dir / (cache_key + (".pdb" if kind == "pdb" else ".debug"))
        cache_meta = cache_dir / (cache_key + ".json")
        if cache_file.is_file() and cache_meta.is_file() and cache_days > 0:
            try:
                record = json.loads(cache_meta.read_text(encoding="utf-8"))
                timestamp = datetime.fromisoformat(record["downloaded_at"])
                valid = (datetime.now(timezone.utc) - timestamp < timedelta(days=cache_days) and
                         record["identity"] == expected and
                         record["sha256"] == sha256(cache_file) and
                         verify_symbols(binary, cache_file, kind)["identity"] == expected)
                if valid:
                    shutil.copy2(cache_file, target)
                    return target, {**record, "status": "cache_hit", "cache_hit": True}
            except (OSError, ValueError, KeyError, TypeError):
                pass
            cache_file.unlink(missing_ok=True)
            cache_meta.unlink(missing_ok=True)
    max_bytes = 512 * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "CastorPollux symbol lookup"})
        with opener.open(request, timeout=30) as response, temporary.open("wb") as output:
            final_url = response.geturl()
            if urlparse(final_url).scheme.lower() != "https":
                raise ValueError("Symbol server final URL must use HTTPS")
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError("Symbol download exceeds 512 MiB")
                digest.update(chunk)
                output.write(chunk)
        verification = verify_symbols(binary, temporary, kind)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    if verification["kind"] != kind or verification["identity"] != expected:
        temporary.unlink(missing_ok=True)
        raise ValueError("Downloaded symbol identity differs from target")
    os.replace(temporary, target)
    provenance = {"server": server.rstrip("/"), "requested_url": url, "final_url": final_url,
                    "downloaded_at": datetime.now(timezone.utc).isoformat(), "sha256": digest.hexdigest(),
                    "bytes": size, "identity": verification["identity"], "status": "identity_verified",
                    "cache_hit": False}
    if cache_file is not None and cache_meta is not None and size <= cache_mb * 1024 * 1024:
        shutil.copy2(target, cache_file)
        cache_meta.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
        _prune_cache(cache_dir, cache_mb)
    return target, provenance


def _prune_cache(folder: Path, limit_mb: int) -> None:
    files = sorted((path for path in folder.iterdir() if path.suffix in {".pdb", ".debug"}),
                   key=lambda path: path.stat().st_mtime, reverse=True)
    total = 0
    for path in files:
        total += path.stat().st_size
        if total > limit_mb * 1024 * 1024:
            path.unlink(missing_ok=True)
            path.with_suffix(".json").unlink(missing_ok=True)
