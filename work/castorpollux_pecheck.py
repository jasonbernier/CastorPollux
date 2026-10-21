"""Small independent PE x86/x64 CALL decoder for saved edge cross-checks."""

from __future__ import annotations

import struct
from pathlib import Path


def pe_layout(path: Path) -> dict | None:
    path = Path(path)
    if not path.is_file():
        return None
    with path.open("rb") as stream:
        header = stream.read(4096)
        if len(header) < 64 or header[:2] != b"MZ":
            return None
        offset = struct.unpack_from("<I", header, 0x3C)[0]
        if offset > 1024 * 1024:
            return None
        stream.seek(offset)
        pe = stream.read(24)
        if len(pe) < 24 or pe[:4] != b"PE\0\0":
            return None
        machine, sections, _, _, _, option_size, _ = struct.unpack_from("<HHIIIHH", pe, 4)
        if machine not in (0x14C, 0x8664) or not 0 < sections <= 96 or option_size < 64:
            return None
        optional = stream.read(option_size)
        if len(optional) < option_size:
            return None
        magic = struct.unpack_from("<H", optional)[0]
        if magic not in (0x10B, 0x20B):
            return None
        image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I", optional,
                                        24 if magic == 0x20B else 28)[0]
        segments = []
        for _ in range(sections):
            row = stream.read(40)
            if len(row) < 40:
                return None
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", row, 8)
            segments.append((virtual_address, virtual_address + max(virtual_size, raw_size), raw_pointer, raw_size))
        return {"machine": "x86_64" if machine == 0x8664 else "x86", "image_base": image_base,
                "sections": segments, "path": path}


def decode_call(layout: dict | None, site: int, expected_target: int | None) -> dict:
    if not layout:
        return {"status": "unavailable", "reason": "Independent raw-byte decoder supports PE x86/x64 only"}
    rva = site - layout["image_base"]
    raw = next((pointer + rva - start for start, end, pointer, size in layout["sections"]
                if start <= rva < end and rva - start < size), None)
    if raw is None:
        return {"status": "unavailable", "reason": "Call site is not file-backed"}
    with layout["path"].open("rb") as stream:
        stream.seek(raw)
        instruction = stream.read(7)
    prefix = 0
    while prefix < 2 and prefix < len(instruction) and (0x40 <= instruction[prefix] <= 0x4F or
                                                         instruction[prefix] in (0x66, 0x67)):
        prefix += 1
    if len(instruction) >= prefix + 5 and instruction[prefix] in (0xE8, 0xE9):
        destination = site + prefix + 5 + struct.unpack_from("<i", instruction, prefix + 1)[0]
        tail = instruction[prefix] == 0xE9
        status = ("tail_jump_verified" if tail else "verified") if expected_target == destination else \
            "disputed" if expected_target is not None else "site_only"
        return {"status": status, "site": f"{site:x}", "decoded_target": f"{destination:x}",
                "opcode": "E9 rel32" if tail else "E8 rel32",
                "reason": "Independently decoded tail jump bytes" if tail else "Independently decoded direct call bytes"}
    if len(instruction) >= prefix + 2 and instruction[prefix] == 0xFF and (instruction[prefix + 1] >> 3) & 7 == 2:
        return {"status": "site_only", "site": f"{site:x}", "opcode": "FF /2 (optional prefixes)",
                "reason": "Independently decoded indirect call site; runtime target is unknown"}
    return {"status": "disputed", "site": f"{site:x}", "opcode_bytes": instruction[:6].hex(),
            "reason": "Raw bytes at this address do not encode a basic x86/x64 CALL form"}
