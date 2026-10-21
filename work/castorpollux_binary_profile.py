"""Bounded binary fingerprinting and opt-in third-party advisory leads."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import ssl
import struct
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.error import URLError
from urllib.request import Request, urlopen

from castorpollux_core import APP_VERSION, home


PE_MACHINES = {0x14c: "x86", 0x8664: "x86_64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA-64"}
ELF_MACHINES = {3: "x86", 40: "ARM", 62: "x86_64", 183: "ARM64", 243: "RISC-V"}
MACH_MACHINES = {7: "x86", 0x01000007: "x86_64", 12: "ARM", 0x0100000c: "ARM64"}

LIBRARIES = (
    ("OpenSSL", rb"\bOpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b", "openssl", "openssl",
     ("SSL_new", "OPENSSL_init_ssl", "EVP_EncryptInit_ex")),
    ("zlib", rb"\bzlib(?:\s+version)?\s+([0-9]+\.[0-9]+\.[0-9]+)\b", "zlib", "zlib",
     ("inflateInit", "deflateInit", "zlibVersion")),
    ("libcurl", rb"\blibcurl/([0-9]+\.[0-9]+\.[0-9]+)\b", "haxx", "curl",
     ("curl_easy_init", "curl_multi_init", "curl_version")),
    ("libpng", rb"\blibpng(?:\s+version)?\s+([0-9]+\.[0-9]+\.[0-9]+)\b", "libpng", "libpng",
     ("png_create_read_struct", "png_read_info", "png_get_libpng_ver")),
    ("SQLite", rb"\bSQLite(?:\s+version)?\s+([0-9]+\.[0-9]+\.[0-9]+)\b", "sqlite", "sqlite",
     ("sqlite3_open", "sqlite3_prepare", "sqlite3_libversion")),
    ("libxml2", rb"\blibxml2(?:\s+version)?\s+([0-9]+\.[0-9]+\.[0-9]+)\b", "xmlsoft", "libxml2",
     ("xmlReadMemory", "xmlParseDoc", "xmlInitParser")),
)

SIGNATURE_TOKENS = {
    "OpenSSL": (b"OPENSSL_init_ssl", b"EVP_EncryptInit_ex", b"SSL_new", b"OPENSSL_CONF"),
    "zlib": (b"inflateInit_", b"deflateInit_", b"zlibVersion", b"ZLIB_VERSION"),
    "libcurl": (b"curl_easy_init", b"curl_multi_init", b"curl_version", b"libcurl"),
    "libpng": (b"png_create_read_struct", b"png_read_info", b"png_get_libpng_ver", b"libpng error"),
    "SQLite": (b"sqlite3_open", b"sqlite3_prepare_v2", b"sqlite3_libversion", b"SQLite format 3"),
    "libxml2": (b"xmlReadMemory", b"xmlParseDoc", b"xmlInitParser", b"libxml2"),
}


def _sample(binary: Path) -> list[tuple[int, bytes]]:
    """Read a bounded head and tail, including the format header."""
    size = binary.stat().st_size
    with binary.open("rb") as stream:
        head = stream.read(min(size, 32 * 1024 * 1024))
        if size <= len(head):
            return [(0, head)]
        stream.seek(max(len(head), size - 8 * 1024 * 1024))
        return [(0, head), (stream.tell(), stream.read(8 * 1024 * 1024))]


def detect_binary_profile(binary: Path, ghidra_summary: dict | None = None) -> dict:
    binary = Path(binary)
    head = _sample(binary)[0][1][:4096]
    fmt, architecture, bitness, endian = "unknown", "unknown", None, "unknown"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        offset = struct.unpack_from("<I", head, 0x3c)[0]
        if offset + 26 <= len(head) and head[offset:offset + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", head, offset + 4)[0]
            magic = struct.unpack_from("<H", head, offset + 24)[0]
            fmt, architecture, bitness, endian = "PE", PE_MACHINES.get(machine, f"PE machine 0x{machine:04x}"), \
                {0x10b: 32, 0x20b: 64}.get(magic), "little"
    elif head[:4] == b"\x7fELF" and len(head) >= 20:
        endian = "little" if head[5] == 1 else "big" if head[5] == 2 else "unknown"
        if endian != "unknown":
            machine = int.from_bytes(head[18:20], endian)
            fmt, architecture, bitness = "ELF", ELF_MACHINES.get(machine, f"ELF machine {machine}"), \
                {1: 32, 2: 64}.get(head[4])
    elif len(head) >= 8 and head[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                                            b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        endian = "little" if head[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else "big"
        machine = int.from_bytes(head[4:8], endian)
        fmt, architecture, bitness = "Mach-O", MACH_MACHINES.get(machine, f"Mach CPU {machine}"), \
            64 if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    markers = ((b"clang version ", "Clang"), (b"GCC: (GNU) ", "GCC"),
               (b"Microsoft Visual C++ Runtime Library", "MSVC runtime"),
               (b"rustc version ", "Rust"), (b"Go build ID:", "Go"))
    compiler = {"name": "unknown", "confidence": "unknown", "evidence": "No distinctive compiler marker found"}
    if fmt == "PE":
        rich = head.find(b"Rich")
        if rich >= 16 and rich + 8 <= len(head):
            key = int.from_bytes(head[rich + 4:rich + 8], "little")
            for offset in range(0x40, rich - 15, 4):
                if (int.from_bytes(head[offset:offset + 4], "little") ^ key) == 0x536e6144 and \
                   all((int.from_bytes(head[offset + step:offset + step + 4], "little") ^ key) == 0
                       for step in (4, 8, 12)):
                    compiler = {"name": "Microsoft toolchain", "confidence": "toolchain marker",
                                "evidence": f"Validated PE Rich header at file offset 0x{rich:x}"}
                    break
    for base, data in _sample(binary):
        for marker, name in markers:
            offset = data.find(marker)
            if offset >= 0:
                compiler = {"name": name, "confidence": "marker only",
                            "evidence": f"Binary marker at file offset 0x{base + offset:x}: {marker.decode('ascii', errors='replace')}"}
                break
        if compiler["name"] != "unknown":
            break
    optimization = {"level": "unknown", "confidence": "unknown", "evidence": "No embedded build flag found"}
    for base, data in _sample(binary):
        for match in re.finditer(rb"(?:^|[\x00\s])(?:-O[0123sgz]|/O[12dxst])(?=[\x00\s])", data):
            context = data[max(0, match.start() - 100):match.end() + 100]
            if re.search(rb"gcc|clang|compiler|command.line|cl\.exe|cflags", context, re.I):
                optimization = {"level": match.group(0).strip().decode("ascii"),
                                "confidence": "embedded flag only",
                                "evidence": f"Build flag near compiler marker at file offset 0x{base + match.start():x}"}
                break
        if optimization["level"] != "unknown":
            break
    summary = ghidra_summary or {}
    return {"format": fmt, "architecture": architecture, "bitness": bitness, "endian": endian,
            "compiler": compiler, "optimization": optimization, "ghidra_language": summary.get("language", ""),
            "ghidra_compiler_spec": summary.get("compiler", ""),
            "note": "Architecture comes from the file header. Compiler markers and Ghidra's ABI spec do not prove the original compiler."}


def scan_embedded_libraries(binary: Path, folder: Path) -> dict:
    """Combine version, symbol and distinctive byte markers without claiming static linkage."""
    binary, folder = Path(binary), Path(folder)
    symbols = set()
    for filename in ("functions.csv", "symbols.csv"):
        path = folder / filename
        if path.is_file():
            with path.open(encoding="utf-8-sig", newline="", errors="replace") as stream:
                for row in csv.DictReader(stream):
                    symbols.add(str(row.get("name", "")).casefold())
    matches = []
    samples = _sample(binary)
    lowered_samples = [data.lower() for _, data in samples]
    for name, pattern, vendor, product, functions in LIBRARIES:
        found = None
        for base, data in samples:
            match = re.search(pattern, data, re.I)
            if match:
                found = (match.group(1).decode("ascii"), base + match.start(), match.group(0).decode("ascii"))
                break
        token_hits = []
        for token in SIGNATURE_TOKENS[name]:
            if any(token.lower() in data for data in lowered_samples):
                token_hits.append(token.decode("ascii"))
        corroboration = [symbol for symbol in functions if any(saved.startswith(symbol.casefold()) for saved in symbols)]
        if not found and len(token_hits) + len(corroboration) < 2:
            continue
        version, offset, marker = found if found else (None, None, None)
        evidence = ([f"Version string at file offset 0x{offset:x}: {marker}"] if found else [])
        evidence += ["Distinctive markers: " + ", ".join(token_hits)] if token_hits else []
        matches.append({"name": name, "version": version, "nvd_vendor": vendor,
                        "nvd_product": product, "evidence": evidence,
                        "signature_markers": token_hits,
                        "corroborating_functions": corroboration,
                        "confidence": "corroborated" if found and corroboration else
                                      "candidate signature" if len(token_hits) + len(corroboration) >= 2 else "version string only",
                        "linkage": "unverified embedded candidate",
                        "note": "A version string can be unused metadata or belong to a dynamically loaded library. Confirm code ownership before claiming inclusion."})
    result = {"generated_at": datetime.now(timezone.utc).isoformat(), "libraries": matches,
              "sampled_bytes": "first 32 MiB and last 8 MiB", "complete_scan": binary.stat().st_size <= 40 * 1024 * 1024,
              "note": "Fingerprint leads only; absence does not establish that a library is absent."}
    prior = folder / "known-vulnerabilities.json"
    if prior.is_file():
        try:
            saved = json.loads(prior.read_text(encoding="utf-8"))
            previous = {(row["library"], row.get("version")) for row in saved.get("results", [])}
            current = {(row["name"], row["version"]) for row in matches}
            if previous != current:
                archive = folder / "KnownVulnerabilityHistory"
                archive.mkdir(exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                shutil.move(str(prior), str(archive / f"known-vulnerabilities-{stamp}.json"))
        except (OSError, ValueError, KeyError):
            prior.unlink(missing_ok=True)
    (folder / "embedded-libraries.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _nvd_json(url: str) -> dict:
    request = Request(url, headers={"User-Agent": f"CastorPollux/{APP_VERSION} (local opt-in advisory lookup)",
                                    "Accept": "application/json"})
    try:
        with urlopen(request, timeout=25) as response:
            if response.url.split("/", 3)[:3] != ["https:", "", "services.nvd.nist.gov"]:
                raise RuntimeError("NVD lookup redirected outside the official host")
            payload = response.read(6 * 1024 * 1024 + 1)
            if len(payload) > 6 * 1024 * 1024:
                raise RuntimeError("NVD response exceeded the local limit")
    except URLError as error:
        if not isinstance(error.reason, ssl.SSLCertVerificationError) or not shutil.which("curl.exe"):
            raise
        # Some Windows installations accept the system-validated Schannel chain
        # while Python's OpenSSL store sees an expired alternate chain.
        with tempfile.TemporaryDirectory(prefix="castorpollux-nvd-") as temporary:
            destination = Path(temporary) / "response.json"
            command = ["curl.exe", "--fail", "--silent", "--show-error", "--max-time", "25",
                       "--max-filesize", str(6 * 1024 * 1024), "--output", str(destination),
                       "--write-out", "%{url_effective}", url]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode or not result.stdout.startswith("https://services.nvd.nist.gov/"):
                raise RuntimeError("NVD HTTPS lookup failed with Windows TLS validation: " +
                                   result.stderr[-300:]) from error
            payload = destination.read_bytes()
    return json.loads(payload)


def _cache_file(cpe: str, cache_dir: Path | None = None) -> Path:
    root = Path(cache_dir) if cache_dir is not None else home() / "AdvisoryCache"
    return root / (hashlib.sha256(cpe.encode("utf-8")).hexdigest() + ".json")


def check_known_vulnerabilities(folder: Path, fetch=None, offline: bool = False,
                                cache_dir: Path | None = None, max_age_days: int = 7) -> dict:
    """Opt-in exact-version CPE lookups. Results are leads, not confirmed target findings."""
    folder = Path(folder)
    inventory = json.loads((folder / "embedded-libraries.json").read_text(encoding="utf-8"))
    if fetch is not None and cache_dir is None:
        cache_dir = folder / "AdvisoryCache"
    fetch = fetch or _nvd_json
    rows = []
    def target_is_vulnerable(cve: dict, vendor: str, product: str) -> bool:
        target = (vendor.casefold(), product.casefold())
        def walk(node):
            for match in node.get("cpeMatch", []):
                parts = str(match.get("criteria", "")).casefold().split(":")
                if len(parts) >= 5 and (parts[3], parts[4]) == target and match.get("vulnerable") is True:
                    return True
            return any(walk(child) for child in node.get("nodes", []))
        return any(walk(configuration) for configuration in cve.get("configurations", []))
    def platform_constraints(cve: dict, vendor: str, product: str) -> list[str]:
        context = set()
        def walk(node, and_context=False):
            combined = and_context or str(node.get("operator", "")).upper() == "AND"
            for match in node.get("cpeMatch", []):
                criteria = str(match.get("criteria", ""))
                parts = criteria.casefold().split(":")
                if combined and len(parts) >= 5 and (parts[3], parts[4]) != (vendor.casefold(), product.casefold()):
                    context.add(criteria[:300])
            for child in node.get("nodes", []):
                walk(child, combined)
        for configuration in cve.get("configurations", []):
            walk(configuration)
        return sorted(context)[:20]
    for library in inventory.get("libraries", [])[:8]:
        if not library.get("version"):
            rows.append({"library": library["name"], "version": None, "status": "version_unknown",
                         "advisories": [], "note": "Exact version required for CPE lookup"})
            continue
        cpe = f"cpe:2.3:a:{library['nvd_vendor']}:{library['nvd_product']}:{library['version']}:*:*:*:*:*:*:*"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode({"cpeName": cpe, "resultsPerPage": 100})
        item = {"library": library["name"], "version": library["version"], "cpe": cpe,
                "url": url, "status": "pending", "advisories": []}
        try:
            cache_path = _cache_file(cpe, cache_dir)
            cached = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.is_file() else None
            if cached and hashlib.sha256(json.dumps(cached.get("response"), sort_keys=True).encode("utf-8")).hexdigest() != cached.get("response_sha256"):
                cached = None
            fresh = bool(cached and cached.get("cpe") == cpe and
                         datetime.fromisoformat(cached["fetched_at"]) + timedelta(days=max_age_days) >
                         datetime.now(timezone.utc))
            if cached and cached.get("cpe") == cpe and (offline or fresh):
                response = cached["response"]
                item["source"] = "offline cache" if offline else "fresh cache"
                item["cached_at"] = cached["fetched_at"]
                item["cache_stale"] = not fresh
            elif offline:
                item["status"] = "cache_missing"
                item["error"] = "No cached advisory response for this exact library version"
                rows.append(item)
                continue
            else:
                response = fetch(url)
                item["source"] = "NVD live"
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                temporary = cache_path.with_suffix(".tmp")
                temporary.write_text(json.dumps({"cpe": cpe, "fetched_at": datetime.now(timezone.utc).isoformat(),
                                                 "response_sha256": hashlib.sha256(json.dumps(response, sort_keys=True).encode("utf-8")).hexdigest(),
                                                 "response": response}), encoding="utf-8")
                temporary.replace(cache_path)
            records = response.get("vulnerabilities", [])
            for record in records[:100]:
                cve = record.get("cve", {})
                if not target_is_vulnerable(cve, library["nvd_vendor"], library["nvd_product"]):
                    continue
                identifier = str(cve.get("id", ""))
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
                    continue
                descriptions = cve.get("descriptions", [])
                summary = next((str(part.get("value", "")) for part in descriptions
                                if part.get("lang") == "en"), "")
                item["advisories"].append({"id": identifier, "summary": summary[:1000],
                                           "url": "https://nvd.nist.gov/vuln/detail/" + identifier,
                                           "configuration_constraints": platform_constraints(cve, library["nvd_vendor"],
                                                                                             library["nvd_product"])})
            item["status"] = "complete" if int(response.get("totalResults", 0)) <= len(records) else "truncated"
            item["total_results"] = int(response.get("totalResults", 0))
            item["target_vulnerable_advisory_leads"] = len(item["advisories"])
        except Exception as error:
            item["status"] = "lookup_failed"
            item["error"] = str(error)[:500]
        rows.append(item)
    result = {"checked_at": datetime.now(timezone.utc).isoformat(), "source": "NVD CVE API 2.0",
              "opt_in": True, "offline": offline, "results": rows,
              "note": "CPE matches are advisory leads. Embedded-library identity, reachable vulnerable code, build flags, and applicability need manual confirmation."}
    (folder / "known-vulnerabilities.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
