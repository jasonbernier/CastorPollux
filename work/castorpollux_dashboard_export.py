"""Create a standalone, static HTML snapshot of scan dashboards."""

from __future__ import annotations

import html
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from castorpollux_metrics import load_metrics, trend


def _text(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _number(value) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return 0.0
    return result if math.isfinite(result) and result > 0 else 0.0


def _name(value) -> str:
    """Keep filenames, never absolute paths, in a shareable snapshot."""
    return str(value or "Unknown binary").replace("\\", "/").split("/")[-1]


def _duration(value) -> str:
    return f"{_number(value):,.1f} s" if value is not None else "Unavailable"


def _mib(value) -> str:
    return f"{_number(value) / 1048576:,.1f} MiB" if value is not None else "Unavailable"


def _bar_rows(rows: list[tuple[str, float]], unit: str) -> str:
    maximum = max((_number(value) for _, value in rows), default=0) or 1
    parts = []
    for label, raw in rows:
        value = _number(raw)
        width = min(100, 100 * value / maximum)
        parts.append(
            f'<div class="bar-row"><div class="bar-label"><span>{_text(label)}</span>'
            f'<strong>{value:,.1f} {_text(unit)}</strong></div>'
            f'<div class="track"><div class="fill" style="width:{width:.2f}%"></div></div></div>'
        )
    return "".join(parts) if parts else '<p class="empty">No timing samples were recorded.</p>'


def _chart(values: list[float], title: str, unit: str) -> str:
    numbers = [_number(value) for value in values]
    if not numbers:
        return '<p class="empty">No samples were recorded.</p>'
    if len(numbers) > 160:
        indexes = [round(i * (len(numbers) - 1) / 159) for i in range(160)]
        numbers = [numbers[index] for index in indexes]
    ceiling = max(numbers) or 1
    points = []
    for index, value in enumerate(numbers):
        x = 48 + index * 704 / max(1, len(numbers) - 1)
        y = 148 - value / ceiling * 122
        points.append(f"{x:.1f},{y:.1f}")
    polyline = (f'<polyline points="{" ".join(points)}" fill="none" stroke="#53cfe0" '
                'stroke-width="2.5" stroke-linejoin="round"/>')
    if len(numbers) == 1:
        polyline += f'<circle cx="48" cy="{148 - numbers[0] / ceiling * 122:.1f}" r="4" fill="#83f7ba"/>'
    return (f'<svg viewBox="0 0 800 185" role="img" aria-label="{_text(title)}" '
            'xmlns="http://www.w3.org/2000/svg">'
            f'<title>{_text(title)}</title>'
            '<path d="M48 26H752 M48 87H752 M48 148H752" stroke="#24414a" stroke-dasharray="4 5"/>'
            f'<text x="6" y="31">{ceiling:.0f}</text><text x="6" y="153">0</text>'
            f'{polyline}<text x="48" y="176">{len(values)} observations · peak {ceiling:.1f} {_text(unit)}</text>'
            '</svg>')


def _card(label: str, value: str, note: str = "") -> str:
    return (f'<div class="stat"><span>{_text(label)}</span><strong>{_text(value)}</strong>'
            f'<small>{_text(note)}</small></div>')


def export_dashboard_html(folder: Path, item: dict, recent_items: list[dict],
                          destination: Path, app_version: str) -> Path:
    """Write a self-contained snapshot without source, logs, full paths or network assets."""
    folder, destination = Path(folder), Path(destination)
    index, detail = load_metrics(folder)
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    coverage_data = detail.get("rea_decompile_counts") or item.get("coverage") or {}
    total = int(_number(coverage_data.get("total")))
    succeeded = int(_number(coverage_data.get("succeeded")))
    coverage = 100 * succeeded / total if total else None
    runs = index.get("runs", []) if isinstance(index, dict) else []
    name = _name(manifest.get("input_name") or item.get("name") or folder.name)
    recent = trend([Path(row["path"]) for row in recent_items[:50] if row.get("path")])
    trend_rows = list(reversed(recent["rows"][:16]))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    stages = [(str(row.get("name", "Stage")), _number(row.get("wall_seconds")))
              for row in detail.get("stages", []) if isinstance(row, dict)]
    stage_markup = _bar_rows(stages, "s")
    attempts = "".join(
        f'<tr><td>{_text(run.get("started_at", "")[:19])}</td>'
        f'<td>{_text(run.get("status", "unknown"))}</td>'
        f'<td>{_duration(run.get("wall_seconds"))}</td></tr>'
        for run in runs[-20:] if isinstance(run, dict))
    if not attempts:
        attempts = '<tr><td colspan="3">No attempt history available.</td></tr>'

    resource_parts = []
    for process in detail.get("processes", []):
        if not isinstance(process, dict):
            continue
        samples = process.get("samples", [])
        values = [_number(row.get("working_set_bytes")) / 1048576
                  for row in samples if isinstance(row, dict)]
        resource_parts.append(
            f'<article class="panel"><h3>{_text(process.get("stage", "Engine"))}</h3>'
            '<div class="metrics">'
            f'{_card("Peak working set", _mib(process.get("peak_working_set_bytes")))}'
            f'{_card("Peak private bytes", _mib(process.get("peak_private_bytes")))}'
            f'{_card("Sampled CPU", _duration(process.get("sampled_cpu_seconds")))}'
            f'{_card("Samples", str(process.get("sample_count", len(values))))}'
            '</div>'
            f'{_chart(values, "Working set over process time", "MiB")}</article>'
        )
    resources = "".join(resource_parts) or '<p class="empty">No process samples were captured for this investigation.</p>'

    quality_rows = []
    for row in recent_items[:12]:
        counts = row.get("coverage") or {}
        count = _number(counts.get("total"))
        percentage = 100 * _number(counts.get("succeeded")) / count if count else 0
        quality_rows.append((_name(row.get("name", "Investigation")), percentage))
    inspected = recent_items[:50]
    complete_rea = sum(row.get("decompile") == "complete" for row in inspected)
    failed_ghidra = sum(row.get("ghidra") == "failed" for row in inspected)
    versions = manifest.get("versions") or {}
    if not isinstance(versions, dict):
        versions = {}
    version_rows = "".join(f'<tr><th>{_text(key)}</th><td>{_text(value)}</td></tr>'
                           for key, value in sorted(versions.items()))
    if not version_rows:
        version_rows = '<tr><td colspan="2">Engine versions unavailable.</td></tr>'
    trend_table = "".join(f'<tr><td>{_text(_name(row["name"]))}</td><td>{_duration(row["seconds"])}</td></tr>'
                          for row in trend_rows) or '<tr><td colspan="2">No recent timing data.</td></tr>'

    document = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>CastorPollux dashboard · {_text(name)}</title>
<style>
:root{{--bg:#071017;--panel:#10212b;--field:#152b36;--line:#24414a;--text:#edf8f5;--muted:#91aaa9;--green:#83f7ba;--cyan:#53cfe0}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Segoe UI,Arial,sans-serif}}
main{{max-width:1120px;margin:auto;padding:28px 24px 60px}}header{{border-bottom:1px solid var(--line);padding-bottom:18px}}
.brand{{color:var(--green);font:700 12px Consolas,monospace;letter-spacing:.15em}}h1{{font-size:34px;margin:5px 0}}h2{{font-size:21px;margin:0 0 15px}}h3{{font-size:16px;margin:0 0 10px;color:var(--cyan)}}
p,.muted{{color:var(--muted)}}nav{{display:flex;flex-wrap:wrap;gap:10px;margin:22px 0}}nav a{{color:var(--cyan);text-decoration:none;background:var(--field);padding:8px 12px;border-radius:8px}}
section{{margin:25px 0 38px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:12px 0}}
.stat,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}}.stat span{{display:block;color:var(--muted);font:700 11px Consolas,monospace;text-transform:uppercase}}
.stat strong{{display:block;color:var(--green);font-size:24px;margin:3px 0}}.stat small{{color:var(--muted)}}.panel{{margin:12px 0}}
.bar-row{{margin:12px 0}}.bar-label{{display:flex;justify-content:space-between;gap:12px}}.bar-label strong{{color:var(--cyan);white-space:nowrap}}
.track{{height:8px;background:var(--field);border-radius:4px;overflow:hidden;margin-top:5px}}.fill{{height:100%;background:var(--cyan)}}
svg{{display:block;width:100%;height:auto;max-height:250px;background:var(--field);border-radius:8px;margin-top:12px}}svg text{{fill:var(--muted);font:11px Consolas,monospace}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:9px;border-bottom:1px solid var(--line)}}th{{color:var(--muted)}}.empty{{padding:16px;color:var(--muted)}}
footer{{border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:12px}}
@media print{{body{{background:white;color:black}}.stat,.panel{{break-inside:avoid;background:white;border-color:#aaa}}nav{{display:none}}svg{{background:#eee}}}}
</style></head><body><main>
<header><div class="brand">◈ CASTORPOLLUX · DASHBOARD SNAPSHOT</div><h1>{_text(name)}</h1>
<p>Generated {generated} · CastorPollux {_text(app_version)} · Static, self-contained report</p></header>
<nav><a href="#overview">Overview</a><a href="#performance">Performance</a><a href="#resources">Resources</a><a href="#quality">Quality</a><a href="#provenance">Provenance</a></nav>
<section id="overview"><h2>Overview</h2><div class="metrics">
{_card("Scan duration", _duration(detail.get("wall_seconds")), "Latest analysis attempt")}
{_card("REA coverage", f"{coverage:.0f}%" if coverage is not None else "Unknown", f"{succeeded}/{total} procedures")}
{_card("Run attempts", str(len(runs)), "Includes resumed scans")}
{_card("Findings", str(item.get("finding_count", 0)), "Saved agent findings")}
</div><article class="panel"><h3>Engine status</h3><p>Ghidra export: <strong>{_text(item.get("ghidra", "unknown"))}</strong> · REA evidence: <strong>{_text(item.get("rea", "unknown"))}</strong> · REA decompilation: <strong>{_text(item.get("decompile", "unknown"))}</strong></p></article></section>
<section id="performance"><h2>Scan performance</h2><div class="metrics">
{_card("Recent median", _duration(recent.get("median_seconds")), "Up to 50 investigations")}
{_card("Recent p95", _duration(recent.get("p95_seconds")), "Mixed binary sizes")}
{_card("Latest status", str(detail.get("status", "unknown")))}
</div><article class="panel"><h3>Stage durations</h3>{stage_markup}</article>
<article class="panel"><h3>Recent investigation duration</h3>{_chart([row["seconds"] for row in trend_rows], "Recent investigation duration", "seconds")}
<table><thead><tr><th>Investigation</th><th>Duration</th></tr></thead><tbody>{trend_table}</tbody></table></article>
<article class="panel"><h3>Attempts for this investigation</h3><table><thead><tr><th>Started</th><th>Status</th><th>Duration</th></tr></thead><tbody>{attempts}</tbody></table></article></section>
<section id="resources"><h2>Engine resources</h2>{resources}<p>Process-tree memory and CPU are sampled every two seconds on Windows. Short peaks and short-lived children can be missed. Working sets are summed across processes and may count shared pages more than once.</p></section>
<section id="quality"><h2>Decompilation quality</h2><div class="metrics">
{_card("Complete REA", str(complete_rea), f"of {len(inspected)} recent investigations")}
{_card("Failed Ghidra", str(failed_ghidra))}
{_card("Latest coverage", f"{coverage:.0f}%" if coverage is not None else "Unknown", f"{succeeded} reconstructed procedures")}
</div><article class="panel"><h3>Recent procedure coverage</h3>{_bar_rows(quality_rows, "%")}</article>
<p>Coverage measures procedure decompilation, not correctness or review completeness.</p></section>
<section id="provenance"><h2>Provenance and sharing</h2><article class="panel"><h3>Engine versions</h3><table><tbody>{version_rows}</tbody></table></article>
<p>Snapshot of the latest saved scan attempt. It contains the binary filename, aggregate findings count, engine versions, and telemetry. It excludes source code, logs, process IDs, and absolute local paths. Review it before sharing.</p></section>
<footer>CastorPollux {_text(app_version)} · Exported {generated} · Offline HTML dashboard snapshot</footer>
</main></body></html>'''
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document, encoding="utf-8")
    return destination
