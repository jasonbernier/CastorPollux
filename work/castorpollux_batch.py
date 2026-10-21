"""Unattended CastorPollux batch entry point for local jobs and CI."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from castorpollux_core import APP_VERSION, AnalysisRunner, ComponentStore
from castorpollux_workspace import CodexReview, REPORT_FORMATS, find_agent_cli, review_readiness
from castorpollux_recovery import attempt_agent_recovery, engine_failures
from castorpollux_usage import read_codex_usage, read_other_usage, usage_label


def run_batch(config_path: Path, notify_external=None, cancelled=None, set_process=None) -> int:
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    def resolve(value: str) -> Path:
        path = Path(value).expanduser()
        return (path if path.is_absolute() else config_path.parent / path).resolve()
    if not isinstance(config, dict):
        raise ValueError("Batch configuration must be a JSON object")
    inputs = config.get("inputs")
    if not isinstance(inputs, list) or not inputs or not all(isinstance(value, str) for value in inputs):
        raise ValueError("Batch configuration needs a nonempty inputs array")
    output = resolve(config["output"])
    if not output.is_dir():
        raise ValueError("Batch output must be an existing directory")
    summary_path = resolve(config.get("summary", str(output / "castorpollux-batch-summary.json")))
    if not summary_path.parent.is_dir():
        raise ValueError("Batch summary parent directory does not exist")
    agent = config.get("agent", "none")
    if agent not in {"none", "codex", "claude", "opencode", "ollama"}:
        raise ValueError("Unknown batch review agent")
    formats = set(config.get("formats", REPORT_FORMATS))
    if not formats or not formats <= set(REPORT_FORMATS):
        raise ValueError("Batch formats must be supported report extensions")
    minimum = int(config.get("minimum_coverage", 80))
    if not 0 <= minimum <= 100:
        raise ValueError("minimum_coverage must be 0..100")
    redaction_terms = config.get("redaction_terms", [])
    if not isinstance(redaction_terms, list) or not all(isinstance(x, str) for x in redaction_terms):
        raise ValueError("redaction_terms must be an array of strings")
    executable = resolve(config["agent_cli"]) if config.get("agent_cli") else \
        find_agent_cli(agent) if agent not in {"none", "ollama"} else None
    if agent not in {"none", "ollama"} and (not executable or not executable.is_file()):
        raise ValueError(f"{agent} CLI was not found")
    retdec = resolve(config["retdec_cli"]) if config.get("retdec_cli") else None
    entries = []
    log_path = summary_path.with_suffix(".log")
    cancelled = cancelled or (lambda: False)
    set_process = set_process or (lambda _: None)
    def notify(message: str) -> None:
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(datetime.now().astimezone().isoformat() + "  " + str(message) + "\n")
        if sys.stdout is not None:
            print(message, flush=True)
        if notify_external:
            notify_external(message)
    summary = {"application_version": APP_VERSION, "started_at": datetime.now().astimezone().isoformat(),
               "config": str(config_path), "log": str(log_path), "results": entries}
    store = ComponentStore()
    for raw in inputs:
        if cancelled():
            break
        source = resolve(raw)
        entry = {"input": str(source), "status": "pending"}
        entries.append(entry)
        try:
            if not source.is_file() or source.stat().st_size == 0:
                raise ValueError("Input binary is missing or empty")
            runner = AnalysisRunner(store, notify, cancelled, set_process)
            symbol_file = resolve(config["symbols"]) if config.get("symbols") else None
            folder = runner.run(source, output, symbols=symbol_file,
                                symbol_server=config.get("symbol_server"))
            entry["investigation"] = str(folder)
            entry["recovery"] = attempt_agent_recovery(runner, folder, find_agent_cli("codex"),
                                                        notify, cancelled, set_process)
            gate = config.get("call_path_gate")
            if gate:
                if not isinstance(gate, dict) or not isinstance(gate.get("sources"), list) or not isinstance(gate.get("sinks"), list):
                    raise ValueError("call_path_gate needs sources and sinks arrays")
                from castorpollux_changegate import gate_new_call_paths
                baseline = resolve(gate["baseline"])
                result = gate_new_call_paths(baseline, folder, gate["sources"], gate["sinks"])
                entry["call_path_gate"] = result
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
            entry["analysis_status"] = manifest.get("rea_decompile_status")
            entry["analysis_warnings"] = manifest.get("warnings", [])
            if engine_failures(manifest):
                entry["status"] = "analysis_incomplete"
                raise RuntimeError("Analysis engine stages remain incomplete after recovery")
            manifest, warnings = review_readiness(folder)
            entry["analysis_warnings"] = warnings
            if agent != "none":
                reviewer = CodexReview(notify, cancelled, set_process)
                report = reviewer.run(folder, bool(config.get("daybreak_blue", False)), executable, formats,
                                      agent, config.get("scope_mode", "all"), config.get("scope_selection", ""),
                                      config.get("local_model", ""), minimum,
                                      bool(config.get("redact_cloud", True)), redaction_terms,
                                      bool(config.get("secondary_decompiler", True)), retdec)
                entry["report"] = str(folder / "security-review-data.json")
                entry["findings"] = len(report["result"]["findings"])
                entry["quality_gate"] = report["quality_gate"]
                if report["quality_gate"]["status"] == "warning" and config.get("fail_on_quality", False):
                    entry["status"] = "quality_warning"
                else:
                    entry["status"] = "complete"
            else:
                entry["status"] = "complete"
            if entry.get("call_path_gate", {}).get("status") == "fail":
                entry["status"] = "new_call_paths"
        except Exception as error:
            if entry.get("status") != "analysis_incomplete":
                entry["status"] = "failed"
            entry["error"] = str(error)
        usage = {"agent": "all", "selected_agent": agent, "items": [
            read_codex_usage(find_agent_cli("codex")),
            read_other_usage("claude", find_agent_cli("claude"),
                             Path(entry["investigation"]) / "claude-review.log" if entry.get("investigation") else None),
            read_other_usage("opencode", find_agent_cli("opencode"))]}
        entry["agent_usage"] = usage
        notify(usage_label(usage))
        if entry.get("investigation"):
            try:
                (Path(entry["investigation"]) / "agent-usage.json").write_text(
                    json.dumps(usage, indent=2), encoding="utf-8")
            except OSError:
                pass
        temporary = summary_path.with_suffix(summary_path.suffix + ".tmp")
        temporary.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        temporary.replace(summary_path)
    summary["finished_at"] = datetime.now().astimezone().isoformat()
    summary["status"] = "cancelled" if cancelled() else \
        "complete" if len(entries) == len(inputs) and all(row["status"] == "complete" for row in entries) else "attention"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0 if summary["status"] == "complete" else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run CastorPollux analyses from a JSON batch configuration")
    parser.add_argument("config", type=Path)
    args = parser.parse_args(argv)
    try:
        return run_batch(args.config)
    except Exception as error:
        if sys.stderr is not None:
            print(f"CastorPollux batch configuration error: {error}", file=sys.stderr)
        try:
            args.config.with_suffix(".batch-error.json").write_text(
                json.dumps({"status": "configuration_error", "error": str(error)}, indent=2), encoding="utf-8")
        except OSError:
            pass
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
