#!/usr/bin/env python3
"""Archive raw reproduction artifacts and describe the original v4 readout.

Invoke the unchanged v4 summarize command first. This collector does not run
inference, repair submissions, change gates, or rescore candidates.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import lzma
from pathlib import Path
import tarfile
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def read(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def file_identity(path):
    with path.open("rb") as stream:
        return {"bytes": path.stat().st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def collect(run_directory, output):
    started = time.monotonic_ns()
    run, output = Path(run_directory).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    cohort = read(run / "suite/RESULT.json")
    frozen = read(run / "SOURCE_SNAPSHOT.json")
    registration_path = run / "source/experiments/hia_agent_assembly_v4_20261030/REGISTRATION.json"
    registration = read(registration_path)
    unchanged = all(file_identity(run / "source" / name) == {"bytes": value["bytes"], "sha256": value["sha256"]}
                    for name, value in frozen["files"].items())
    if not unchanged:
        raise RuntimeError("frozen source inventory changed; retain failed observation")
    with (output / "COHORT_RESULT.json").open("xb") as stream:
        stream.write((run / "suite/RESULT.json").read_bytes())
    models, arms = [], []
    for model in cohort["models"]:
        model_id = model["model"]["id"]
        cells = model.get("cells", [])
        models.append({"model_id": model_id, "status": model["status"],
                       "valid_observation": model["valid_observation"],
                       "planned_cells": 12, "attempted_cells": len(cells),
                       "correct_observed": sum(bool(cell["correct"]) for cell in cells),
                       "new_requests": model.get("new_requests"), "responses_received": model.get("responses_received"),
                       "usage_complete": model.get("usage_complete", False),
                       "experiment_wall_ns": model.get("experiment_wall_ns"),
                       "source_unchanged": model.get("sources_unchanged"),
                       "model_unchanged": model.get("model_unchanged"),
                       "tools_unchanged": model.get("tools_unchanged"),
                       "error": model.get("error"),
                       "engine_count": len(model.get("engines", []))})
        for arm in ("hia", "assembly", "rust"):
            selected = [cell for cell in cells if cell["language"] == arm]
            attempts = [attempt for cell in selected for attempt in cell["attempts"]]
            complete = len(selected) == 4 and all(cell["usage_complete"] for cell in selected)
            arms.append({"model_id": model_id, "language": arm, "planned_cells": 4,
                         "attempted_cells": len(selected), "correct_observed": sum(bool(cell["correct"]) for cell in selected),
                         "hidden_tests_evaluated_cells": sum(bool(cell["hidden_tests_evaluated"]) for cell in selected),
                         "submissions": len(attempts), "usage_complete": complete,
                         "input_tokens": sum(cell["input_tokens"] for cell in selected) if complete else None,
                         "output_tokens": sum(cell["output_tokens"] for cell in selected) if complete else None,
                         "total_tokens": sum(cell["total_tokens"] for cell in selected) if complete else None,
                         "known_input_tokens_lower_bound": sum(cell["known_input_tokens"] for cell in selected),
                         "known_output_tokens_lower_bound": sum(cell["known_output_tokens"] for cell in selected),
                         "submission_statuses": dict(Counter(attempt["status"] for attempt in attempts)),
                         "cell_statuses": dict(Counter(cell["status"] for cell in selected))})
    inventory = {}
    for name in ("controls-01", "capacity-01", "capacity-02", "suite"):
        for path in sorted((run / name).rglob("*")):
            if path.is_symlink():
                raise RuntimeError("unexpected artifact symlink: " + str(path))
            if path.is_file():
                inventory[str(path.relative_to(run))] = file_identity(path)
    save(output / "ARTIFACT_MANIFEST.json", {"files": inventory, "content_sha256": hashlib.sha256(canonical(inventory)).hexdigest()})
    archive_started = time.monotonic_ns()
    compression = {"format": "xz", "filter": "lzma2", "preset": 6,
                   "dictionary_bytes": 64 * 1024 * 1024, "check": "crc64", "threads": 1}
    # The dictionary spans repeated Rust ELF sections across complete files.
    # Keep every artifact byte and tar metadata; no stripping or deduplication.
    with (output / "artifacts.tar.xz").open("xb") as raw:
        with lzma.LZMAFile(raw, "w", check=lzma.CHECK_CRC64,
                          filters=[{"id": lzma.FILTER_LZMA2, "preset": compression["preset"],
                                    "dict_size": compression["dictionary_bytes"]}]) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name in inventory:
                    archive.add(run / name, arcname=name, recursive=False)
    archive_ns = time.monotonic_ns() - archive_started
    if any(file_identity(run / name) != value for name, value in inventory.items()):
        raise RuntimeError("raw artifacts changed during archive creation")
    events_after = Path("/sys/fs/cgroup/memory.events").read_text()
    parse_events = lambda text: {line.split()[0]: int(line.split()[1]) for line in text.splitlines()}
    before = parse_events(frozen["resources"]["memory.events"])
    after = parse_events(events_after)
    result = {"schema": "hepta.agent-replication.five-deliverables-readout.v1",
              "new_blind_tasks": False, "old_responses_rescored": False, "original_protocol_modified": False,
              "baseline_commit": frozen["baseline_commit"], "source_content_sha256": frozen["content_sha256"],
              "registration_sha256": file_identity(registration_path)["sha256"],
              "registered_source_count": len(registration["sources"]), "frozen_source_inventory_unchanged": unchanged,
              "complete_valid_coverage": cohort["complete_valid_coverage"], "models": models, "arms": arms,
              "cross_family_gates": cohort["cross_family_gates"],
              "cross_family_assembly_vs_json_gates": cohort["cross_family_assembly_vs_json_gates"],
              "controls": read(run / "controls-01/RESULT.json"),
              "capacity_attempts": [{"path": name, "passed": read(run / name / "RESULT.json")["passed"],
                                     "completion_requests": read(run / name / "RESULT.json")["model_requests"],
                                     "wall_ns": read(run / name / "RESULT.json")["wall_ns"]}
                                    for name in ("capacity-01", "capacity-02")],
              "memory_events_before": before, "memory_events_after": after,
              "new_cgroup_oom_events": after["oom"] - before["oom"],
              "new_cgroup_oom_kills": after["oom_kill"] - before["oom_kill"],
              "artifact_files": len(inventory), "artifact_archive": file_identity(output / "artifacts.tar.xz"),
              "artifact_archive_compression": compression,
              "artifact_archive_wall_ns": archive_ns, "collector_wall_ns": time.monotonic_ns() - started,
              "model_experiment_wall_ns_sum": sum(model["experiment_wall_ns"] for model in models)
                  if all(type(model["experiment_wall_ns"]) is int for model in models) else None,
              "manual_engineering_time_ns": None, "total_economic_cost_known": False,
              "limits": ["disclosed four-task repetition, not new blind tasks or independent population samples",
                         "two small quantized model families, not general Agent productivity",
                         "source snapshot differs from later development outside the registered closure; see the separate rebind report",
                         "unknown usage remains null; known token counts are only lower bounds",
                         "nested request, process, validation and preparation times must not be added as disjoint costs",
                         "no universal advantage, complete C++ migration, language soundness, or instruction optimality claim"],
              "observed_unix_ns": time.time_ns()}
    save(output / "READOUT.json", result)
    print(json.dumps({"complete_valid_coverage": result["complete_valid_coverage"], "models": models,
                      "artifact_files": len(inventory), "artifact_archive": result["artifact_archive"],
                      "collector_wall_ns": result["collector_wall_ns"]}), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-directory", "output"):
        parser.add_argument("--" + name, required=True)
    collect(**vars(parser.parse_args()))
