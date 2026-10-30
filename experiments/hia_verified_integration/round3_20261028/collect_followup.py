"""Read-only result extraction and lossless retention; never runs a workload."""
from __future__ import annotations
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import time


def collect(source, destination, name):
    source, destination = Path(source).resolve(strict=True), Path(destination).resolve(strict=True)
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in name):
        raise ValueError("Plain artifact name required")
    raw_result = (source / "RESULT.json").read_bytes()
    result = json.loads(raw_result)
    if result["schema"] != "hepta.hia.registered-followup.result.v1":
        raise ValueError("Unsupported study result")
    archive = destination / (name + ".tar.xz")
    manifest_path = destination / (name + ".manifest.json")
    summary_path = destination / (name + ".summary.json")
    if any(p.exists() for p in (archive, manifest_path, summary_path)):
        raise FileExistsError("Completed or failed evidence is immutable")
    summary = {k: result.get(k) for k in ("schema", "kind", "registration_sha256", "host",
        "status", "all_costs_known", "global_optimality_claim", "implementation_gate_passed",
        "finite_net_benefit_gate_passed", "statistical_superiority_established",
        "bound_inputs_unchanged", "retained_sources", "runner_wall_ns_before_final_report", "error")}
    summary.update(schema="hepta.hia.registered-followup.readout.v1",
        raw_result_sha256=sha256(raw_result).hexdigest(), deployment_authority=False,
        scientific_gate_recomputed=False, samples_excluded=0)
    if result["kind"] == "stream-ndu" and "measurement" in result:
        measured = result["measurement"]
        for field in ("native_identity", "native_binary_sha256", "native_transport", "native_session",
                      "bank_sha256", "median_episode_cost_ns", "median_amortized_cost_ns",
                      "standalone_total_cost_ns", "setup_accounting", "study_wall_ns",
                      "study_plus_native_build_wall_ns", "actual_transitions", "all_episodes_completed",
                      "all_outputs_correct", "all_actual_budgets_passed"):
            summary[field] = measured[field]
        summary["wrapper_cost"] = result["wrapper_cost"]
        summary["standalone_total_cost_with_wrapper_ns"] = result["standalone_total_cost_with_wrapper_ns"]
        bank = json.loads((source / "graph/BANK.json").read_bytes())
        summary["counts"] = {"episodes": len(measured["episodes"]),
            "workload_observations": sum(len(e["observations"]) for e in measured["episodes"]),
            "calibration_observations": sum(len(c["samples"]) for c in bank["candidates"].values()),
            "actual_transitions": measured["actual_transitions"]}
        summary["candidate_statuses"] = {name: c["verification"]["status"]
                                         for name, c in bank["candidates"].items()}
        summary["episodes"] = [{"arm": e["arm"], "group": e["group"], "status": e["status"],
            "actual_budget_passed": e["actual_budget_passed"], "completion_admitted": e["completion_admitted"],
            "net_cost_ns": e["net_cost_ns"], "error": e.get("error"),
            "transitions": [{k: t[k] for k in ("batch", "source", "target")} for t in e["transitions"]],
            "chosen_actions": [d["bundle"]["plans"][d["selected_plan"]]["actions"]
                if d["selected_plan"] in d["bundle"]["plans"] else [] for d in e["decisions"]],
            "all_actual_mappings_verified": all(o.get("loaded_mapping_verified") for o in e["observations"])}
            for e in measured["episodes"]]
    elif result["kind"] == "prepared-runtime":
        summary["samples"] = []
        for row in result.get("samples", []):
            retained = {k: v for k, v in row.items() if k not in {"builds", "driver", "snapshot"}}
            snapshot = row.get("snapshot", {})
            retained["proof_reuse_selections"] = [e for e in snapshot.get("events", [])
                if e.get("event") == "selected" and e.get("proof_reuse", {}).get("new_solver_call") is False]
            summary["samples"].append(retained)
        for key in ("shared_wrapper_ns", "shared_wrapper_cost_policy", "median_deployment_api_ns",
                    "median_baseline_execution_ns", "median_measured_net_ns"):
            summary[key] = result.get(key)
    started = time.monotonic_ns()
    members = []
    total = 0
    with tarfile.open(archive, "x:xz", preset=3) as output:
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("Evidence contains a symbolic link")
            if not path.is_file():
                continue
            content = path.read_bytes()
            total += len(content)
            if total > 1024**3:
                raise ValueError("Finite evidence archive budget exceeded")
            relative = str(path.relative_to(source))
            entry = tarfile.TarInfo(relative)
            entry.size, entry.mtime, entry.mode = len(content), 0, path.stat().st_mode & 0o777
            output.addfile(entry, io.BytesIO(content))
            members.append({"path": relative, "bytes": len(content), "sha256": sha256(content).hexdigest()})
    with tarfile.open(archive, "r:xz") as check:
        if len(check.getmembers()) != len(members):
            raise ValueError("Archive member census changed")
        for member in members:
            content = check.extractfile(member["path"]).read()
            if len(content) != member["bytes"] or sha256(content).hexdigest() != member["sha256"]:
                raise ValueError("Archive differs from retained source bytes")
    archive_record = {"schema": "hepta.hia.followup.lossless-archive.v1", "file": archive.name,
        "bytes": archive.stat().st_size, "sha256": sha256(archive.read_bytes()).hexdigest(),
        "members": members, "raw_bytes": total, "all_member_hashes_verified": True,
        "pack_and_verify_ns": time.monotonic_ns() - started,
        "collector_sha256": sha256(Path(__file__).read_bytes()).hexdigest(), "native_workloads_executed": 0}
    with manifest_path.open("x") as stream:
        json.dump(archive_record, stream, indent=2, sort_keys=True)
        stream.write("\n")
    summary["archive"] = {k: v for k, v in archive_record.items() if k != "members"}
    with summary_path.open("x") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    value = collect(args.source, args.destination, args.name)
    print(json.dumps({k: value[k] for k in ("status", "implementation_gate_passed",
                                         "finite_net_benefit_gate_passed", "archive")}))
