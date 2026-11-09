#!/usr/bin/env python3
"""Compare two fixed, completed artifacts; stdlib-only and no project execution."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import zipfile

P = "Hepta/Hepta/artifacts/verified-optimization/"
POLICIES = ("native-release-ndu", "verified-reduction-ndu", "narrowed-reduction-ndu")
METRICS = ("attempts", "allocations", "frees", "refusals", "live", "requested_total", "usable_total", "peak_requested", "peak_usable", "live_requested", "live_usable", "accounting_errors", "stack_anchor", "stack_max_distance")


def digest(b):
    return hashlib.sha256(b).hexdigest()


def stats(values):
    a = sorted(values)
    return {"count": len(a), "median": statistics.median(a), "p95": a[math.ceil(.95 * len(a)) - 1], "p99": a[math.ceil(.99 * len(a)) - 1]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-zip", type=Path, required=True)
    parser.add_argument("--new-zip", type=Path, required=True)
    parser.add_argument("--old-review", type=Path, required=True)
    parser.add_argument("--new-review", type=Path, required=True)
    args = parser.parse_args()
    audit_old = json.loads((args.old_review / "audit.json").read_bytes())
    audit_new = json.loads((args.new_review / "audit.json").read_bytes())
    assert audit_old["source_commit"] == audit_new["source_commit"] == "6ecd8023615a6e0b2dc269379fb059c656b38b6f"
    assert audit_old["source_tree"] == audit_new["source_tree"] == "4c51962e030e9ea39c6498224c99eb40fbdd2f35"
    source_old = json.loads((args.old_review / "source-bindings.json").read_bytes())
    source_new = json.loads((args.new_review / "source-bindings.json").read_bytes())
    assert source_old == source_new
    runs, raw_members = [], []
    all_reports = []
    for path, audited in ((args.old_zip, audit_old), (args.new_zip, audit_new)):
        assert digest(path.read_bytes()) == audited["artifact_sha256"]
        z = zipfile.ZipFile(path)
        reports = {}
        checks = {}
        for profile in POLICIES:
            report = json.loads(z.read(P + profile + "/RESULT.json"))
            reports[profile] = report
            spec = report["protocol"]
            rows = {(r["backend"], r["n"], r["seed"]): r for r in report["training"]}
            assert len(rows) == len(report["training"]) == 36
            seen = []
            for seed_index, seed in enumerate(spec["training_seeds"]):
                for backend in spec["backends"]:
                    name = P + profile + f"/training-{seed_index}-{backend}.jsonl"
                    raw = z.read(name)
                    raw_members.append({"run_id": audited["run_id"], "member": name, "bytes": len(raw), "sha256": digest(raw)})
                    records = [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
                    assert records[-1] == {"exit_code": 0, "stderr_hex": ""}
                    requests = {e["sequence"]: e["request"] for e in records if "request" in e}
                    responses = {e["sequence"]: json.loads(bytes.fromhex(e["response_hex"])) for e in records if "response_hex" in e}
                    assert len(requests) + len(responses) + 1 == len(records)
                    assert responses.pop(0)["ready"] is True and set(requests) == set(responses)
                    for sequence, request in requests.items():
                        value = responses[sequence]
                        if not request.startswith("R "):
                            continue
                        row = rows[(backend, value["n"], seed)]
                        expected = ["R", str(row["id"]), str(row["n"]), str(seed), str(spec["batch_calls"]), str(spec["training_samples_per_request"]), str(spec["warmup_calls"]), "0"]
                        assert request.split() == expected
                        assert len(value["metrics"]) == len(METRICS)
                        metrics = dict(zip(METRICS, value["metrics"]))
                        metrics["allocator_slack_bytes"] = metrics["peak_usable"] - metrics["peak_requested"]
                        value["metrics"] = metrics
                        assert all(row[k] == v for k, v in value.items())
                        assert sum(value["times_ns"]) == value["elapsed_ns"]
                        seen.append((backend, value["n"], seed))
            assert len(seen) == len(set(seen)) == 36 and set(seen) == set(rows)
            checks[profile] = {"raw_transcripts": 12, "requests": 36, "timing_batches": sum(len(r["times_ns"]) for r in rows.values()), "all_native_response_fields_bound": True}
        all_reports.append(reports)
        runs.append({"run_id": audited["run_id"], "artifact_id": audited["artifact_id"], "artifact_sha256": audited["artifact_sha256"], "policy_training_raw_checks": checks})
    parity_rows = []
    old_parity = json.loads((args.old_review / "parity-comparisons.json").read_bytes())
    new_parity = json.loads((args.new_review / "parity-comparisons.json").read_bytes())
    assert len(old_parity) == len(new_parity) == 90
    for old, new in zip(old_parity, new_parity):
        identity = {k: old[k] for k in ("profile", "phase", "size", "baseline")}
        assert identity == {k: new[k] for k in identity}
        parity_rows.append({**identity, "original": old, "postintegration": new, "gate_changed": old["passed"] != new["passed"]})
    policy_rows = []
    for profile in POLICIES:
        old, new = all_reports[0][profile], all_reports[1][profile]
        assert old["protocol"] == new["protocol"]
        for oc, nc in zip(audit_old["native_policy"][profile]["recomputed_training_comparisons"], audit_new["native_policy"][profile]["recomputed_training_comparisons"]):
            assert (oc["size"], oc["baseline"]) == (nc["size"], nc["baseline"])
            values = []
            for r in (old, new):
                values.append({b: stats([t for row in r["training"] if row["n"] == oc["size"] and row["backend"] == b for t in row["times_ns"]]) for b in ("hia", oc["baseline"])})
            policy_rows.append({"profile": profile, "size": oc["size"], "baseline": oc["baseline"], "original": oc, "postintegration": nc,
                                "gate_changed": oc["passed"] != nc["passed"], "original_stats": values[0], "postintegration_stats": values[1]})
    original_images = {r["label"]: r["sha256"] for r in json.loads((args.old_review / "native-image-bindings.json").read_bytes())}
    new_images = {r["label"]: r["sha256"] for r in json.loads((args.new_review / "native-image-bindings.json").read_bytes())}
    assert set(original_images) == set(new_images)
    image_changes = [k for k in original_images if original_images[k] != new_images[k]]
    opportunities = [{"run_id": a["run_id"], "charged_search_wall_ns": a["guarded_opportunity"]["charged_search_wall_ns"],
                      "modules": a["guarded_opportunity"]["module_opportunities_recomputed"],
                      "exports": a["guarded_opportunity"]["exports_from_retained_ELF"]} for a in (audit_old, audit_new)]
    result = {"schema": "hepta.same-source-full-ndu-repeat-comparison.v1", "status": "PASS_READONLY_COMPARISON",
              "runs": runs, "same_238_exact_source_blobs": True, "same_native_policy_registered_protocols": True,
              "parity_comparisons": parity_rows, "native_policy_training_comparisons": policy_rows,
              "additional_raw_policy_training_members": raw_members, "opportunities": opportunities,
              "parity_image_labels_with_different_hashes": image_changes,
              "claims": {"narrowed_release_parity_gate_passes_in_both_runs": all(a["parity"]["narrowed-reduction-parity"]["performance_gate_passed"] for a in (audit_old,audit_new)),
                         "every_related_performance_gate_reproduced": False,
                         "statistical_stability_or_general_performance_proved": False,
                         "stable_incremental_NDU_or_complete_economic_gain": False,
                         "new_native_solver_compiler_or_project_execution": False}}
    (args.new_review / "comparison.json").write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({"status":result["status"],"additional_raw_policy_training_transcripts":len(raw_members),
                      "additional_raw_policy_training_requests":216,"additional_raw_policy_training_batches":4536,
                      "parity_gate_flips":[{k:r[k] for k in ('profile','phase','size','baseline')} for r in parity_rows if r['gate_changed']],
                      "policy_training_gate_flips":[{k:r[k] for k in ('profile','size','baseline')} for r in policy_rows if r['gate_changed']],
                      "parity_image_changes":image_changes},sort_keys=True))


if __name__ == "__main__":
    main()
