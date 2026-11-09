#!/usr/bin/env python3
"""Read-only, standard-library audit of a previously completed CI artifact.

No Hepta import, project checker, compiler, solver, native image or test is run.
Inputs are the original ZIP, saved official API metadata/log, and exact Git tree.
Outputs are independent derived tables and small, byte-preserved originals.
"""
import argparse
import base64
import collections
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct
import subprocess
import zipfile

HEAD = "6ecd8023615a6e0b2dc269379fb059c656b38b6f"
TREE = "4c51962e030e9ea39c6498224c99eb40fbdd2f35"
ZIP_SHA = "d8ad94fe9ab18679c1475de2e490c03620081e58bad52654031c73253e2d1dff"
P = "Hepta/Hepta/artifacts/verified-optimization/"
SCOPE = ("subject", "property", "profile", "assumptions", "checker", "unproved_obligations")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stats(values):
    ordered = sorted(values)
    median = statistics.median(ordered)
    return {"count": len(values), "minimum": ordered[0], "median": median,
            "p95": ordered[math.ceil(.95 * len(ordered)) - 1],
            "p99": ordered[math.ceil(.99 * len(ordered)) - 1], "maximum": ordered[-1],
            "relative_mad": statistics.median(abs(v - median) for v in ordered) / max(1, median),
            "excluded": 0}


def byte_sum(n, seed):
    cycles, tail = divmod(n, 256)
    return cycles * 32640 + sum(((seed & 255) + i) & 255 for i in range(tail))


def exported_symbol(image, name):
    """Extract existing ELF64 symbol bytes; never load or execute the image."""
    require(image[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
    phoff, shoff = struct.unpack_from("<QQ", image, 32)
    phsize, phnum, shsize, shnum = struct.unpack_from("<HHHH", image, 54)
    sections = [struct.unpack_from("<IIQQQQIIQQ", image, shoff + i * shsize) for i in range(shnum)]
    matches = []
    for section in sections:
        if section[1] != 11:
            continue
        strings = sections[section[6]]
        strings = image[strings[4]:strings[4] + strings[5]]
        for pos in range(section[4], section[4] + section[5], section[9]):
            no, info, other, index, value, size = struct.unpack_from("<IBBHQQ", image, pos)
            if strings[no:].split(b"\0", 1)[0] != name.encode():
                continue
            for i in range(phnum):
                seg = struct.unpack_from("<IIQQQQQQ", image, phoff + i * phsize)
                if seg[0] == 1 and seg[1] & 1 and seg[3] <= value and value + size <= seg[3] + seg[5]:
                    start = seg[2] + value - seg[3]
                    matches.append(image[start:start + size])
    require(len(matches) == 1 and matches[0], "export must have one file-backed executable range")
    return matches[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", type=Path, required=True)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--evidence-root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = args.output
    (out / "originals").mkdir(parents=True, exist_ok=True)
    members = {}
    source_groups = {}
    source_expected = {}
    image_bindings = []

    def save(name, value):
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False).encode() + b"\n")

    zip_hash = hashlib.sha256()
    with args.zip.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            zip_hash.update(chunk)
    require(args.zip.stat().st_size == 19759307 and zip_hash.hexdigest() == ZIP_SHA, "original ZIP identity")
    z = zipfile.ZipFile(args.zip)
    require(len(z.infolist()) == 1796 and sum(x.file_size for x in z.infolist()) == 227392009, "ZIP inventory")
    require(len(z.namelist()) == len(set(z.namelist())), "duplicate ZIP member")

    def raw(name):
        data = z.read(name)
        members[name] = {"bytes": len(data), "sha256": sha(data)}
        return data

    def obj(name):
        return json.loads(raw(name))

    def original(name, destination):
        data = raw(name)
        (out / "originals" / destination).write_bytes(data)

    def source_group(label, mapping):
        source_groups[label] = dict(mapping)
        for path, digest in mapping.items():
            require(isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest), "source SHA shape: " + path)
            require(path not in source_expected or source_expected[path] == digest, "inconsistent source SHA: " + path)
            source_expected[path] = digest

    def native_binding(label, folder, record):
        data = raw(P + folder + "/" + Path(record["path"]).name)
        require(len(data) == record["bytes"] and sha(data) == record["sha256"], "retained image identity: " + label)
        image_bindings.append({"label": label, "member": P + folder + "/" + Path(record["path"]).name,
                               "bytes": len(data), "sha256": sha(data)})

    official_paths = {
        "official-artifacts.json": "b6ecd-full-ndu-artifact-metadata.json",
        "official-run.json": "candidate-6ecd-ci-readback/final-ndu-run.json",
        "official-jobs.json": "candidate-6ecd-ci-readback/final-jobs-42565815059.json",
        "original-job.log": "candidate-6ecd-ci-readback/ndu-job-128991965937.log",
    }
    official = {}
    for name, path in official_paths.items():
        data = (args.evidence_root / path).read_bytes()
        (out / "originals" / name).write_bytes(data)
        official[name] = {"bytes": len(data), "sha256": sha(data)}
    metadata = json.loads((out / "originals/official-artifacts.json").read_bytes())["artifacts"]
    artifact = next(x for x in metadata if x["id"] == 13653895483)
    require(artifact["digest"] == "sha256:" + ZIP_SHA and artifact["size_in_bytes"] == 19759307, "official artifact digest")
    require(artifact["workflow_run"]["id"] == 42565815059 and artifact["workflow_run"]["head_sha"] == HEAD, "official artifact source")
    run = json.loads((out / "originals/official-run.json").read_bytes())
    require(run["id"] == 42565815059 and run["head_sha"] == HEAD and run["conclusion"] == "success" and run["run_attempt"] == 1, "run qualification")
    job = json.loads((out / "originals/official-jobs.json").read_bytes())["jobs"][0]
    require(job["id"] == 128991965937 and job["conclusion"] == "success", "job identity")
    log = (out / "originals/original-job.log").read_text()
    require("git checkout --progress --force " + HEAD in log and "HEAD is now at 6ecd802" in log, "actual head checkout in original log")
    require(raw(P + "source-sha.txt").decode().strip() == HEAD and raw(P + "source-tree.txt").decode().strip() == TREE, "artifact source/tree")

    parity = {}
    all_comparisons = []
    proof_receipts = {}
    for folder in ("release-parity", "verified-reduction-parity", "narrowed-reduction-parity"):
        report = obj(P + folder + "/RESULT.json")
        registration = obj(P + folder + "/REGISTRATION.json")
        spec = report["protocol"]
        require(registration["protocol"] == spec and registration["protocol_sha256"] == report["protocol_sha256"] == sha(wire(spec)), "frozen parity protocol")
        require(registration["measurements"] == [] and registration["status"] == "running", "registration before samples")
        require(report["source_before"]["head"] == report["source_after"]["head"] == HEAD and report["source_unchanged"], "parity source head")
        require(report["bindings_before"] == report["bindings_after"] == registration["bindings_before"], "parity source unchanged")
        source_group(folder, report["bindings_before"])
        rows = report["measurements"]
        keys = [(r["phase"], r["backend"], r["n"], r["seed"]) for r in rows]
        expected = {(phase, backend, n, seed) for phase in ("training", "holdout") for backend in spec["backends"]
                    for n in spec[phase + "_sizes"] for seed in spec[phase + "_seeds"]}
        require(len(keys) == len(set(keys)) == len(expected) == 120 and set(keys) == expected, "complete parity request denominator")
        lookup = dict(zip(keys, rows))
        raw_seen = []
        transcript_count = 0
        for phase in ("training", "holdout"):
            for seed_index, seed in enumerate(spec[phase + "_seeds"]):
                for backend in spec["backends"]:
                    transcript_count += 1
                    entries = [json.loads(line) for line in raw(P + folder + f"/{phase}-{seed_index}-{backend}.jsonl").decode().splitlines() if line.strip()]
                    require(entries[-1] == {"exit_code": 0, "stderr_hex": ""}, "native driver clean transcript exit")
                    requests = {}
                    responses = {}
                    for e in entries[:-1]:
                        if "request" in e:
                            require(e["sequence"] not in requests, "duplicate request sequence")
                            requests[e["sequence"]] = e["request"]
                        else:
                            require(set(e) == {"response_hex", "sequence"} and e["sequence"] not in responses, "response wrapper shape")
                            responses[e["sequence"]] = json.loads(bytes.fromhex(e["response_hex"]))
                    require(responses.pop(0).get("ready") is True and set(responses) == set(requests), "all transcript replies retained")
                    for seq, request in requests.items():
                        value = responses[seq]
                        if request.startswith("R "):
                            parts = request.split()
                            n = int(parts[2])
                            require(parts == ["R", "0", str(n), str(seed), str(spec["batch_calls"]), str(spec["samples"]), str(spec["warmup_calls"]), "0"], "frozen native request work")
                            key = (phase, backend, n, seed)
                            row = lookup[key]
                            require(all(row.get(k) == v for k, v in value.items()), "raw native response equals report row")
                            require(row["calls"] == spec["batch_calls"] and row["samples"] == spec["samples"] and len(row["times_ns"]) == spec["samples"], "timing sample count")
                            require(all(type(x) is int and 0 < x <= (1 << 63) - 1 for x in row["times_ns"]), "positive timing samples")
                            require(row["cold_value"] == row["observed"] == byte_sum(n, seed), "scalar result checksum")
                            require(row["batch_checksum"] == sum(byte_sum(n, (seed + i) & 0xffffffff) for i in range(row["calls"])), "batch checksum")
                            raw_seen.append(key)
                        elif request.startswith("L "):
                            require(value.get("loaded") == 0, "load response")
                        elif request.startswith("M "):
                            require(value.get("status") == "observed-loader-segments", "mapping response")
                        elif request == "Q":
                            require(value.get("closed") is True, "close response")
                        else:
                            require(False, "unexpected raw transcript request")
        require(len(raw_seen) == len(set(raw_seen)) == 120 and set(raw_seen) == expected, "complete raw JSONL request coverage")
        cohorts, comparisons = {}, []
        gate = spec["performance_gate"]
        require(gate == {"all_baselines_and_sizes_required": True, "hia_median_ratio_maximum": 1.1, "hia_tail_ratio_maximum": 1.2}, "unrelaxed registered parity thresholds")
        for phase in ("training", "holdout"):
            cohorts[phase] = {}
            for n in spec[phase + "_sizes"]:
                values = {backend: stats([v for row in rows if row["phase"] == phase and row["backend"] == backend and row["n"] == n for v in row["times_ns"]]) for backend in spec["backends"]}
                require(all(v["count"] == 63 for v in values.values()), "complete cohort timing denominator")
                cohorts[phase][str(n)] = values
                for baseline in ("c", "cpp", "rust"):
                    ratios = {s + "_ratio": values["hia"][s] / values[baseline][s] for s in ("median", "p95", "p99")}
                    comparisons.append({"phase": phase, "size": n, "baseline": baseline, **ratios,
                                        "passed": ratios["median_ratio"] <= 1.1 and ratios["p95_ratio"] <= 1.2 and ratios["p99_ratio"] <= 1.2})
        assessment = report["assessment"]
        require(cohorts == assessment["cohorts"] and comparisons == assessment["comparisons"], "independent parity statistics match original")
        require(assessment["performance_gate_passed"] == all(r["passed"] for r in comparisons), "parity gate")
        require(assessment["holdout_gate_passed"] == all(r["passed"] for r in comparisons if r["phase"] == "holdout"), "holdout gate")
        require(assessment["broad_rust_performance_parity_established"] is False and report["valid_observation"] is True, "parity scope")
        for backend, record in report["native_artifacts"].items():
            native_binding(folder + ":" + backend, folder, record)
        native_binding(folder + ":driver", folder, report["driver_identity"])
        if "hia_guarded_compilation" in report:
            proof = obj(P + folder + "/hia.guarded-proof.json")
            require(proof == report["hia_guarded_compilation"], "proof original matches embedded receipt")
            require(proof["native"]["artifact_sha256"] == report["native_artifacts"]["hia"]["sha256"], "proof image binding")
            proof_receipts[folder] = proof
            original(P + folder + "/hia.guarded-proof.json", folder + "-proof.json")
        parity[folder] = {"status": report["status"], "valid_observation": True,
                          "requests": len(rows), "timed_batches": sum(len(r["times_ns"]) for r in rows),
                          "calls_per_batch": spec["batch_calls"], "raw_jsonl_transcripts": transcript_count,
                          "all_raw_responses_bound": True, "cohorts": cohorts,
                          "training_passed": sum(c["passed"] for c in comparisons if c["phase"] == "training"), "training_total": 9,
                          "holdout_passed": sum(c["passed"] for c in comparisons if c["phase"] == "holdout"), "holdout_total": 21,
                          "performance_gate_passed": assessment["performance_gate_passed"],
                          "holdout_gate_passed": assessment["holdout_gate_passed"], "broad_rust_performance_parity_established": False,
                          "build_profile": report["build_profile"], "toolchains": report["toolchains"],
                          "cost_scope": report["cost_scope"], "campaign_wall_ns": report["campaign_wall_ns"],
                          "whole_lifecycle_cost_ns": report["whole_lifecycle_cost_ns"], "energy_joules": report["energy_joules"],
                          "manual_engineering_ns": report["manual_engineering_ns"],
                          "original_correctness_rows": len(report["correctness"]),
                          "correctness_suite_independently_reexecuted": False}
        all_comparisons.extend({"profile": folder, **c} for c in comparisons)
        save("protocols/" + folder + ".json", {"derived_copy_of_original_protocol": spec, "sha256_canonical": report["protocol_sha256"]})

    guard = obj(P + "guarded-opportunity/RESULT.json")
    protocol_bytes = raw(P + "guarded-opportunity/frozen-protocol.json")
    spec = json.loads(protocol_bytes)
    require(sha(protocol_bytes) == guard["protocol_sha256"] == "1b4d1818d7fa9aff079bf7b27220d9f4df2bc0668a52b827e8a0adbd1b8cebbf", "preregistered opportunity bytes")
    require(spec == guard["protocol"] and guard["qualified"] is True and guard["status"] == "no-economic-opportunity", "opportunity result scope")
    require(guard["expected_source"] == HEAD and guard["source_before"] == guard["source_after"], "opportunity source identity")
    require(guard["source_state_before"] == guard["source_state_after"] and guard["source_state_before"]["head"] == HEAD and guard["source_state_before"]["tree"] == TREE, "whole source snapshot unchanged")
    source_group("guarded-opportunity", guard["source_before"])
    source_group("guarded-opportunity-protocol", {"experiments/hia_guarded_opportunity/protocol_v1.json": sha(protocol_bytes)})
    original(P + "guarded-opportunity/frozen-protocol.json", "guarded-opportunity-protocol.json")
    exports = {}
    six_scopes = {}
    for action, candidate in guard["candidates"].items():
        image = raw(P + "guarded-opportunity/" + action + ".so")
        require(sha(image) == candidate["compilation"]["artifact_sha256"] == candidate["native_differential"]["artifact_sha256"], "guarded candidate image binding")
        code = exported_symbol(image, "calculate")
        recorded = guard["exported_code"][action]
        require(sha(code) == recorded["sha256"] and code.hex() == recorded["hex"] and len(code) == recorded["bytes"], "distinct exported bytes from actual ELF")
        exports[action] = {"bytes": len(code), "sha256": sha(code), "artifact_sha256": sha(image), "machine_code_semantics_proved": False}
        proof = candidate["translation"]
        require(all(field in proof for field in SCOPE) and proof["status"] == "verified" and proof["execution_authority"] is False, "six-field translation proof")
        require(sha(wire(proof["checker"]["source_identity"])) == proof["checker"]["source_identity_sha256"], "canonical proof checker digest")
        source_group("guarded-translation-" + action, {"hepta/" + k: v for k, v in proof["checker"]["source_identity"].items()})
        six_scopes[action] = {k: proof[k] for k in (*SCOPE, "status", "execution_authority")}
    require(len({e["sha256"] for e in exports.values()}) == 3, "genuinely distinct exported code")
    samples = guard["samples"]
    expected = {(m["id"], phase, action, trial, seed) for m in spec["modules"] for phase in ("training", "validation")
                for action in spec["actions"] for trial, seed in enumerate(spec[phase + "_seeds"])}
    sample_keys = [(s["module"], s["phase"], s["candidate"], s["trial"], s["seed"]) for s in samples]
    require(len(sample_keys) == len(set(sample_keys)) == len(expected) == 84 and set(sample_keys) == expected, "complete opportunity denominator")
    driver = raw(P + "guarded-opportunity/driver")
    for sample in samples:
        stdout = base64.b64decode(sample["raw_stdout_base64"], validate=True)
        stderr = base64.b64decode(sample["raw_stderr_base64"], validate=True)
        value = json.loads(stdout)
        require(stdout.decode() == sample["stdout"] and stderr.decode() == sample["stderr"] and not stderr and sample["returncode"] == 0, "original guarded output bytes")
        require(all(sample.get(k) == v for k, v in value.items()), "guarded raw response fields")
        require(sample["checksum"] == sample["expected_checksum"] and sample["calls"] == spec["iterations_per_batch"], "guarded finite sample checksum/work")
        require(sample["artifact_sha256"] == exports[sample["candidate"]]["artifact_sha256"] and sample["driver_sha256"] == sha(driver), "guarded sample image/driver")
    economics = guard["economics"]
    future_batches = spec["expected_calls_per_module"] // spec["iterations_per_batch"]
    require(future_batches == economics["future_batches_per_module"] == 500, "registered synthetic horizon")
    recalculated = []
    for module in economics["module_opportunities"]:
        phases = {}
        for phase, original_phase in module["phases"].items():
            base = [s for s in samples if s["module"] == module["module"] and s["phase"] == phase and s["candidate"] == "baseline"]
            selected = [s for s in samples if s["module"] == module["module"] and s["phase"] == phase and s["candidate"] == module["candidate"]]
            require(len(base) == len(selected) == 7, "seven samples per module/phase/action")
            lo = min(s["outer_wall_ns"] for s in base)
            hi = max(s["outer_wall_ns"] for s in selected)
            saved = lo - hi
            result = {"baseline_min_batch_ns": lo, "candidate_max_batch_ns": hi,
                      "conservative_saved_batch_ns": saved, "prospective_savings_ns": saved * future_batches,
                      "net_savings_ns": saved * future_batches - guard["charged_search_wall_ns"],
                      "kernel_saved_batch_ns_diagnostic": min(s["elapsed_ns"] for s in base) - max(s["elapsed_ns"] for s in selected)}
            require(all(original_phase[k] == v for k, v in result.items()), "opportunity envelope arithmetic")
            phases[phase] = result
        positive = all(v["net_savings_ns"] > 0 for v in phases.values())
        require(positive == module["positive_after_all_costs"] is False, "module net opportunity gate")
        recalculated.append({"module": module["module"], "candidate": module["candidate"], "phases": phases, "positive_after_all_costs": positive})
    require(economics["opportunity_gate_passed"] is False and economics["ndu_comparison_authorized_by_this_evidence"] is False and economics["NDU_gain_established"] is False, "opportunity does not authorize NDU gain")
    guarded_summary = {"qualified": True, "status": guard["status"], "all_84_original_outputs_bound": True,
                       "samples": 84, "exports_from_retained_ELF": exports, "charged_search_wall_ns": guard["charged_search_wall_ns"],
                       "cost_stages": guard["cost_stages"], "cost_exclusions": guard["cost_exclusions"],
                       "module_opportunities_recomputed": recalculated, "original_economics": economics,
                       "unchanged_full_source_snapshot_entries": len(guard["source_state_before"]["files"]),
                       "full_9833_entry_map_independently_compared_to_Git": False,
                       "recorded_before_after_map_equal": True, "claims": guard["claims"]}
    save("guarded-opportunity-samples.json", [{k:v for k,v in s.items() if k not in ("raw_stdout_base64", "raw_stderr_base64", "stdout", "stderr")} for s in samples])
    save("six-field-translation-scopes.json", six_scopes)

    policy_results = {}
    policy_rows = []
    for folder in ("native-release-ndu", "verified-reduction-ndu", "narrowed-reduction-ndu"):
        report = obj(P + folder + "/RESULT.json")
        require(report["source_before"]["head"] == report["source_after"]["head"] == HEAD and report["source_unchanged"], "native policy source")
        require(report["input_hashes_before"] == report["input_hashes_after"], "native policy source maps")
        source_group(folder, report["input_hashes_before"])
        rows = report["policy_runs"]
        expected = {(episode, arm) for episode in range(len(report["protocol"]["episodes"])) for arm in report["protocol"]["policy_arms"]}
        keys = [(r["episode"], r["arm"]) for r in rows]
        require(len(rows) == len(set(keys)) == len(expected) == 12 and set(keys) == expected, "complete policy cohort")
        require(all(r["status"] == "passed" and r["service_total_ns"] == r["actual_total_ns"] - r["independent_audit_ns"] for r in rows), "service accounting")
        lookup = dict(zip(keys, rows))
        comparisons = []
        for episode in range(3):
            ndu = lookup[(episode, "native_ndu")]["service_total_ns"]
            for baseline in ("fixed", "exact_dp", "greedy"):
                cost = lookup[(episode, baseline)]["service_total_ns"]
                comparisons.append({"episode": episode, "baseline": baseline, "ndu_ns": ndu, "baseline_ns": cost, "ratio": ndu / cost, "passed": ndu < cost})
        acceptance = report["acceptance"]
        require(comparisons == acceptance["economic_comparisons"], "recomputed native policy comparisons")
        require(sum(r["native_invocations"] for r in rows) == acceptance["native_policy_invocations"] == 0, "no native NDU policy call")
        for claim in ("service_scope_gated_policy_benefit_established", "service_scope_net_ndu_benefit_established", "whole_lifecycle_net_ndu_benefit_established", "complete_lifecycle_cost_known"):
            require(acceptance[claim] is False, "nonpositive economics retained: " + claim)
        require(report["acceptance_observation_valid"] is True, "qualified observation distinct from economic win")
        # Training comparisons are recomputed from all 36 rows in RESULT; these
        # are not relabelled as the independent 120-row release-parity holdout.
        training = report["training"]
        expected_training = {(b, n, seed) for b in report["protocol"]["backends"] for n in report["protocol"]["sizes"] for seed in report["protocol"]["training_seeds"]}
        training_keys = [(r["backend"], r["n"], r["seed"]) for r in training]
        require(len(training_keys) == len(set(training_keys)) == 36 and set(training_keys) == expected_training, "native training denominator")
        train_comps = []
        for n in report["protocol"]["sizes"]:
            summaries = {b: stats([t for r in training if r["backend"] == b and r["n"] == n for t in r["times_ns"]]) for b in report["protocol"]["backends"]}
            for baseline in ("c", "cpp", "rust"):
                ratios = {s + "_ratio": summaries["hia"][s] / summaries[baseline][s] for s in ("median", "p95", "p99")}
                train_comps.append({"size": n, "baseline": baseline, **ratios, "passed": ratios["median_ratio"] <= 1.1 and ratios["p95_ratio"] <= 1.2 and ratios["p99_ratio"] <= 1.2})
        require(train_comps == acceptance["performance_comparisons"], "native training statistics")
        policy_results[folder] = {"original_acceptance": acceptance, "recomputed_policy_comparisons": comparisons,
                                 "recomputed_training_comparisons": train_comps, "policy_rows": 12,
                                 "native_policy_invocations": 0, "cost_exclusions": report["cost_exclusions"],
                                 "training_raw_jsonl_independently_reconciled": False,
                                 "all_policy_step_transcripts_independently_reconciled": False}
        policy_rows.extend({"profile": folder, **{k: r[k] for k in ("episode", "arm", "status", "actual_total_ns", "independent_audit_ns", "service_total_ns", "native_invocations")}} for r in rows)

    loop = obj(P + "ndu-loop/RESULT.json")
    source_group("ndu-loop", loop["source_identity"])
    loop_summary = {k: loop[k] for k in ("median_net_cost_ns", "median_amortized_net_cost_ns", "standalone_total_cost_ns", "setup_accounting", "all_actual_budgets_passed", "all_actual_outputs_correct", "all_episodes_completed", "ndu_descriptive_cost_lower_than_light", "ndu_descriptive_cost_lower_than_selected_fixed", "statistical_superiority_established", "interpretation", "authority")}
    loop_summary.update(episode_count=len(loop["episodes"]), independent_episode_or_solver_replay=False,
                        source="Original CI result summarized; not an independently rerun economic study.")
    loop_bank = obj(P + "ndu-loop/BANK.json")
    loop_summary["bank_native_bytes_identical_original"] = loop_bank["native_bytes_identical"]
    original(P + "ndu-loop/FAULTS.json", "ndu-loop-original-fault-controls.json")
    costed = obj(P + "costed-native-ndu/RESULT.json")
    background = obj(P + "background-costs.json")
    other = {"costed_native": {k: costed[k] for k in ("status", "mode", "native_calls", "exact_dp_comparison", "application_speedup_established", "net_ndu_benefit_established", "authority")},
             "background": {k: background[k] for k in ("ok", "actual_native_ndu_invocations", "native_measurement_calls", "claims")},
             "boundary": "Original limited-model and lifecycle controls summarized only. No independent replay of their nested request/response trees; synthetic lifecycle costs are not benchmark results."}

    # Only relevant recorded source maps, not every large historical tracked
    # evidence object, are independently matched against the exact Git tree.
    raw_tree = subprocess.check_output(["git", "-C", str(args.repo), "ls-tree", "-rz", TREE])
    tree_map = {}
    for row in raw_tree.split(b"\0"):
        if row:
            meta, path = row.split(b"\t", 1)
            mode, typ, oid = meta.decode().split()
            if typ == "blob":
                tree_map[path.decode()] = oid
    extras = (".github/workflows/verified-optimization.yml", "tools/qualify_hia_guarded_opportunity.py",
              "tools/qualify_hia_release_parity.py", "tools/qualify_hia_native_ndu.py",
              "hepta/hia_guarded_batch.py", "hepta/hia_optimization.py", "hepta/hia_guarded_optimization.py",
              "hepta/hia_narrowing.py", "hepta/hia_scalar_proof_contract.py")
    paths = sorted(set(source_expected) | {p for p in extras if p in tree_map})
    require(all(p in tree_map for p in paths), "source path in exact tree")
    response = subprocess.check_output(["git", "-C", str(args.repo), "cat-file", "--batch"], input="".join(tree_map[p] + "\n" for p in paths).encode())
    offset = 0
    source_bytes = {}
    source_verified = {}
    for path in paths:
        end = response.index(b"\n", offset)
        oid, typ, size = response[offset:end].decode().split()
        size = int(size)
        data = response[end + 1:end + 1 + size]
        offset = end + size + 2
        require(typ == "blob" and hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest() == oid == tree_map[path], "Git blob content address")
        require(path not in source_expected or sha(data) == source_expected[path], "recorded source matches B blob: " + path)
        source_bytes[path] = data
        source_verified[path] = {"git_blob": oid, "bytes": size, "sha256": sha(data)}
    require(offset == len(response), "complete Git batch consumption")
    source_group_counts = {k: len(v) for k, v in source_groups.items()}
    names = ("hia_optimization.py", "hia_program.py", "hia_capability_flow.py", "hia_opcodes.py", "hia_schema.py", "hia_program_composite.py", "hia_json_preflight.py", "hia_program_runtime.py", "hia_bounded_memory.py")
    optimization = sha(b"".join(n.encode() + b"\0" + source_bytes["hepta/" + n] + b"\0" for n in names))
    guarded_checker = sha(optimization.encode() + b"".join(n.encode() + b"\0" + source_bytes["hepta/" + n] + b"\0" for n in ("hia_guarded_optimization.py", "hia_inductive.py")))
    narrowing = sha(optimization.encode() + source_bytes["hepta/hia_narrowing.py"])
    chain = sha(wire({"narrowing": narrowing, "guarded": guarded_checker}))
    require(loop["checker_sha256"] == optimization, "loop checker source identity")
    require(proof_receipts["verified-reduction-parity"]["verification"]["checker_sha256"] == guarded_checker, "guarded checker identity")
    narrow = proof_receipts["narrowed-reduction-parity"]["verification"]
    require(narrow["checker_sha256"] == chain and narrow["stages"][0]["proof"]["checker_sha256"] == guarded_checker and narrow["stages"][1]["proof"]["checker_sha256"] == narrowing, "narrowed chain/stage checker identities")
    for folder, receipt in proof_receipts.items():
        require(receipt["claims"]["backend_refinement_proved"] is False and receipt["claims"]["final_artifact_bound"] is True, "Core proof is not machine refinement")
        proof = receipt["verification"]
        require(proof["claims"]["whole_language_soundness_proved"] is False and proof["claims"]["deployment_authority"] is False, "legacy proof claim boundaries")
        core = obj(P + folder + "/hia.core.json")
        optimized = obj(P + folder + "/hia.optimized.core.json")
        require(sha(wire(core)) == proof["base_sha256"] and sha(wire(optimized)) == proof["candidate_sha256"] == receipt["native"]["core_sha256"], "original/final Core binding")
        bound = {"base": proof["base_sha256"], "candidate": proof["candidate_sha256"], "verification": proof["verification_sha256"],
                 "artifact": receipt["native"]["artifact_sha256"], "compiler": receipt["native"]["toolchain"]["sha256"], "target": receipt["native"]["target"]}
        require(sha(wire(bound)) == receipt["binding_sha256"], "legacy proof/native binding digest")

    audit = {"schema": "hepta.independent-full-ndu-readonly-audit.v1", "status": "PASS_READONLY_EVIDENCE_RECONCILIATION",
             "source_commit": HEAD, "source_tree": TREE, "run_id": 42565815059, "job_id": 128991965937, "artifact_id": 13653895483,
             "artifact_sha256": ZIP_SHA, "artifact_bytes": 19759307, "artifact_members": 1796, "uncompressed_member_bytes": 227392009,
             "official_originals": official, "actual_checkout": HEAD, "original_ci_attempt": 1,
             "source_groups_verified": source_group_counts, "distinct_git_source_blobs_verified": len(source_verified),
             "checker_identities_recomputed": {"optimization": optimization, "guarded": guarded_checker, "narrowing": narrowing, "chain": chain},
             "parity": parity, "guarded_opportunity": guarded_summary, "native_policy": policy_results,
             "original_loop_summary": loop_summary, "other_original_limited_controls": other,
             "scope": {"project_code_imports_or_execution": 0, "local_compiler_solver_native_or_test_runs": 0,
                       "all_ci_successes_independently_reexecuted": False,
                       "source_qualification_transferred_from_other_heads": False,
                       "stable_incremental_ndu_or_complete_economic_benefit_established": False,
                       "bounded_narrowed_kernel_complete_training_and_holdout_performance_gate": True,
                       "formal_translation_scope_fields_verified": list(SCOPE),
                       "legacy_optimization_lowering_receipts_are_six_field_machine_proofs": False,
                       "legacy_receipt_boundary": "Bounded Core transformation/native-byte binding under trusted compiler/linker/loader/libc/hardware; no general machine or whole-language proof.",
                       "performance_boundary": "One instrumented owned-byte kernel, finite registered sizes/seeds, one shared host, differing compiler implementations/LLVM versions, empirical batch timing. No general Rust parity, production demand, energy or complete human/tool acquisition cost claim.",
                       "preregistration_boundary": "Frozen protocol bytes and initial registrations are bound; this audit does not independently attest historical wall-clock order beyond original CI logs and static source flow."}}
    save("audit.json", audit)
    save("parity-comparisons.json", all_comparisons)
    save("native-policy-rows.json", policy_rows)
    save("source-bindings.json", {"tree": TREE, "groups": source_groups, "blobs": source_verified})
    save("native-image-bindings.json", image_bindings)
    save("analyzed-original-members.json", members)
    print(json.dumps({"status": audit["status"], "source_blobs": len(source_verified), "original_members_read": len(members),
                      "parity": {k: [v["training_passed"], v["holdout_passed"]] for k,v in parity.items()},
                      "guarded_samples": 84, "opportunity_gate": False, "native_policy_calls": [0,0,0]}, sort_keys=True))


if __name__ == "__main__":
    main()
