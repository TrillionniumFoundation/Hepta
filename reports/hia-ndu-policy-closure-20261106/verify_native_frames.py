#!/usr/bin/env python3
"""Read-only independent audit of the completed NDU policy campaign's wire evidence.

No tested Python helper, simulator, native binary or controller is imported/run.
The byte serializers below independently implement the pinned original Rust
recursive and evaluation receipt formats, including their policy/profile and
per-candidate contribution digests. This is local evidence verification, not
hardware attestation or a physical workload/net-benefit experiment.
"""
import argparse
from collections import Counter
import gzip
from hashlib import sha256
import json
from pathlib import Path
import struct
import time

Q32 = 1 << 32
LIMIT = 1_000_000 * Q32
UPSTREAM = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"
ARMS = ("dynamic-ndu", "fixed-preference-ndu")
AXIS, RISK, RESOURCE, ORGAN = "utility.net", "risk.tail", "resource.optimization", "hia.control"


def require(ok, reason):
    if not ok:
        raise AssertionError(reason)


def load(path):
    path = Path(path)
    with (gzip.open if path.suffix == ".gz" else open)(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def identity(path):
    path = Path(path)
    hasher = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(block)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": hasher.hexdigest()}


def h(raw):
    return sha256(raw).digest()


def u32(value):
    return struct.pack(">I", value)


def u64(value):
    return struct.pack(">Q", value)


def i64(value):
    return struct.pack(">q", value)


def sid(value):
    raw = value.encode("utf-8")
    return u32(len(raw)) + raw


def axis(name, value):
    return u32(1) + sid(name) + i64(value)


def mul(left, right):
    product = left * right
    quotient, remainder = divmod(abs(product), Q32)
    quotient += int(2*remainder > Q32 or (2*remainder == Q32 and quotient % 2))
    return -quotient if product < 0 else quotient


def json_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


UNITS = h(b"hia.value.scalar.q32.v1;instant-and-continuation-same-units;no-normalization")
COEFFICIENT = h(b"hia.value.backup.original.scalar.v1")
POLICY = h(b"hepta.ndu.evaluation-policy.v2" + sid("hia.control.original.backup.v1")
           + b"".join(u32(1)+sid(name)+b"\x03" for name in (AXIS, RISK, RESOURCE, AXIS)) + axis(AXIS, 0))


def expected_response(request, request_raw):
    request_hash = h(request_raw)
    objective = bytes.fromhex(request["objective_digest"])
    preference = bytes.fromhex(request["preference_digest"])
    state = bytes.fromhex(request["state_digest"])
    paths, candidate_bytes, values, eligible, rejected = [], {}, {}, {}, []
    for index, c in enumerate(request["candidates"]):
        name = c["id"]
        value = c["instant_q32"] + mul(c["discount_q32"], c["terminal_q32"])
        require(-LIMIT <= value <= LIMIT, "unreported utility projection")
        recursive_bytes = (b"hepta.ndu.recursive-utility.scalar.q32.v1" + objective
            + h(state + name.encode()) + COEFFICIENT + UNITS + request_hash
            + i64(c["terminal_q32"]) + i64(-LIMIT) + i64(LIMIT) + u64(1)
            + u64(1) + h(request_hash + u64(index)) + preference
            + i64(c["instant_q32"]) + i64(c["discount_q32"]) + i64(value) + i64(c["terminal_q32"]) + u32(0))
        recursive = h(recursive_bytes)
        paths.append({"id": name, "recursive_evidence_digest": recursive.hex()})
        axes = axis(AXIS, value) + axis(RISK, c["risk_q32"]) + axis(RESOURCE, c["resource_q32"]) + axis(AXIS, 0)
        contribution = h(b"hepta.ndu.contribution.v1" + sid(name) + sid(ORGAN) + objective
            + u64(request["generation"]) + bytes([0 if c["feasible"] else 1]) + axes + h(request_hash + recursive))
        candidate_bytes[name] = sid(name) + axes + h(contribution) + b"\x00"
        reasons = (["HardConstraintViolation"] if not c["feasible"] else [])
        if c["risk_q32"] > request["risk_ceiling_q32"]:
            reasons.append("RiskCeilingExceeded")
        if c["resource_q32"] > request["resource_budget_q32"]:
            reasons.append("ResourceCeilingExceeded")
        if reasons:
            rejected.append({"id": name, "reasons": reasons})
        values[name], eligible[name] = value, not reasons
    accepted = sorted(name for name, yes in eligible.items() if yes)
    require(accepted and "abstain" in accepted, "explicit feasible abstention missing")
    best = max(values[name] for name in accepted)
    winners = [name for name in accepted if values[name] == best]
    disposition = 0 if accepted == ["abstain"] else 1 if len(winners) == 1 else 2
    advisory = winners[0] if disposition in (0, 1) else None
    profile = h(b"hepta.ndu.utility-profile.v1" + sid("hia.control.value.v1")
        + h(b"utility.net/risk.tail/resource.optimization.v1") + UNITS
        + u32(1) + sid(AXIS) + b"\x00" + axis(RISK, request["risk_ceiling_q32"])
        + axis(RESOURCE, request["resource_budget_q32"]) + u32(1) + sid(ORGAN))
    rejected.sort(key=lambda row: row["id"])
    reason_tags = {"HardConstraintViolation": 0, "RiskCeilingExceeded": 1, "ResourceCeilingExceeded": 2}
    evaluation_v1 = h(b"hepta.ndu.evaluation.v1" + objective + profile + b"\x00"
        + u64(request["generation"]) + bytes([disposition]) + u32(len(accepted))
        + b"".join(candidate_bytes[name] for name in accepted) + u32(len(rejected))
        + b"".join(sid(row["id"])+u32(len(row["reasons"]))+bytes(reason_tags[x] for x in row["reasons"]) for row in rejected)
        + u32(len(winners)) + b"".join(candidate_bytes[name] for name in winners)
        + (b"\x00" if advisory is None else b"\x01"+sid(advisory)))
    return {"values_q32": values, "eligible": eligible, "winners": winners, "chosen_id": winners[0],
        "rejected": rejected, "path_receipts": paths, "projection_count": 0,
        "evaluation_digest": h(b"hepta.ndu.evaluation.v2" + evaluation_v1 + POLICY + bytes([disposition])).hex()}


def verify_session(path, artifact, costs, states, arm, inputs, scenario):
    before = identity(path)
    require(before == artifact, "native log differs from profile artifact: " + str(path))
    hello, close, exchanges, validated, total_call_ns = None, None, {}, 0, 0
    with path.open() as stream:
        for index, line in enumerate(stream):
            row = json.loads(line)
            event = row["event"]
            if event == "hello":
                require(index == 0 and hello is None, "native hello placement")
                hello = row
                require(row["binary_sha256"] == inputs["value_binary"]["sha256"] and
                    row["manifest_sha256"] == inputs["value_manifest"]["sha256"], "hello input identity")
                require(sha256(row["raw_response"].encode()).hexdigest() == row["response_sha256"], "hello frame hash")
                payload = json.loads(row["raw_response"])
                require(payload["schema"] == "hepta.hia.ndu.value.hello.v1" and payload["identity"]["upstream_commit"] == UPSTREAM
                    and payload["authority"] == "DENY_ALL" and payload["safety_certificate"] is False, "native hello contract")
            elif event == "exchange":
                require(hello is not None and close is None and validated == len(exchanges), "exchange lifecycle")
                require(row["sequence"] == len(exchanges)+1, "exchange sequence gap or duplicate")
                for name in ("request", "response"):
                    require(sha256(row[name].encode()).hexdigest() == row[name+"_sha256"], name+" exact raw frame hash")
                request, response = json.loads(row["request"]), json.loads(row["response"])
                require(request["schema"] == "hepta.hia.ndu.value.request.v1" and response["schema"] == "hepta.hia.ndu.value.response.v1", "native schema")
                require(request["sequence"] == row["sequence"] == response["sequence"], "wire sequence binding")
                require(response["request_sha256"] == row["request_sha256"], "response request identity")
                require(all(response[k] == request[k] for k in ("generation", "state_digest", "preference_digest", "objective_digest")), "response context binding")
                require(response["authority"] == "DENY_ALL" and response["safety_certificate"] is False
                    and response["execution_authorized"] is False and response["upstream_commit"] == UPSTREAM, "native effect/provenance boundary")
                require(response["entry_points"] == ["codex_hepta_ndu::evaluate_recursive_utility", "codex_hepta_ndu::evaluate_candidates_with_policy"], "native entry points")
                expected = expected_response(request, row["request"].encode())
                for key, value in expected.items():
                    require(response[key] == value, f"independent {key} at {path.name}:{row['sequence']}")
                exchanges[row["sequence"]] = (request, response)
            elif event == "validated":
                require(close is None and row["sequence"] == validated+1 == len(exchanges), "validated pairing")
                response = exchanges[row["sequence"]][1]
                require(row["values_q32"] == response["values_q32"] and row["winners"] == response["winners"], "validation response consumption")
                validated += 1
                total_call_ns += row["outer_call_ns"]
            elif event == "close":
                require(close is None and validated == len(exchanges), "close placement")
                close = row
                require(row["calls"] == len(exchanges) and row["returncode"] == 0 and not row["killed"] and row["reaped"]
                    and row["stderr"] == "" and not row["stderr_over_bound"], "unclean native process")
                require(row["total_call_ns"] == total_call_ns, "native call-time ledger")
            else:
                raise AssertionError("unexpected/failed native event: " + event)
    require(hello is not None and close is not None and exchanges, "incomplete native session")
    receipt = costs["native_close"]
    require(receipt == {"started": True, "calls": len(exchanges), "startup_ns": hello["startup_ns"],
        "close_ns": close["close_ns"], "returncode": 0, "call_wall_ns": total_call_ns}, "native cleanup/summary ledger")
    next_call, roots_checked = 1, 0
    objective = json_digest({"rule": "state-price-plus-discounted-mean-downside-v1", "scenario": scenario})
    for state in states:
        cell = state["arms"][arm]
        first, last = cell["native_call_range"]
        require(cell["status"] == "completed" and cell["native_backend_used"] and first == next_call <= last,
            "native per-state range gap, overlap or empty range")
        require(last-first+1 == cell["search"]["backend_calls"], "state backend call accounting")
        request, response = exchanges[last]
        require(request["state_digest"] == json_digest(state["observation"])
            and request["preference_digest"] == json_digest(cell["preference"])
            and request["objective_digest"] == objective, "last postorder call is not the recorded root decision")
        require(response["chosen_id"] == cell["selected_action"] and response["values_q32"] == cell["candidate_values_q32"], "root native value/action consumption")
        next_call, roots_checked = last+1, roots_checked+1
    require(next_call == len(exchanges)+1, "unattributed native calls")
    require(identity(path) == before, "native log changed during audit")
    return {"path": str(path), "sha256": before["sha256"], "calls": len(exchanges), "state_decisions": roots_checked,
        "recursive_receipts": sum(len(request["candidates"]) for request, _ in exchanges.values()), "evaluation_digests": len(exchanges),
        "raw_frames": 2*len(exchanges)+1, "clean_close": True, "status": "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic_ns()
    script = identity(__file__)
    result_identity = identity(args.campaign/"RESULT.json")
    result, frozen = load(args.campaign/"RESULT.json"), load(args.campaign/"REGISTRATION.json.gz")
    require(result["status"] == "passed" and result["source"] == frozen["source"], "campaign is not terminal/passed/source-bound")
    require(len(result["profiles"]) == 54 and result["retained_states"] == 10224 and result["planned_cells"] == 122688, "final denominator")
    for name, expected in frozen["source"]["files"].items():
        require(identity(args.repository/name)["sha256"] == expected, "frozen research source changed: "+name)
    for item in frozen["inputs"].values():
        require(identity(item["path"]) == item, "admitted native input changed")
    manifest = load(frozen["inputs"]["value_manifest"]["path"])
    require(manifest == frozen["build_receipt"] and manifest["upstream"]["commit"] == UPSTREAM, "build receipt/upstream binding")
    for name, expected in manifest["adapter_files"].items():
        require(identity(args.repository/"rust/hia-ndu-value"/name)["sha256"] == expected, "adapter source binding: "+name)
    for name, expected in manifest["build_inputs"].items():
        require(identity(args.build_root/name)["sha256"] == expected, "retained original build input: "+name)
    original_count = 0
    for name, expected in manifest["original_source_files"].items():
        if name.endswith("Cargo.toml"):
            continue
        require(identity(args.build_root/name.removeprefix("codex-rs/"))["sha256"] == expected, "original non-manifest source: "+name)
        original_count += 1
    sessions = []
    for profile in result["profiles"]:
        directory = args.campaign/profile["id"]
        require(load(directory/"SUMMARY.json") == profile, "profile summary/root result mismatch")
        states = load(directory/"STATE_RESULTS.json.gz")
        artifacts = {Path(item["path"]).name: item for item in profile["artifacts"]}
        require(identity(directory/"STATE_RESULTS.json.gz") == artifacts["STATE_RESULTS.json.gz"], "state result identity")
        for arm in ARMS:
            sessions.append({"profile": profile["id"], "arm": arm, **verify_session(directory/(arm+".jsonl"),
                artifacts[arm+".jsonl"], profile["costs"][arm], states, arm, frozen["inputs"], profile["scenario"])})
        print(json.dumps({"verified_profiles": len(sessions)//2, "calls": sum(s["calls"] for s in sessions)}), flush=True)
    require(identity(args.campaign/"RESULT.json") == result_identity and identity(__file__) == script, "audit input/script drift")
    counts = Counter()
    for session in sessions:
        for key in ("calls", "state_decisions", "recursive_receipts", "evaluation_digests", "raw_frames"):
            counts[key] += session[key]
    require(counts["calls"] == 84960 and counts["state_decisions"] == 20448, "full native audit denominator")
    report = {"schema": "hepta.ndu.independent-native-frame-audit.v1", "status": "passed", "script": script,
        "source_commit": frozen["source"]["commit"], "upstream_commit": UPSTREAM, "campaign_result": result_identity,
        "native_inputs": frozen["inputs"], "sessions": sessions, "counts": dict(counts),
        "source_files_matched": len(frozen["source"]["files"]), "build_inputs_matched": len(manifest["build_inputs"]),
        "original_non_manifest_files_matched": original_count, "source_and_input_bytes_unchanged": True,
        "audit_wall_ns": time.monotonic_ns()-started, "frozen_campaign_modified": False,
        "independence": "Separate stdlib integer/byte serializers from pinned original Rust; no tested helper or binary executed.",
        "scope": "All stored original-native frames, recursive/evaluation digests, root consumption, call ranges and clean exits; local record integrity, not hardware attestation or physical workload/economic benefit."}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "counts": dict(counts), "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
