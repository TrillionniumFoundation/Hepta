"""Fresh installed v5 baseline and original journal/SQL/replay scenarios.

The caller installs a real wheel and provides an explicit administrator digest.
This process imports the installed product before source-owned test providers.
Every actual worker uses the same installed capsule as its real setup.
"""
from __future__ import annotations
import argparse
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys
import unittest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "installed", "bundle", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--lane", choices=("current-v1", "current-v5"), default="current-v5")
    args = parser.parse_args()
    root, installed = args.root.resolve(strict=True), args.installed.resolve(strict=True)
    output = args.evidence.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Normal lookup from this fresh interpreter first chooses the wheel.
    sys.path[:0] = [str(installed), str(root)]
    from hepta import hia_agent_service as api, hia_agent_store as store
    from hepta.hia_native_helpers import native_helpers_scope
    from hepta.hia_agent_contract import installation_manifest
    from tests.hia_slot_worker_terminal import SourceAuthority, worker_profile, assert_terminal
    authority = SourceAuthority(root)
    profile = worker_profile((installed / "hepta/hia_agent_worker.py").read_bytes())
    assert profile == authority.profile
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.hia_agent_native_qualification import exhaustive_u8_workload
    from tests.hia_slot_operations_qualification_support import (
        canonical, clean_environment, regular_bytes, pin, run_owned,
        successful_exit, write_json)
    assert Path(api.__file__).resolve().is_relative_to(installed)
    assert Path(store.__file__).resolve().is_relative_to(installed)
    bundle_raw = regular_bytes(args.bundle)
    assert sha256(bundle_raw).hexdigest() == args.expected_bundle_sha256
    capsule = json.loads(bundle_raw)
    mechanical_lane = args.lane == "current-v5"
    assert capsule["schema"] == ("hepta.hia.native-helpers.v5" if mechanical_lane
                                 else "hepta.hia.native-helpers.v1")
    bridge = capsule["bridges"][0] if mechanical_lane else None
    environment = clean_environment()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    test = unittest.TestCase()
    command_records = []

    def run_worker(label, mode="normal", case=None, request=None, code=0, identity=None,
                   require_loaded=True):
        command = [sys.executable, "-I", "-B", str(root / "tests/hia_slot_mechanical_worker_probe.py"),
            "--installed", str(installed), "--mode", mode,
            "--native-helpers-manifest", str(args.bundle),
            "--expected-native-helpers-sha256", args.expected_bundle_sha256]
        if case is None:
            command.append("--installation-manifest")
            body = None
        else:
            command += ["--state-root", str(case.state_root), "--artifact-root", str(case.files_root),
                        "--request-json-stdin"]
            for field in ("worker", "backend", "catalog"):
                command += ["--expected-" + field + "-sha256", identity[field + "_sha256"]]
            body = canonical(request)
        result = run_owned(command, cwd=root, directory=output / label, timeout_seconds=60,
                           environment=environment, stdin=body)
        command_records.append({"label": label, "result": result})
        test.assertEqual(result["exit_code"], code, result)
        test.assertFalse(result["timed_out"])
        test.assertIsNone(result["interruption"])
        test.assertTrue(result["owned_cleanup"]["reaped"])
        test.assertEqual(result["owned_cleanup"]["after"], [])
        test.assertEqual(result["owned_cleanup"]["signals"], [])
        raw = regular_bytes(output / label / "stdout.log")
        stderr = regular_bytes(output / label / "stderr.log")
        def tagged(prefix):
            rows = [json.loads(line[len(prefix):]) for line in stderr.splitlines()
                    if line.startswith(prefix)]
            test.assertEqual(len(rows), 1, stderr)
            return rows[0]
        counts = tagged(b"SLOT_OPERATIONS_INSTALLED=")
        mechanical = tagged(b"SLOT_MECHANICAL_WORKER=")
        test.assertEqual(counts["retained_calls"], [])
        assert_terminal(test, counts["terminal"], stderr, label, profile)
        require_loaded = require_loaded and mechanical_lane
        test.assertIs(mechanical["loaded"], require_loaded)
        if require_loaded:
            test.assertEqual(mechanical["abi"], bridge["abi"])
            test.assertEqual(mechanical["actual_binary"], {k: bridge["binary"][k] for k in ("bytes", "sha256")})
            test.assertEqual(mechanical["receipt"], {k: bridge["build_receipt"][k] for k in ("bytes", "sha256")})
            test.assertEqual(mechanical["seals"], mechanical["required_seals"])
            test.assertEqual(mechanical["seals"], 15)
            test.assertEqual(mechanical["modes"], 15)
            test.assertEqual(mechanical["ports"], 136)
            test.assertTrue(mechanical["actual_live_exports_unchanged"])
        test.assertEqual(mechanical["pid"], result["pid"])
        test.assertEqual(mechanical["pgid"], result["pid"])
        test.assertEqual(mechanical["ppid"], os.getpid())
        test.assertEqual(mechanical["argv"], command[3:])
        return raw, counts, mechanical

    def prepare():
        case = AgentToolCase("runTest")
        saved = dict(os.environ)
        setup_completed = False
        try:
            os.environ.clear()
            os.environ.update(environment)
            with native_helpers_scope(str(args.bundle), args.expected_bundle_sha256):
                case.setUp()
                setup_completed = True
                case.session.freeze(exhaustive_u8_workload())
                arguments = case.session.arguments(target_slot="installed-slot-missing",
                    expected_current={"generation": "0", "epoch": "0"},
                    retained_generation="0", reason="qualification missing slot remains rejected")
                request = {"schema": "hia-agent-worker-request-v1", "tool": "hia_rollback",
                    "arguments": arguments, "profile_sha256": "a" * 64,
                    "catalog_sha256": case.service.catalog_sha256}
                request["request_sha256"] = api.digest(request)
                case.service.close()
            return case, request
        except BaseException:
            if setup_completed:
                case.tearDown()
            raise
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def state(case, request):
        key = api.digest({"tool": request["tool"], "key": request["arguments"]["request_key"]})
        with closing(sqlite3.connect(case.state_root / "state.sqlite3")) as db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM requests WHERE key=?", (key,)).fetchone()
            return {"request": None if row is None else dict(row),
                "slots": [tuple(row) for row in db.execute("SELECT * FROM slots ORDER BY name")],
                "versions": [tuple(row) for row in db.execute("SELECT * FROM versions ORDER BY slot,generation")],
                "leases": [tuple(row) for row in db.execute("SELECT * FROM leases ORDER BY id")],
                "costs": db.execute("SELECT COUNT(*) FROM costs").fetchone()[0]}

    identities_raw, identity_counts, identity_mechanical = run_worker("installation-manifest")
    identities = json.loads(identities_raw)
    test.assertEqual(set(identities), {"worker_sha256", "backend_sha256", "catalog_sha256",
                                    "native_helpers_sha256"})
    test.assertEqual(identities["native_helpers_sha256"], args.expected_bundle_sha256)
    test.assertEqual(sum(identity_counts["startup"].values()), 0)
    test.assertEqual(sum(identity_counts["request"].values()), 0)
    test.assertEqual(identity_counts["unknown_records"], 0)
    with native_helpers_scope(str(args.bundle), args.expected_bundle_sha256):
        test.assertEqual(identities, installation_manifest())
    observations = {}
    case, request = prepare()
    try:
        before = state(case, request)
        raw, counts, code = run_worker("normal", case=case, request=request, identity=identities)
        report, after = json.loads(raw), state(case, request)
        test.assertEqual(report["native_helpers_sha256"], args.expected_bundle_sha256)
        test.assertEqual(report["response"]["status"], "rejected")
        test.assertGreater(sum(counts["request"].values()), 0)
        test.assertGreater(counts["request_modes"].get("4", 0), 0)
        test.assertGreater(counts["request_modes"].get("2", 0), 0)
        test.assertGreater(counts["decision_request"], 0)
        test.assertEqual(counts["unknown_records"], 0)
        test.assertEqual(after["request"]["state"], "completed")
        for name in ("slots", "versions", "leases"):
            test.assertEqual(after[name], before[name])
        replay, replay_counts, replay_code = run_worker("replay", case=case, request=request, identity=identities)
        test.assertEqual(json.loads(replay)["response"], report["response"])
        test.assertEqual(sum(replay_counts["request"].values()), 0)
        test.assertEqual(state(case, request), after)
        observations["normal"] = {"response": report, "counts": counts, "mechanical": code,
                                  "before": before, "after": after}
        observations["replay"] = {"response": json.loads(replay), "counts": replay_counts,
                                  "mechanical": replay_code}
    finally:
        case.tearDown()
    case, request = prepare()
    try:
        before = state(case, request)
        raw, counts, code = run_worker("lost-SQL-ACK", mode="lost-execute-ack",
            case=case, request=request, code=profile["lost_ack_exit"], identity=identities)
        after = state(case, request)
        test.assertEqual(raw, b"")
        test.assertTrue(counts["lost_ack_injected"])
        test.assertGreater(counts["unknown_records"], 0)
        test.assertGreater(counts["unknown_resource_observations"], 0)
        test.assertEqual(counts["close_calls"], 0)
        test.assertEqual(after["request"]["state"], "running")
        test.assertIsNone(after["request"]["response"])
        test.assertEqual(after["costs"], before["costs"])
        for name in ("slots", "versions", "leases"):
            test.assertEqual(after[name], before[name])
        replay, replay_counts, replay_code = run_worker("unknown-replay", case=case,
                                                       request=request, identity=identities)
        response, replay_after = json.loads(replay), state(case, request)
        test.assertEqual(response["response"]["status"], "rejected")
        test.assertEqual(response["response"]["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
        test.assertEqual(sum(replay_counts["request"].values()), 0)
        test.assertEqual(replay_after["request"], after["request"])
        test.assertEqual(replay_after["costs"], after["costs"] + 1)
        observations["lost_SQL_ACK"] = {"counts": counts, "mechanical": code,
                                       "before": before, "after": after}
        observations["unknown_replay"] = {"response": response, "counts": replay_counts,
                                          "mechanical": replay_code, "after": replay_after}
        # All original pairs finish before mutations. Both use the original
        # worker's actual expected-source flags and leave SQLite/CAS untouched.
        source_path = installed / "hepta/hia_slot_continuations.py"
        source_before = regular_bytes(source_path)
        extra_path = installed / "hepta/_mechanical_v5_extra_module.py"
        test.assertFalse(extra_path.exists())
        drift_rows = []
        for label, require_loaded in (("source-plus-LF", False), ("extra-module", True)):
            prior = state(case, request)
            if label == "source-plus-LF":
                source_path.write_bytes(source_before + b"\n")
                mutated = source_path
            else:
                extra_path.write_bytes(b"# installed inventory drift control\n")
                mutated = extra_path
            mutation = {"path": str(mutated), **pin(mutated)}
            try:
                raw, counts, mechanical = run_worker(label, case=case, request=request,
                    code=2, identity=identities, require_loaded=require_loaded)
                test.assertEqual(raw, b"")
                test.assertEqual(sum(counts["startup"].values()), 0)
                test.assertEqual(sum(counts["request"].values()), 0)
                test.assertFalse(counts["lost_ack_injected"])
                test.assertEqual(counts["unknown_records"], 0)
                test.assertEqual(state(case, request), prior)
                drift_rows.append({"label": label, "mutation": mutation, "counts": counts,
                                   "mechanical": mechanical, "state_unchanged": True})
            finally:
                if label == "source-plus-LF":
                    source_path.write_bytes(source_before)
                else:
                    extra_path.unlink()
            test.assertEqual(regular_bytes(source_path), source_before)
            test.assertFalse(extra_path.exists())
        observations["source_drift"] = {"source_before": {"path": str(source_path),
            "bytes": len(source_before), "sha256": sha256(source_before).hexdigest()},
            "rows": drift_rows, "source_restored": True, "extra_module_removed": True}
    finally:
        case.tearDown()
    test.assertEqual(regular_bytes(args.bundle), bundle_raw)
    authority.finish()
    write_json(output / "report.json", {
        "schema": "hepta.slot.mechanical.installed-worker.v2", "status": "PASS",
        "lane": args.lane, "source_authority": authority.summary(),
        "capsule": {"path": str(args.bundle), **pin(args.bundle)},
        "installed": str(installed), "identities": identities,
        "identity_child": {"counts": identity_counts, "mechanical": identity_mechanical},
        "commands": command_records, "observations": observations,
        "actual_installed_same_capsule_setup": True,
        "actual_original_worker": True, "all_fifteen_methods_in_worker_observed": False,
        "original_Native6_replaced": False, "whole_native_stack_qualified": False})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
