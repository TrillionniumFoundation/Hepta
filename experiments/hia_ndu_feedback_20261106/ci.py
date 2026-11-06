"""Strict, bounded CI for the non-production feedback research profile.

All generated files live outside the checkout. Private upstream inputs and
compiler streams stay in scratch; only explicit receipts and research protocol
outputs enter the public evidence directory. No credentials are requested.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"
AUTHORITY = {"authority": "DENY_ALL", "production_activation": False}


class GateError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise GateError(reason)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def fingerprint(path):
    data = Path(path).read_bytes()
    return {"bytes": len(data), "sha256": sha256(data).hexdigest()}


def source_snapshot(output, *, expected_head, before=None, root=ROOT):
    """Require the exact requested commit as well as stable, clean source bytes."""
    require(type(expected_head) is str and len(expected_head) == 40
            and expected_head != "0" * 40 and set(expected_head) <= set("0123456789abcdef"),
            "expected source head must be a nonzero full lowercase Git SHA")
    root = Path(root).resolve()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root, text=True)
    entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, _, stage = metadata.decode().split()
        relative = name.decode("utf-8")
        require(stage == "0" and mode in {"100644", "100755", "120000"}, "unmerged or unsupported source member")
        path = root / relative
        if mode == "120000":
            data = os.readlink(path).encode()
        else:
            require(path.is_file() and not path.is_symlink(), "missing or replaced tracked source: " + relative)
            data = path.read_bytes()
        files[relative] = {"mode": mode, "bytes": len(data), "sha256": sha256(data).hexdigest()}
    snapshot = {"schema": "hepta.hia.ndu.feedback-source-snapshot.v1", "head": head,
                "expected_head": expected_head, "matches_expected_head": head == expected_head,
                "clean": not status, "status_porcelain": status, "files": files, **AUTHORITY}
    if before is not None:
        expected = json.loads(Path(before).read_text())
        snapshot["matches_before"] = (expected.get("clean") is True and not status
                                      and expected.get("expected_head") == expected_head
                                      and expected.get("matches_expected_head") is True
                                      and head == expected.get("head") and files == expected.get("files"))
    write_json(output, snapshot)
    require(snapshot["matches_expected_head"], "checked-out HEAD is not the exact requested source head")
    require(not status, "research CI requires a clean worktree; no reset or source rewrite is performed")
    require(before is None or snapshot["matches_before"], "tracked source changed during research CI")
    return snapshot


def guard_controls(evidence):
    """Reject a real same-tree synthetic merge and changes to the expected head.

Only a temporary fixture Git repository is mutated. The published source and
the original experiment's source/measurement receipts are never rewritten.
"""
    output = Path(evidence) / "source-guard-controls"
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": "hepta.hia.ndu.feedback-source-guard-controls.v1", "passed": False, **AUTHORITY}
    started = time.monotonic_ns()
    try:
        with tempfile.TemporaryDirectory(prefix="hia-feedback-source-guard-") as temporary:
            fixture = Path(temporary) / "repo"
            fixture.mkdir()
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_AUTHOR_NAME="NDU guard fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                       GIT_COMMITTER_NAME="NDU guard fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                       GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00",
                       PYTHONDONTWRITEBYTECODE="1")

            def git(*args):
                return subprocess.check_output(["git", "-C", str(fixture), *args], env=env,
                                               stderr=subprocess.PIPE, text=True).strip()

            git("init", "--quiet")
            (fixture / "fixture.txt").write_text("identical bytes at the head and merge\n")
            git("add", "fixture.txt")
            tree = git("write-tree")
            base = git("commit-tree", tree, "-m", "fixture base")
            head = git("commit-tree", tree, "-p", base, "-m", "requested PR head")
            other = git("commit-tree", tree, "-p", base, "-m", "base branch tip")
            merge = git("commit-tree", tree, "-p", other, "-p", head, "-m", "synthetic PR merge")
            git("checkout", "--quiet", "--detach", head)
            before = output / "exact-before.json"
            source_snapshot(before, expected_head=head, root=fixture)
            source_snapshot(output / "exact-after.json", expected_head=head, before=before, root=fixture)

            def rejected(name, *, expected, previous=None):
                try:
                    source_snapshot(output / (name + ".json"), expected_head=expected, before=previous, root=fixture)
                except GateError as error:
                    return {"rejected": True, "reason": str(error)}
                raise GateError("source guard accepted negative control: " + name)

            controls = {"wrong_exact_head": rejected("wrong-exact-head", expected=other)}
            git("checkout", "--quiet", "--detach", merge)
            require(git("rev-parse", "HEAD^{tree}") == tree and merge != head, "invalid same-tree merge fixture")
            controls["same_tree_merge"] = rejected("same-tree-merge", expected=head)
            controls["merge_after_exact_head"] = rejected("merge-after-exact-head", expected=head, previous=before)
            controls["changed_expected_head"] = rejected("changed-expected-head", expected=merge, previous=before)

            omitted_output = Path(temporary) / "omitted-expected-head.json"
            command = [sys.executable, "-B", "-m", "experiments.hia_ndu_feedback_20261106.ci", "snapshot",
                       "--root", str(fixture), "--output", str(omitted_output)]
            omitted = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
            require(omitted.returncode == 2 and "--expected-head" in omitted.stderr and not omitted_output.exists(),
                    "snapshot CLI accepted an omitted expected head")
            write_json(output / "required-head-cli.json", {"argv": command, "returncode": omitted.returncode,
                       "stdout": omitted.stdout, "stderr": omitted.stderr, "snapshot_written": omitted_output.exists()})
            receipt.update(passed=True, controls=controls, required_head_cli_rejected=True,
                           fixture={"base": base, "requested_head": head, "other_head": other,
                                    "synthetic_merge": merge, "shared_tree": tree,
                                    "merge_parents": git("rev-list", "--parents", "-n", "1", merge).split()[1:]})
    finally:
        receipt["wall_ns"] = time.monotonic_ns() - started
        write_json(output / "receipt.json", receipt)
    return receipt


def test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


def run_tests(names, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    identities = list(test_ids(suite))
    require(identities and len(identities) == len(set(identities)), "empty or duplicated test inventory")
    started = time.monotonic_ns()
    with (output / "unittest.log").open("x", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    complete = (result.wasSuccessful() and not result.skipped and not result.expectedFailures
                and result.testsRun == len(identities))
    receipt = {"schema": "hepta.hia.ndu.feedback-test-gate.v1", "requested": names,
               "test_ids": identities, "tests_run": result.testsRun, "failures": len(result.failures),
               "errors": len(result.errors), "skipped": len(result.skipped),
               "expected_failures": len(result.expectedFailures),
               "unexpected_successes": len(result.unexpectedSuccesses),
               "wall_ns": time.monotonic_ns() - started, "all_passed_zero_skips": complete,
               "log": fingerprint(output / "unittest.log"), **AUTHORITY}
    write_json(output / "receipt.json", receipt)
    require(complete, "unittest gate failed or skipped a required test; inspect " + str(output / "unittest.log"))
    return receipt


def reference(evidence):
    return run_tests(["tests.test_hia_ndu_feedback", "tests.test_hia_ndu_feedback_workload",
                      "tests.test_hia_ndu_feedback_campaign", "tests.test_hia_ndu_feedback_coverage",
                      "tests.test_hia_ndu_economical", "tests.test_hia_ndu_compute_price",
                      "tests.test_hia_ndu_compute_debit",
                      "tests.test_hia_ndu_policy_audit", "tests.test_hia_ndu_policy_campaign",
                      "tests.test_hia_ndu_feedback_ci_paths",
                      "tests.test_core_seven_shared_source_closure", "tests.test_hia_ndu_dynamic",
                      "tests.test_hia_ndu_preparation_bound",
                      "experiments.hia_ndu_feedback_20261106.test_native.ExactArithmeticTests"],
                     Path(evidence) / "reference-tests")


def cpu_children():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return round((usage.ru_utime + usage.ru_stime) * 1_000_000_000)


def prepare(scratch, evidence, *, upstream=None, cargo=None):
    """Retain complete acquisition/build costs, including failed commands.

The default CI path fetches anonymously. Explicit local inputs support replay;
their earlier acquisition cost is unknown, never silently set to zero.
"""
    supplied_upstream, supplied_cargo = upstream is not None, cargo is not None
    scratch, evidence = Path(scratch).resolve(), Path(evidence).resolve()
    require(not scratch.exists(), "preparation scratch must be new")
    scratch.mkdir(parents=True)
    (scratch / "commands").mkdir()
    evidence.mkdir(parents=True, exist_ok=True)
    started, parent_cpu, child_cpu = time.monotonic_ns(), time.process_time_ns(), cpu_children()
    commands, builds = [], {}
    stage, error = "toolchain", None
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", CARGO_INCREMENTAL="0",
               CARGO_PROFILE_RELEASE_DEBUG="0", PYTHONDONTWRITEBYTECODE="1")

    def command(label, argv, *, command_env=None):
        began = time.monotonic_ns()
        record = {"label": label, "argv": [str(x) for x in argv], "cwd": str(ROOT), "returncode": None}
        out, err = scratch / "commands" / (label + ".stdout"), scratch / "commands" / (label + ".stderr")
        try:
            with out.open("xb") as stdout, err.open("xb") as stderr:
                record["returncode"] = subprocess.run(record["argv"], cwd=ROOT, env=command_env or env,
                    stdout=stdout, stderr=stderr, check=False, timeout=1200).returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            record["launch_or_timeout_error"] = type(exc).__name__
        finally:
            record["wall_ns"] = time.monotonic_ns() - began
            record["stdout"] = fingerprint(out)
            record["stderr"] = fingerprint(err)
            record["raw_streams"] = "retained in private runner scratch; compiler diagnostics may contain upstream source"
            commands.append(record)
        require(record["returncode"] == 0, "preparation command failed: " + label)
        return out.read_text().strip()

    try:
        if cargo is None:
            command("rustup-install", ["rustup", "toolchain", "install", "1.95.0", "--profile", "minimal"])
            cargo = Path(command("cargo-location", ["rustup", "which", "--toolchain", "1.95.0", "cargo"]))
        else:
            cargo = Path(cargo).resolve(strict=True)
        rustc = cargo.parent / "rustc"
        env.update(RUSTC=str(rustc), PATH=str(cargo.parent) + os.pathsep + env.get("PATH", ""))
        require(command("cargo-version", [str(cargo), "--version"]).startswith("cargo 1.95.0 "), "requires Cargo 1.95.0")
        require(command("rustc-version", [str(rustc), "--version"]).startswith("rustc 1.95.0 "), "requires Rust 1.95.0")
        stage = "upstream-fetch"
        pin = json.loads((ROOT / "rust/hia-ndu-value/upstream.json").read_text())
        require(pin["commit"] == UPSTREAM, "unexpected upstream pin")
        if upstream is None:
            upstream = scratch / "upstream"
            command("git-init", ["git", "init", "--quiet", str(upstream)])
            command("git-remote", ["git", "-C", str(upstream), "remote", "add", "origin", pin["repository"]])
            command("git-promisor", ["git", "-C", str(upstream), "config", "remote.origin.promisor", "true"])
            command("git-filter", ["git", "-C", str(upstream), "config", "remote.origin.partialclonefilter", "blob:none"])
            command("git-fetch", ["git", "-C", str(upstream), "-c", "credential.helper=", "-c", "protocol.version=2",
                                  "fetch", "--filter=blob:none", "--depth=1", "origin", UPSTREAM])
            require(command("fetch-head", ["git", "-C", str(upstream), "rev-parse", "FETCH_HEAD"]) == UPSTREAM,
                    "fetch did not resolve the requested commit")
        upstream = Path(upstream).resolve(strict=True)
        require(command("source-commit", ["git", "-C", str(upstream), "rev-parse", UPSTREAM + "^{commit}"]) == UPSTREAM,
                "source commit mismatch")
        for profile, builder in (("value", "build_hia_ndu_value_bridge.py"),
                                 ("workload", "build_hia_ndu_dynamic_bridge.py")):
            stage = profile + "-build"
            build = scratch / (profile + "-build")
            build_env = dict(env, CARGO_TARGET_DIR=str(scratch / (profile + "-target")))
            try:
                command(stage, [sys.executable, "-B", str(ROOT / "tools" / builder), "--upstream", str(upstream),
                               "--output", str(build), "--cargo", str(cargo)], command_env=build_env)
            finally:
                # Explicit metadata-only allowlist. Never copy source fixtures,
                # source archives, targets, binaries or raw compiler streams.
                for relative in ("build-receipt.json", "build-failure.json", "command-evidence/cargo.json"):
                    source = build / relative
                    if source.is_file() and not source.is_symlink():
                        receipt = json.loads(source.read_text())
                        write_json(evidence / "build-receipts" / profile / relative, receipt)
            manifest = build / "build-receipt.json"
            report = json.loads(manifest.read_text())
            require(report["upstream"]["commit"] == UPSTREAM and report["original_rust_sources_unchanged"]
                    and report["all_original_non_manifest_inputs_unchanged"] and report["build_inputs_unchanged"],
                    "pinned original build source changed")
            builds[profile] = {"binary": report["binary"], "manifest": str(manifest),
                               "binary_sha256": report["binary_sha256"]}
        write_json(scratch / "native-config.json", builds)
        stage = "complete"
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        write_json(evidence / "preparation.json", {
            "schema": "hepta.hia.ndu.feedback-preparation.v1", "stage": stage, "completed": stage == "complete",
            "upstream_access_gate": "OPEN" if stage == "upstream-fetch" else "not_failed_at_fetch",
            "error": error, "commands": commands, "builds": builds,
            "wall_ns": time.monotonic_ns() - started, "parent_cpu_ns": time.process_time_ns() - parent_cpu,
            "child_cpu_ns": cpu_children() - child_cpu,
            "scope": "prepare entry through toolchain, source acquisition/verification and both isolated builds; excludes final receipt write and runner/Python setup",
            "source_acquisition": "supplied local Git objects" if supplied_upstream else "anonymous exact-commit Git fetch",
            "toolchain_acquisition": "supplied local executable" if supplied_cargo else "rustup install 1.95.0",
            "supplied_checkout_prior_cost": "unknown when --upstream is provided; not treated as zero",
            "fully_cold_machine_claim": False, "credentials_added": False, **AUTHORITY})
    return builds


def native(evidence, config):
    from .model import (Observation, SCENARIOS, independent_oracle, plan, run_episode,
                        wiring_probes, degeneration_probe)
    from .native import NativeValueBackend
    from .workload import NativeCache

    evidence = Path(evidence)
    config = json.loads(Path(config).read_text())
    for profile in ("value", "workload"):
        require(fingerprint(config[profile]["binary"])["sha256"] == config[profile]["binary_sha256"],
                "prepared binary changed: " + profile)
    controls = evidence / "native-controls"
    controls.mkdir(parents=True, exist_ok=False)
    os.environ.update(HIA_NDU_VALUE_BINARY=config["value"]["binary"],
                      HIA_NDU_VALUE_MANIFEST=config["value"]["manifest"], HIA_NDU_VALUE_EVIDENCE=str(controls))
    tests = run_tests(["experiments.hia_ndu_feedback_20261106.test_native"], evidence / "native-tests")
    started = time.monotonic_ns()
    value = config["value"]
    backend = NativeValueBackend(value["binary"], value["manifest"], log=evidence / "engine-native.jsonl")
    receipt = {"schema": "hepta.hia.ndu.feedback-native-smoke.v1", "passed": False, **AUTHORITY}
    try:
        with backend:
            wiring = wiring_probes(backend)
            write_json(evidence / "native-wiring.json", wiring)
            require(wiring["all_passed"] and wiring["native_backend_supplied"], "native wiring reversal failed")
            degeneration = degeneration_probe(backend)
            write_json(evidence / "native-degeneration.json", degeneration)
            require(degeneration["all_passed"], "native linear degeneration control failed")
            episodes = []
            for scenario in SCENARIOS.values():
                episode = run_episode(scenario, 7, "dynamic-ndu", backend=backend)
                for row in episode["steps"]:
                    decision = row["decision"]
                    observation = Observation(**decision["observation"])
                    ordinary = plan(scenario, observation, "same-objective")
                    oracle = independent_oracle(scenario, observation)
                    require(decision["action"] == ordinary["action"] == oracle["action"], "native/oracle action mismatch")
                    require(decision["candidate_values_q32"] == ordinary["candidate_values_q32"]
                            and all(decision["candidate_values_q32"][k] == v for k, v in oracle["candidate_values_q32"].items()),
                            "native/oracle candidate value mismatch")
                    require(decision["search"]["backups"] == decision["search"]["backend_calls"] > 0,
                            "a search backup bypassed the native evaluator")
                episodes.append(episode)
            write_json(evidence / "native-model-episodes.json", {"episodes": episodes, **AUTHORITY})

            # This is an execution smoke, not a calibrated performance study.
            # Forecasts are declared before execution; feedback is measured only
            # after the chosen cache/load/retire/dispatch commands complete.
            scenario = replace(SCENARIOS["adaptive"], name="ci-native-workload", horizon=2,
                               direct_cost=2_000_000, hot_cost=1_000_000, load_cost=1_000_000,
                               initial_budget=10_000_000_000, initial_deadline=10_000_000_000,
                               cost_unit=1_000_000, cost_unit_label="measured host nanoseconds")
            workload = config["workload"]
            worker = NativeCache(workload["binary"], workload["manifest"], evidence / "workload-native.jsonl", n=16, seed=123)
            try:
                def execute(observation, action):
                    require(observation.resident == worker.resident, "controller/worker cache state mismatch")
                    row = worker.execute(action, observation.request, repeats=2, vector_seed=101 + observation.step,
                                         expected_state_digest=worker.state_digest)
                    require(row["status"] == "success" and row["output_elements_checked"] == 16,
                            "native output check failed")
                    return row["workload_wall_ns"]
                actual = run_episode(scenario, 3, "dynamic-ndu", backend=backend, executor=execute)
                require(actual["delivered"] == scenario.horizon and len(worker.rows) == scenario.horizon,
                        "native workload smoke did not deliver the declared requests")
                require(actual["actual_cost"] == sum(row["workload_wall_ns"] for row in worker.rows),
                        "actual feedback cost differs from observed workload wall")
            finally:
                close = worker.close()
                write_json(evidence / "native-workload-lifecycle.json", {
                    "rows": worker.rows, "close": close, "startup_ns": worker.startup_ns,
                    "scope": "uncalibrated CI execution smoke; no speed or profitability claim", **AUTHORITY})
            write_json(evidence / "native-workload-episode.json", actual)
        require(backend.returncode == 0, "native value process did not close cleanly")
        receipt.update(passed=True, native_calls=backend.calls, tests_run=tests["tests_run"], skipped=tests["skipped"])
    finally:
        receipt.update(wall_ns=time.monotonic_ns() - started, native_startup_ns=backend.startup_ns,
                       native_close_ns=backend.close_ns, native_call_instrument_ns=backend.total_call_ns,
                       native_returncode=backend.returncode)
        write_json(evidence / "native-smoke.json", receipt)
    return receipt


def publish(evidence, output):
    """Stage a closed evidence inventory. Never glob through private builds."""
    evidence, output = Path(evidence).resolve(), Path(output).resolve()
    require(not output.exists(), "artifact staging directory must be new")
    named = {"source-before.json", "source-after.json", "preparation.json", "engine-native.jsonl",
             "native-wiring.json", "native-degeneration.json", "native-model-episodes.json",
             "workload-native.jsonl", "native-workload-lifecycle.json", "native-workload-episode.json", "native-smoke.json"}
    manifests = {f"build-receipts/{profile}/{name}" for profile in ("value", "workload")
                 for name in ("build-receipt.json", "build-failure.json", "command-evidence/cargo.json")}
    suites = {f"{suite}/{name}" for suite in ("reference-tests", "native-tests") for name in ("receipt.json", "unittest.log")}
    guards = {"source-guard-controls/" + name + ".json" for name in
              ("exact-before", "exact-after", "wrong-exact-head", "same-tree-merge", "merge-after-exact-head",
               "changed-expected-head", "required-head-cli", "receipt")}
    sources = []
    for path in sorted(evidence.rglob("*")):
        require(not path.is_symlink(), "symlink in public evidence")
        if not path.is_file():
            continue
        relative = path.relative_to(evidence).as_posix()
        allow = (relative in named | manifests | suites | guards or
                 path.parent == evidence / "native-controls" and path.name.startswith("test_") and path.suffix == ".jsonl")
        require(allow, "unexpected public evidence member: " + relative)
        if path.suffix == ".json":
            json.loads(path.read_text())
        sources.append((relative, path))
    require(sources, "no public evidence to publish")
    output.mkdir(parents=True)
    inventory = {}
    for relative, source in sources:
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        inventory[relative] = fingerprint(destination)
    write_json(output / "artifact-inventory.json", {
        "schema": "hepta.hia.ndu.feedback-public-evidence.v1", "files": inventory,
        "contains_upstream_source_or_binaries": False,
        "private_build_streams": "not uploaded; hashes and exit/cost receipts retained", **AUTHORITY})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--output", type=Path, required=True)
    snap.add_argument("--expected-head", required=True)
    snap.add_argument("--before", type=Path)
    snap.add_argument("--root", type=Path, default=ROOT)
    for name in ("guard-controls", "reference", "prepare", "native", "publish"):
        command = sub.add_parser(name)
        command.add_argument("--evidence", type=Path, required=True)
        if name == "prepare":
            command.add_argument("--scratch", type=Path, required=True)
            command.add_argument("--upstream", type=Path)
            command.add_argument("--cargo", type=Path)
        elif name == "native":
            command.add_argument("--config", type=Path, required=True)
        elif name == "publish":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "snapshot":
        source_snapshot(args.output, expected_head=args.expected_head, before=args.before, root=args.root)
    elif args.command == "guard-controls":
        guard_controls(args.evidence)
    elif args.command == "reference":
        reference(args.evidence)
    elif args.command == "prepare":
        prepare(args.scratch, args.evidence, upstream=args.upstream, cargo=args.cargo)
    elif args.command == "native":
        native(args.evidence, args.config)
    else:
        publish(args.evidence, args.output)


if __name__ == "__main__":
    main()
