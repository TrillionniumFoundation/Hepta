"""Versioned depth policies use real VMs and preserve stopped resource ledgers.

The recorder wraps the real pinned transport; it never supplies a successful
execution response. Deliberately replayed producer bytes occur only in refusal
controls, outside the positive observation corpus.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta import hia_rust_crosscheck as crosscheck
from tests import test_hia_rust_execution_crosscheck as legacy
from tests.test_hia_rust_crosscheck import scalar_program, owned_program
from tests.test_hia_rust_scalar_vm import recursive_call, depth_boundary
from tests.test_hia_returned_loans import loan_program
from tests.test_hia_rust_returned_chains import recursive_chain_head
from tests.test_hia_rust_owned_memory import recursive_chain
from tests.test_hia_composite_abi import nominal_identity_program

ROOT = Path(__file__).resolve().parents[1]


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def policy(depth, *, steps=100_000, heap=1024 * 1024, fail=None):
    return {"max_call_depth": depth, "max_steps": steps,
            "max_heap_bytes": heap, "allocation_fail_at": fail}


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual bound depth qualification requires Linux/Cargo; NOT qualified")
class RustBoundDepthParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observations, cls.refusals, cls.compatibility, cls.programs = [], [], [], {}
        argv = ["cargo", "build", "--locked", "--offline", "--message-format=json",
                "--manifest-path", str(ROOT / "rust/hia-core-shadow/Cargo.toml")]
        built = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=240)
        cls.build = {"argv": argv, "cwd": str(ROOT), "returncode": built.returncode,
                     "stdout": built.stdout, "stderr": built.stderr}
        if built.returncode:
            raise AssertionError(built.stderr)
        artifacts = [row["executable"] for line in built.stdout.splitlines()
                     if (row := json.loads(line)).get("reason") == "compiler-artifact"
                     and row.get("executable") and "bin" in row["target"]["kind"]]
        if len(artifacts) != 1:
            raise AssertionError("Cargo did not identify exactly one actual Rust binary")
        cls.executable = Path(artifacts[0])
        cls.digest = sha256(cls.executable.read_bytes()).hexdigest()

    def compare(self, source, entry, arguments, *, depth, **limits):
        core = verify_program(source)
        type(self).programs[core.sha256] = core.canonical_bytes.decode()
        captured = []
        actual_transport = crosscheck._run_pinned_shadow

        def record(binary, argv, stdin, timeout, **kwargs):
            stdout, stderr, returncode = actual_transport(binary, argv, stdin, timeout, **kwargs)
            captured.append({"argv_after_pinned_executable": argv,
                "executable_sha256": sha256(binary).hexdigest(), "stdin_sha256": sha256(stdin).hexdigest(),
                "returncode": returncode, "stdout": stdout.decode(), "stderr": stderr.decode()})
            return stdout, stderr, returncode

        with patch.object(crosscheck, "_run_pinned_shadow", record):
            result = crosscheck.crosscheck_rust_execution_v2(source, entry, arguments, self.executable,
                executable_sha256=self.digest, max_call_depth=depth, **limits)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["executable_sha256"], self.digest)
        self.assertEqual(captured[0]["stdin_sha256"], core.sha256)
        self.assertEqual(result["schema"], "hepta.hia.rust-execution-crosscheck.v2")
        self.assertEqual(result["request"]["schema"], "hepta.hia.rust-execution-request.v2")
        self.assertEqual(result["request"]["policy"]["max_call_depth"], depth)
        self.assertEqual(result["rust_report"]["max_call_depth"], depth)
        self.assertIs(result["claims"]["rust_is_production_admission_authority"], False)
        self.assertIs(result["claims"]["native_backend_refinement_proved"], False)
        type(self).observations.append({"test": self.id(), "crosscheck": result,
                                       "process": captured[0], "matched": True})
        return result["rust_report"]

    def raw(self, raw_core, entry, raw_arguments, raw_policy, *, mode="--owned-run-bound-v2"):
        argv = [str(self.executable), mode, entry, raw_arguments, raw_policy]
        completed = subprocess.run(argv, input=raw_core, cwd=ROOT, capture_output=True, timeout=15)
        return {"argv": argv, "returncode": completed.returncode,
                "stdout": completed.stdout.decode(), "stderr": completed.stderr.decode()}

    def reject_raw(self, raw_core, entry, raw_arguments, raw_policy, *, reason, python_error=None):
        actual = self.raw(raw_core, entry, raw_arguments, raw_policy)
        self.assertEqual(actual["returncode"], 1, actual)
        self.assertEqual(actual["stdout"], "")
        self.assertTrue(actual["stderr"].startswith("E_HIA_"), actual)
        self.assertNotIn("panicked", actual["stderr"])
        type(self).refusals.append({"test": self.id(), "reason": reason,
            "raw_core_utf8": raw_core.decode(), "raw_core_sha256": sha256(raw_core).hexdigest(),
            "python_error": python_error, "process": actual, "rejected": True})

    def test_all_depths_have_root_inclusive_scalar_boundaries_and_exact_ticks(self):
        for depth in range(1, 33):
            with self.subTest(depth=depth):
                forever = self.compare(recursive_call(), "recur", [9], depth=depth)
                self.assertEqual(forever["error"], {"code": "calls"})
                self.assertEqual(forever["steps"], 2 * depth)
                normal = self.compare(depth_boundary(), "bounded", [depth - 1], depth=depth)
                self.assertEqual(normal["values"], [0])
                stopped = self.compare(depth_boundary(), "bounded", [depth], depth=depth)
                self.assertEqual(stopped["error"], {"code": "calls"})

    def test_recursive_returned_loans_and_chain_transfers_keep_stopped_owners(self):
        for depth in (1, 2, 3, 5, 16, 31, 32):
            for kind in ("loan", "chain_head", "owned_chain"):
                for normal in (False, True) if depth >= 2 else (False,):
                    recursion = depth - (2 if normal else 1)
                    if kind == "loan":
                        source = loan_program("mut", "recursive")
                        ops = source["functions"][-1]["blocks"][0]["ops"]
                        next(op for op in ops if op["op"] == "const" and
                             op["out"][0]["name"] == "depth")["attrs"]["value"] = recursion
                        entry, arguments = source["exports"][0], [2, 37]
                    elif kind == "chain_head":
                        source = recursive_chain_head(depth=recursion)
                        entry, arguments = source["exports"][0], [2, 37]
                    else:
                        source = recursive_chain()
                        entry, arguments = "chain_recursion", [recursion]
                    with self.subTest(depth=depth, kind=kind, normal=normal):
                        observed = self.compare(source, entry, arguments, depth=depth)
                        ledger = observed["resources"]
                        if normal:
                            self.assertEqual(observed["values"], [True] if kind == "owned_chain" else [42])
                            self.assertEqual((ledger["live_bytes"], ledger["live_owners"],
                                              ledger["live_local_loans"]), (0, 0, 0))
                        else:
                            self.assertEqual(observed["error"], {"code": "calls"})
                            self.assertEqual(ledger["live_bytes"], 2 if kind == "loan" else
                                             25 if kind == "owned_chain" else 26)
                            self.assertEqual(ledger["live_owners"], 1 if kind == "loan" else 2)
                            self.assertEqual(ledger["live_local_loans"], 0 if kind == "owned_chain" else 1)
                        if kind != "loan":
                            self.assertEqual(ledger["live_chain_nodes"], 0 if normal else 1)
                            self.assertEqual(ledger["live_chains"], 0 if normal else 1)

    def test_step_heap_allocation_and_depth_stops_preserve_real_prefixes(self):
        source = recursive_chain_head(depth=1)
        entry = source["exports"][0]
        complete = self.compare(source, entry, [2, 37], depth=3)
        partial_destructor = False
        for steps in range(1, complete["steps"]):
            report = self.compare(source, entry, [2, 37], depth=3, max_steps=steps)
            self.assertEqual(report["error"], {"code": "steps"})
            ledger = report["resources"]
            partial_destructor |= ledger["live_chains"] == 0 and ledger["live_chain_nodes"] == 1
        self.assertTrue(partial_destructor)
        for depth in (1, 2, 3, 32):
            with self.subTest(depth=depth):
                early = self.compare(source, entry, [2, 37], depth=depth, max_steps=1)
                self.assertEqual(early["error"], {"code": "steps"})
                heap = self.compare(source, entry, [2, 37], depth=depth, max_heap_bytes=2)
                self.assertEqual(heap["error"], {"code": "heap"})
                self.assertEqual(heap["resources"]["live_bytes"], 2)
                refused = self.compare(source, entry, [2, 37], depth=depth, allocation_fail_at=1)
                self.assertEqual(refused["error"], {"code": "allocation"})
                no_head = self.compare(source, entry, [2, 37], depth=depth, allocation_fail_at=2)
                self.assertEqual(no_head["status"], "trapped")

    def test_v1_and_legacy_reports_stay_fixed_at_32_for_every_schema(self):
        for version in range(1, 9):
            source = recursive_call()
            source["schema"] = f"hepta.hia.program.v{version}"
            core = verify_program(source)
            self.compare(source, "recur", [9], depth=1)
            v2 = self.compare(source, "recur", [9], depth=32)
            legacy_result = subprocess.run([str(self.executable), "--owned-run", "recur", "[9]",
                "100000", "1048576", "none"], input=core.canonical_bytes, capture_output=True, timeout=15)
            v1_result = subprocess.run([str(self.executable), "--owned-run-bound", "recur", "[9]",
                "100000", "1048576", "none"], input=core.canonical_bytes, capture_output=True, timeout=15)
            for result in (legacy_result, v1_result):
                self.assertEqual((result.returncode, result.stderr), (0, b""))
            v1 = json.loads(v1_result.stdout)
            self.assertEqual(v1["schema"], "hepta.hia.rust-bound-execution.v1")
            self.assertEqual(v1["request"]["schema"], "hepta.hia.rust-execution-request.v1")
            self.assertEqual(v1["execution"], v2)
            self.assertEqual(json.loads(legacy_result.stdout), v2)
            self.assertEqual((v2["steps"], v2["max_call_depth"]), (64, 32))
            old_api = crosscheck.crosscheck_rust_execution(source, "recur", [9], self.executable,
                                                         executable_sha256=self.digest)
            self.assertEqual(old_api["rust_report"], v2)
            type(self).compatibility.append({"core_sha256": core.sha256, "version": version,
                "legacy_process": {"argv": legacy_result.args, "returncode": legacy_result.returncode,
                    "stdout": legacy_result.stdout.decode(), "stderr": legacy_result.stderr.decode()},
                "v1_process": {"argv": v1_result.args, "returncode": v1_result.returncode,
                    "stdout": v1_result.stdout.decode(), "stderr": v1_result.stderr.decode()},
                "v1_crosscheck": old_api, "unchanged": True})

    def test_python_policy_and_nominal_entries_reject_before_launch(self):
        for depth in (True, False, 0, 33, -1, 1.0, None, "2", [], 1 << 64):
            with self.subTest(depth=depth), patch.object(crosscheck, "_verified_executable_bytes") as launch:
                with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    crosscheck.crosscheck_rust_execution_v2(scalar_program(), "identity", [7], self.executable,
                        executable_sha256=self.digest, max_call_depth=depth)
                launch.assert_not_called()
        with patch.object(crosscheck, "_verified_executable_bytes") as launch:
            with self.assertRaises(TypeError):
                crosscheck.crosscheck_rust_execution_v2(scalar_program(), "identity", [7], self.executable,
                                                       executable_sha256=self.digest)
            with self.assertRaises(TypeError):
                crosscheck.crosscheck_rust_execution_v2(scalar_program(), "identity", [7], self.executable,
                    executable_sha256=self.digest, max_call_depth=1, unknown_policy=False)
            with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                crosscheck.crosscheck_rust_execution_v2(nominal_identity_program(), "inspect_packet", [7],
                    self.executable, executable_sha256=self.digest, max_call_depth=1)
            source = loan_program("mut", "child")
            with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                crosscheck.crosscheck_rust_execution_v2(source, source["functions"][0]["name"], [0],
                    self.executable, executable_sha256=self.digest, max_call_depth=1)
            launch.assert_not_called()
        self.assertEqual(self.compare(nominal_identity_program(), "public_identity", [7], depth=2)["values"], [7])

    def test_raw_policy_requires_exact_shape_types_bounds_and_json(self):
        variants = []
        valid = policy(2)
        for field in valid:
            changed = deepcopy(valid)
            del changed[field]
            variants.append(("missing " + field, wire(changed).decode()))
            for value in (True, False, "1", [], {}):
                changed = {**valid, field: value}
                variants.append(("inexact " + field, wire(changed).decode()))
        for field, value in (("max_call_depth", 0), ("max_call_depth", 33), ("max_call_depth", -1),
                ("max_call_depth", 1 << 64), ("max_call_depth", None), ("max_steps", 0),
                ("max_steps", 1_000_001), ("max_steps", None), ("max_heap_bytes", -1),
                ("max_heap_bytes", 16 * 1024 * 1024 + 1), ("max_heap_bytes", None),
                ("allocation_fail_at", 0), ("allocation_fail_at", -1),
                ("allocation_fail_at", 1 << 64), ("unknown", False)):
            variants.append(("outside " + field, wire({**valid, field: value}).decode()))
        encoded = wire(valid).decode()
        variants += [("duplicate field", encoded[:-1] + ',"max_call_depth":2}'),
                     ("float", encoded.replace('"max_call_depth":2', '"max_call_depth":2.0')),
                     ("exponent", encoded.replace('"max_call_depth":2', '"max_call_depth":2e0')),
                     ("trailing json", encoded + "{}"), ("oversize", " " * 1025),
                     ("too deep", "[" * 70 + "0" + "]" * 70), ("null", "null"), ("array", "[]")]
        for label, raw_policy in variants:
            with self.subTest(label=label, policy=raw_policy[:100]):
                self.reject_raw(wire(scalar_program()), "identity", "[7]", raw_policy, reason=label)
        for args in (["--owned-run-bound-v2", "identity", "[7]"],
                     ["--owned-run-bound-v2", "identity", "[7]", encoded, "extra"]):
            completed = subprocess.run([str(self.executable), *args], input=wire(scalar_program()),
                                       capture_output=True, timeout=15)
            self.assertEqual((completed.returncode, completed.stdout), (1, b""))

    def test_invalid_raw_core_and_typed_arguments_cannot_hide_behind_depth_one(self):
        hidden = scalar_program()
        bad = deepcopy(hidden["functions"][0])
        bad["name"] = "hidden"
        bad["blocks"][0]["ops"] = [{"op": "future.unsafe", "args": [], "out": [], "attrs": {}}]
        hidden["functions"].append(bad)
        origin = loan_program("mut", "recursive")
        origin["functions"][0]["return_loans"] = ["missing"]
        exported = loan_program("mut", "child")
        exported["exports"].append(exported["functions"][0]["name"])
        variants = [(wire(hidden), "identity", "[7]"),
                    (wire(origin), origin["exports"][0], "[2,37]"),
                    (wire(exported), exported["exports"][0], "[2,37]"),
                    (wire(scalar_program()).replace(b'"schema":', b'"schema":"bad","schema":'), "identity", "[7]")]
        for raw_core, entry, args in variants:
            with self.assertRaises(HIAProgramRejected) as denied:
                verify_program(raw_core)
            self.reject_raw(raw_core, entry, args, wire(policy(1, steps=1, heap=0, fail=1)).decode(),
                            reason="whole-module independent refusal", python_error=str(denied.exception))
        for arguments in ("[true]", "[false]", "[7.0]", "[7e0]", '["7"]', "[7,8]", "{}"):
            self.reject_raw(wire(scalar_program()), "identity", arguments, wire(policy(1)).decode(),
                            reason="typed scalar boundary")

    def test_rehashed_policy_or_result_tampering_and_cross_version_replays_reject(self):
        self.compare(owned_program(), "allocate_release", [3], depth=1, max_steps=2)
        envelope = json.loads(type(self).observations[-1]["process"]["stdout"])
        mutations = [
            lambda r: r["request"].update(function="another_entry"),
            lambda r: r["request"].update(arguments=[4]),
            lambda r: r["request"].update(program_sha256="0" * 64),
            lambda r: r["request"]["policy"].update(max_call_depth=2),
            lambda r: r["request"]["policy"].update(max_call_depth=True),
            lambda r: r["request"]["policy"].pop("max_call_depth"),
            lambda r: r["request"]["policy"].update(unknown=False),
            lambda r: r["execution"].update(max_call_depth=2),
            lambda r: r["execution"].update(max_call_depth=True),
            lambda r: r["execution"]["resources"].update(live_owners=0),
            lambda r: r["execution"]["resources"].update(live_owners=True),
            lambda r: r["execution"]["claims"].update(production_admission_authorized=0),
            lambda r: r["execution"]["claims"].update(production_admission_authorized=True),
            lambda r: r.update(schema="hepta.hia.rust-bound-execution.v1"),
            lambda r: r["request"].update(schema="hepta.hia.rust-execution-request.v1"),
        ]
        for index, mutate in enumerate(mutations):
            report = deepcopy(envelope)
            mutate(report)
            report["request_sha256"] = sha256(wire(report["request"])).hexdigest()
            with self.subTest(mutation=index), tempfile.TemporaryDirectory() as directory:
                executable, digest = legacy.RustExecutionCrosscheck.fake(self, directory, wire(report) + b"\n")
                with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    crosscheck.crosscheck_rust_execution_v2(owned_program(), "allocate_release", [3], executable,
                        executable_sha256=digest, max_call_depth=1, max_steps=2)
        self.compare(scalar_program(), "identity", [7], depth=32)
        actual_v2 = type(self).observations[-1]["process"]["stdout"].encode()
        with tempfile.TemporaryDirectory() as directory:
            executable, digest = legacy.RustExecutionCrosscheck.fake(self, directory, actual_v2)
            with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                crosscheck.crosscheck_rust_execution(scalar_program(), "identity", [7], executable,
                                                   executable_sha256=digest)
        v1_process = subprocess.run([str(self.executable), "--owned-run-bound", "identity", "[7]",
            "100000", "1048576", "none"], input=wire(scalar_program()), capture_output=True, timeout=15)
        self.assertEqual((v1_process.returncode, v1_process.stderr), (0, b""))
        bad_results = [v1_process.stdout]
        for value in (8, True):
            changed = json.loads(actual_v2)
            changed["execution"]["values"] = [value]
            bad_results.append(wire(changed) + b"\n")
        for raw in bad_results:
            with tempfile.TemporaryDirectory() as directory:
                executable, digest = legacy.RustExecutionCrosscheck.fake(self, directory, raw)
                with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    crosscheck.crosscheck_rust_execution_v2(scalar_program(), "identity", [7], executable,
                        executable_sha256=digest, max_call_depth=32)


if __name__ == "__main__":
    unittest.main()
