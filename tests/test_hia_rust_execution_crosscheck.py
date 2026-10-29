"""Actual dual execution and adversarial invocation-envelope controls.

Replayed reports are deliberately fake producer fixtures. Their rejection
tests exercise the consumer contract; they cannot authenticate a hostile host.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_rust_crosscheck import HIARustCrosscheckRejected, crosscheck_rust_execution
from tests import test_hia_rust_crosscheck as static_crosscheck
from tests.test_hia_rust_crosscheck import owned_program, scalar_program
from tests.test_hia_composite_abi import nominal_identity_program
from tests.test_hia_returned_loans import loan_program, multiple_shared
from tests.test_hia_rust_returned_chains import chain_bulk_pipeline, shared_chain_returns


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual pinned Rust execution requires Linux and Cargo; NOT qualified")
class RustExecutionCrosscheck(unittest.TestCase):
    setUpClass = classmethod(static_crosscheck.RustShadowCrosscheckNative.setUpClass.__func__)

    def compare(self, document, entry, arguments, **policy):
        report = crosscheck_rust_execution(document, entry, arguments, self.executable,
                                          executable_sha256=self.digest, **policy)
        self.assertEqual(report["status"], "execution_corroborated_not_authority")
        self.assertIs(report["claims"]["rust_is_production_admission_authority"], False)
        self.assertIs(report["claims"]["native_backend_refinement_proved"], False)
        self.assertEqual(report["request_sha256"], sha256(wire(report["request"])).hexdigest())
        return report

    def envelope(self, document, entry, arguments, *, steps=100_000, heap=1024 * 1024, fail=None):
        checked = verify_program(document)
        result = subprocess.run([str(self.executable), "--owned-run-bound", entry,
                                 wire(arguments).decode(), str(steps), str(heap),
                                 "none" if fail is None else str(fail)],
                                input=checked.canonical_bytes, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def fake(self, root, raw, *, diagnostic="", returncode=0):
        path = Path(root) / "replay"
        path.write_text(f"#!{sys.executable}\nimport sys\nsys.stdin.buffer.read()\n"
                        f"sys.stdout.buffer.write({raw!r})\n"
                        f"sys.stderr.write({diagnostic!r})\nsys.exit({returncode})\n")
        path.chmod(0o700)
        return path, sha256(path.read_bytes()).hexdigest()

    def reject_envelope(self, envelope, document, entry, arguments, **policy):
        with tempfile.TemporaryDirectory() as temporary:
            executable, digest = self.fake(temporary, wire(envelope) + b"\n")
            with self.assertRaises(HIARustCrosscheckRejected):
                crosscheck_rust_execution(document, entry, arguments, executable,
                                          executable_sha256=digest, **policy)

    def test_actual_v1_to_v8_scalar_extremes_and_legacy_output_unchanged(self):
        source = scalar_program()
        source = json.loads(json.dumps(source).replace('"u32"', '"u64"'))
        for version in range(1, 9):
            source["schema"] = f"hepta.hia.program.v{version}"
            report = self.compare(source, "identity", [(1 << 64) - 1])
            self.assertEqual(report["rust_report"]["values"], [(1 << 64) - 1])
            legacy = subprocess.run([str(self.executable), "--owned-run", "identity",
                                     str([(1 << 64) - 1]), "100000", "1048576", "none"],
                                    input=verify_program(source).canonical_bytes,
                                    capture_output=True, timeout=15)
            self.assertEqual(legacy.returncode, 0)
            self.assertEqual(json.loads(legacy.stdout), report["rust_report"])

    def test_v8_returned_loans_shared_results_and_recursive_origins(self):
        for construction in ("forward", "child", "recursive"):
            source = loan_program("mut", construction)
            report = self.compare(source, source["exports"][0], [2, 37])
            self.assertEqual(report["rust_report"]["values"], [42])
            self.assertEqual(report["rust_report"]["profile"], "bounded-cfg-byte-owner-loan-returns-v4")
        report = self.compare(multiple_shared("mixed"), "shared", [37])
        self.assertEqual(report["rust_report"]["values"], [74])
        self.assertEqual(report["rust_report"]["resources"]["live_local_loans"], 0)

    def test_chain_storage_aliases_bulk_and_returned_loans_share_bound_contract(self):
        for version in (7, 8):
            report = self.compare(chain_bulk_pipeline(version=version), "pipeline", [True])
            self.assertEqual(report["rust_report"]["profile"], "bounded-cfg-owned-memory-v5")
            self.assertEqual(report["rust_report"]["resources"]["live_chain_nodes"], 0)
        report = self.compare(shared_chain_returns(), "shared", [37])
        self.assertEqual(report["rust_report"]["values"], [74])

    def test_return_trap_heap_and_every_step_stop_keep_exact_ledgers(self):
        source = loan_program("mut", "child")
        entry = source["exports"][0]
        completed = self.compare(source, entry, [2, 37])
        for budget in range(1, completed["python_report"]["steps"] + 1):
            observed = self.compare(source, entry, [2, 37], max_steps=budget)
            self.assertEqual(observed["rust_report"]["status"],
                             "returned" if budget == completed["python_report"]["steps"] else "budget_exceeded")
        trapped = self.compare(owned_program(), "allocate_release", [3], allocation_fail_at=1)
        self.assertEqual(trapped["rust_report"]["status"], "trapped")
        self.assertEqual(trapped["rust_report"]["error"], {"code": "allocation"})
        stopped = self.compare(owned_program(), "allocate_release", [3], max_heap_bytes=0)
        self.assertEqual(stopped["rust_report"]["status"], "budget_exceeded")
        self.assertEqual(stopped["rust_report"]["error"], {"code": "heap"})
        recursive = loan_program("read", "recursive")
        operations = recursive["functions"][-1]["blocks"][0]["ops"]
        next(op for op in operations if op["op"] == "const" and op["out"][0]["name"] == "depth")["attrs"]["value"] = 40
        stopped = self.compare(recursive, recursive["exports"][0], [2, 37])
        self.assertEqual(stopped["rust_report"]["error"], {"code": "calls"})
        self.assertGreater(stopped["rust_report"]["resources"]["live_local_loans"], 0)

    def test_nominal_input_preserves_public_entry_eligibility(self):
        source = nominal_identity_program()
        report = self.compare(source, "public_identity", [42])
        self.assertEqual(report["rust_report"]["values"], [42])
        self.assertEqual(report["input_sha256"], verify_program(source).input_sha256)
        with patch("hepta.hia_rust_crosscheck._verified_executable_bytes") as launch:
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "public scalar"):
                self.compare(source, "inspect_packet", [42])
            returned = loan_program("mut", "child")
            with self.assertRaisesRegex(HIARustCrosscheckRejected, "public scalar"):
                self.compare(returned, returned["functions"][0]["name"], [0])
            launch.assert_not_called()

    def test_changed_request_is_rejected_even_when_rehashed_and_same_result(self):
        source = scalar_program()
        # The second argument is unused, so changing it cannot be caught by
        # comparing returned values, step counts or the resource ledger alone.
        fn = source["functions"][0]
        fn["params"].append({"name": "unused", "type": "u32"})
        fn["blocks"][0]["params"].append({"name": "unused", "type": "u32"})
        valid = self.envelope(source, "identity", [7, 0])
        for field, changed in (("arguments", [7, 1]), ("function", "another"),
                               ("program_sha256", "0" * 64), ("mode", "scalar")):
            report = deepcopy(valid)
            report["request"][field] = changed
            report["request_sha256"] = sha256(wire(report["request"])).hexdigest()
            with self.subTest(field=field):
                self.reject_envelope(report, source, "identity", [7, 0])
        for field, changed in (("max_steps", 100001), ("max_heap_bytes", 0),
                               ("allocation_fail_at", 1), ("max_call_depth", 31)):
            report = deepcopy(valid)
            report["request"]["policy"][field] = changed
            report["request_sha256"] = sha256(wire(report["request"])).hexdigest()
            with self.subTest(policy=field):
                self.reject_envelope(report, source, "identity", [7, 0])
        for action in ("missing", "unknown"):
            report = deepcopy(valid)
            if action == "missing":
                del report["request"]["policy"]["max_call_depth"]
            else:
                report["request"]["policy"]["allow_native"] = False
            report["request_sha256"] = sha256(wire(report["request"])).hexdigest()
            with self.subTest(policy_shape=action):
                self.reject_envelope(report, source, "identity", [7, 0])

    def test_complete_report_types_capabilities_and_stopped_ledger_are_checked(self):
        source = owned_program()
        valid = self.envelope(source, "allocate_release", [3], steps=2)
        mutations = [
            lambda r: r["execution"].update(steps=2),
            lambda r: r["execution"].update(status="returned", values=[]),
            lambda r: r["execution"]["resources"].update(live_owners=0),
            lambda r: r["execution"]["resources"].pop("peak_bytes"),
            lambda r: r["execution"]["resources"].update(allocation_attempts=True),
            lambda r: r["execution"]["claims"].update(production_admission_authorized=True),
            lambda r: r["execution"]["claims"].update(general_resource_execution=0),
            lambda r: r["execution"]["claims"].pop("finite_byte_owner_execution"),
            lambda r: r["execution"].update(profile="bounded-cfg-owned-memory-v5"),
            lambda r: r["execution"].update(unknown_extension=False),
            lambda r: r["execution"]["error"].update(code="allocation"),
            lambda r: r.update(request_sha256="0" * 64),
        ]
        for index, mutate in enumerate(mutations):
            report = deepcopy(valid)
            mutate(report)
            with self.subTest(index=index):
                self.reject_envelope(report, source, "allocate_release", [3], max_steps=2)
        for value in (2, True):
            report = self.envelope(scalar_program(), "identity", [1])
            report["execution"]["values"][0] = value
            with self.subTest(return_value=value):
                self.reject_envelope(report, scalar_program(), "identity", [1])

    def test_malformed_wire_unknown_fields_stderr_and_exit_are_rejected(self):
        source = scalar_program()
        good = wire(self.envelope(source, "identity", [7]))
        cases = [(good, "", 0), (good + b"\n\n", "", 0),
                 (b'{"schema":"first","schema":"second"}\n', "", 0),
                 (b'{"request":1e300}\n', "", 0), (b"[" * 2000 + b"\n", "", 0),
                 (good + b"\n", "unexpected", 0), (good + b"\n", "", 1)]
        for index, (raw, diagnostic, code) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                executable, digest = self.fake(temporary, raw, diagnostic=diagnostic, returncode=code)
                with self.assertRaises(HIARustCrosscheckRejected):
                    crosscheck_rust_execution(source, "identity", [7], executable,
                                              executable_sha256=digest)

    def test_invalid_policy_arguments_and_hidden_core_reject_before_launch(self):
        cases = [([True], {}), ([1.0], {}), ([1 << 64], {}), ([[1]], {}),
                 ([0] * 8193, {}), ([7], {"max_steps": True}), ([7], {"max_steps": 1_000_001}),
                 ([7], {"max_heap_bytes": 16 * 1024 * 1024 + 1}),
                 ([7], {"allocation_fail_at": 1 << 64}), ([7], {"timeout": float("nan")})]
        with patch("hepta.hia_rust_crosscheck._verified_executable_bytes") as launch:
            for arguments, policy in cases:
                with self.subTest(arguments=arguments[:2], policy=policy):
                    with self.assertRaises(HIARustCrosscheckRejected):
                        self.compare(scalar_program(), "identity", arguments, **policy)
            source = scalar_program()
            unused = deepcopy(source["functions"][0])
            unused["name"] = "unused"
            unused["blocks"][0]["ops"] = [{"op": "future.unsafe", "args": [], "out": [], "attrs": {}}]
            source["functions"].append(unused)
            with self.assertRaises(HIAProgramRejected):
                self.compare(source, "identity", [7], max_steps=1)
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
