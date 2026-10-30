"""Actual v4 invocation parity; no imported receipt or production promotion."""
from copy import deepcopy
from hashlib import sha256
import json
import platform
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_rust_crosscheck as crosscheck
from hepta.hia_program import HIAProgramRejected, verify_program
from tests import test_hia_rust_bound_depth as depth_v2
from tests import test_hia_rust_execution_crosscheck as legacy
from tests.test_hia_rust_crosscheck import scalar_program, owned_program
from tests.test_hia_rust_owned_memory import chain_extent
from tests.test_hia_returned_loans import loan_program
from tests.test_hia_composite_abi import nominal_identity_program

wire = depth_v2.wire


def policy(*, fail=None, steps=100_000, heap=1024 * 1024, depth=32):
    return {"max_steps": steps, "max_heap_bytes": heap,
            "max_call_depth": depth, "allocation_fail_at": fail}


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual bound-v4 qualification requires Linux/Cargo; NOT qualified")
class RustApiV4Parity(unittest.TestCase):
    setUpClass = classmethod(depth_v2.RustBoundDepthParity.setUpClass.__func__)

    def compare(self, source, entry, arguments, **limits):
        core = verify_program(source)
        type(self).programs[core.sha256] = core.canonical_bytes.decode()
        captured = []
        actual = crosscheck._run_pinned_shadow

        def record(binary, argv, stdin, timeout, **kwargs):
            stdout, stderr, returncode = actual(binary, argv, stdin, timeout, **kwargs)
            captured.append({"argv_after_pinned_executable": argv,
                "executable_sha256": sha256(binary).hexdigest(), "stdin_sha256": sha256(stdin).hexdigest(),
                "returncode": returncode, "stdout": stdout.decode(), "stderr": stderr.decode()})
            return stdout, stderr, returncode

        with patch.object(crosscheck, "_run_pinned_shadow", record):
            result = crosscheck.crosscheck_rust_execution_v4(source, entry, arguments,
                self.executable, executable_sha256=self.digest, **limits)
        self.assertEqual(len(captured), 1)
        self.assertEqual(result["schema"], "hepta.hia.rust-execution-crosscheck.v4")
        self.assertEqual(result["rust_report"]["schema"], "hepta.hia.rust-byte-owner-execution.v2")
        self.assertEqual(result["request_sha256"], sha256(wire(result["request"])).hexdigest())
        self.assertIs(result["claims"]["rust_is_production_admission_authority"], False)
        type(self).observations.append({"test": self.id(), "crosscheck": result,
            "argument_container": type(arguments).__name__, "process": captured[0], "matched": True})
        return result

    def raw(self, raw_core, entry, raw_arguments, raw_policy, *, mode="--owned-run-bound-v4"):
        return depth_v2.RustBoundDepthParity.raw(
            self, raw_core, entry, raw_arguments, raw_policy, mode=mode)

    reject_raw = depth_v2.RustBoundDepthParity.reject_raw

    def test_tuple_list_and_wide_indices_bind_identical_invocations(self):
        for version in range(1, 9):
            source = scalar_program()
            source["schema"] = f"hepta.hia.program.v{version}"
            for fail in (None, 1, (1 << 64) - 1, (1 << 64) + 1,
                         (1 << 255) + 17, (1 << 2048) + 1):
                with self.subTest(version=version, bits=None if fail is None else fail.bit_length()):
                    listed = self.compare(source, "identity", [7], allocation_fail_at=fail)
                    tupled = self.compare(source, "identity", (7,), allocation_fail_at=fail)
                    self.assertEqual(listed["request"], tupled["request"])
                    self.assertEqual(listed["request_sha256"], tupled["request_sha256"])
                    encoded = tupled["request"]["policy"]["allocation_fail_at"]
                    self.assertEqual(encoded, None if fail is None else hex(fail))
                    self.assertEqual(tupled["rust_report"]["allocation_fail_at"], encoded)
                    self.assertEqual(tupled["rust_report"]["values"], [7])

    def test_allocation_order_loans_chains_and_step_stops_keep_exact_ledgers(self):
        for fail in (1, 2, (1 << 64) + 1, (1 << 128) + 1):
            for size in (0, 3):
                observed = self.compare(owned_program(), "allocate_release", (size,),
                                        allocation_fail_at=fail)["rust_report"]
                self.assertEqual(observed["resources"]["allocation_attempts"], int(size != 0))
                self.assertEqual(observed["status"], "trapped" if size and fail == 1 else "returned")
            chain = self.compare(chain_extent(), "extent", (3,), allocation_fail_at=fail)["rust_report"]
            self.assertEqual(chain["status"], "returned")
            self.assertEqual(chain["resources"]["live_owners"], 0)
            self.assertEqual(chain["resources"]["live_chain_nodes"], 0)
        source = loan_program("mut", "child")
        entry = source["exports"][0]
        normal = self.compare(source, entry, (2, 37), allocation_fail_at=(1 << 64) + 1)
        for steps in range(1, normal["rust_report"]["steps"]):
            stopped = self.compare(source, entry, (2, 37), max_steps=steps,
                allocation_fail_at=(1 << 64) + 1)["rust_report"]
            self.assertEqual(stopped["error"], {"code": "steps"})
            self.assertEqual(stopped["steps"], steps + 1)
        denied = self.compare(owned_program(), "allocate_release", (1,),
            max_heap_bytes=0, allocation_fail_at=(1 << 64) + 1)["rust_report"]
        self.assertEqual(denied["error"], {"code": "heap"})
        self.assertEqual(denied["resources"]["allocation_attempts"], 0)

    def test_exact_policy_wire_boundary_and_prelaunch_large_integer_refusal(self):
        selected = policy(steps=100, heap=64, depth=32)
        digits = 1024 - len(wire(selected))
        largest_width = 1 << (4 * (digits - 1))
        limits = {"max_steps": 100, "max_heap_bytes": 64, "max_call_depth": 32}
        observed = self.compare(owned_program(), "allocate_release", (1,),
                                allocation_fail_at=largest_width, **limits)
        encoded = wire(observed["request"]["policy"])
        self.assertEqual(len(encoded), 1024)
        self.assertEqual(int(observed["request"]["policy"]["allocation_fail_at"], 16), largest_width)
        with patch.object(crosscheck, "_verified_executable_bytes") as launch:
            for index in (1 << (4 * digits), 1 << 100_000):
                with self.assertRaisesRegex(crosscheck.HIARustCrosscheckRejected, "policy wire budget"):
                    crosscheck.crosscheck_rust_execution_v4(scalar_program(), "identity", (7,),
                        self.executable, executable_sha256=self.digest, allocation_fail_at=index, **limits)
            launch.assert_not_called()
        self.reject_raw(wire(scalar_program()), "identity", "[7]", " " + encoded.decode(),
                        reason="1025-byte policy refused before execution")

    def test_native_policy_rejects_noncanonical_hex_and_ambiguous_json(self):
        valid = policy(fail="0x10000000000000001")
        variants = []
        for fail in (0, 1, True, False, [], {}, 1.0, "", "1", "0x", "0x0", "0x00",
                     "0x01", "0X1", "0xA", "+0x1", "-0x1", "0x-1", "0x1_0", "0x1 ", " 0x1", "0xé"):
            variants.append(("inexact failure " + repr(fail), wire({**valid, "allocation_fail_at": fail}).decode()))
        for field in valid:
            missing = deepcopy(valid)
            del missing[field]
            variants.append(("missing " + field, wire(missing).decode()))
        for field, value in (("max_steps", True), ("max_steps", 10_000_001),
                ("max_heap_bytes", -1), ("max_call_depth", 257), ("unknown", False)):
            variants.append(("invalid " + field, wire({**valid, field: value}).decode()))
        encoded = wire(valid).decode()
        variants.extend([
            ("duplicate", encoded[:-1] + ',"allocation_fail_at":"0x1"}'),
            ("decoded duplicate", encoded[:-1] + ',"allocation_fail\\u005fat":"0x1"}'),
            ("exponent", encoded.replace('"max_steps":100000', '"max_steps":1e5')),
            ("trailing JSON", encoded + "{}"),
        ])
        for reason, raw in variants:
            with self.subTest(reason=reason):
                self.reject_raw(wire(scalar_program()), "identity", "[7]", raw, reason=reason)

    def test_python_exact_types_and_original_entry_eligibility_reject_before_launch(self):
        class IntSubclass(int):
            pass
        class TupleSubclass(tuple):
            pass
        cases = [((7,), {"allocation_fail_at": item})
                 for item in (True, False, 0, -1, 1.0, "0x1", IntSubclass(1))]
        cases += [(args, {}) for args in (TupleSubclass((7,)), iter([7]), (True,), (1.0,),
                                          (IntSubclass(7),), ([7],), (7, 8), (0,) * 8193)]
        with patch.object(crosscheck, "_verified_executable_bytes") as launch:
            for arguments, limits in cases:
                with self.subTest(container=type(arguments).__name__, fields=tuple(limits)):
                    with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                        crosscheck.crosscheck_rust_execution_v4(scalar_program(), "identity", arguments,
                            self.executable, executable_sha256=self.digest, **limits)
            with self.assertRaisesRegex(crosscheck.HIARustCrosscheckRejected, "public scalar"):
                crosscheck.crosscheck_rust_execution_v4(nominal_identity_program(), "inspect_packet", (7,),
                    self.executable, executable_sha256=self.digest, allocation_fail_at=(1 << 64) + 1)
            launch.assert_not_called()
        admitted = self.compare(nominal_identity_program(), "public_identity", (7,),
                                allocation_fail_at=(1 << 64) + 1)
        self.assertEqual(admitted["input_sha256"], verify_program(nominal_identity_program()).input_sha256)

    def test_tiny_budget_or_wide_index_cannot_hide_invalid_unused_function(self):
        source = scalar_program()
        hidden = deepcopy(source["functions"][0])
        hidden["name"] = "hidden"
        hidden["blocks"][0]["ops"] = [{"op": "future.unsafe", "args": [], "out": [], "attrs": {}}]
        source["functions"].append(hidden)
        with patch.object(crosscheck, "_verified_executable_bytes") as launch:
            with self.assertRaises(HIAProgramRejected):
                crosscheck.crosscheck_rust_execution_v4(source, "identity", (7,), self.executable,
                    executable_sha256=self.digest, max_steps=1, allocation_fail_at=(1 << 64) + 1)
            launch.assert_not_called()
        self.reject_raw(wire(source), "identity", "[7]",
            wire(policy(steps=1, fail="0x10000000000000001")).decode(),
            reason="whole-module admission still precedes execution")

    def test_rehashed_policy_tampering_and_cross_protocol_replay_are_rejected(self):
        core = verify_program(scalar_program())
        selected = policy(fail="0x10000000000000001")
        raw = self.raw(core.canonical_bytes, "identity", "[7]", wire(selected).decode())
        self.assertEqual(raw["returncode"], 0, raw)
        actual = json.loads(raw["stdout"])
        cases = []
        for wrong in (None, 1, "0x1", "0x10000000000000002", "0x010000000000000001"):
            changed = deepcopy(actual)
            changed["request"]["policy"]["allocation_fail_at"] = wrong
            changed["execution"]["allocation_fail_at"] = wrong
            changed["request_sha256"] = sha256(wire(changed["request"])).hexdigest()
            cases.append(changed)
        for version in (1, 2, 3):
            changed = deepcopy(actual)
            changed["schema"] = f"hepta.hia.rust-bound-execution.v{version}"
            changed["request"]["schema"] = f"hepta.hia.rust-execution-request.v{version}"
            changed["request_sha256"] = sha256(wire(changed["request"])).hexdigest()
            cases.append(changed)
        changed = deepcopy(actual)
        changed["execution"]["schema"] = "hepta.hia.rust-byte-owner-execution.v1"
        cases.append(changed)
        for index, changed in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                executable, digest = legacy.RustExecutionCrosscheck.fake(self, directory, wire(changed) + b"\n")
                with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    crosscheck.crosscheck_rust_execution_v4(scalar_program(), "identity", (7,), executable,
                        executable_sha256=digest, allocation_fail_at=(1 << 64) + 1,
                        max_steps=100_000, max_heap_bytes=1024 * 1024, max_call_depth=32)

    def test_legacy_reports_and_refusal_contracts_remain_unchanged(self):
        apis = (crosscheck.crosscheck_rust_execution, crosscheck.crosscheck_rust_execution_v2,
                crosscheck.crosscheck_rust_execution_v3)
        for version in range(1, 9):
            source = owned_program()
            source["schema"] = f"hepta.hia.program.v{version}"
            reports = []
            for fail in (None, 1, 2):
                selected = {"max_steps": 100_000, "max_heap_bytes": 1024 * 1024,
                            "allocation_fail_at": fail}
                current = self.compare(source, "allocate_release", (3,), max_call_depth=32, **selected)
                expected = deepcopy(current["rust_report"])
                expected["schema"] = "hepta.hia.rust-byte-owner-execution.v1"
                expected["allocation_fail_at"] = fail
                for index, api in enumerate(apis):
                    limits = {} if index == 0 else {"max_call_depth": 32}
                    observed = api(source, "allocate_release", [3], self.executable,
                        executable_sha256=self.digest, **selected, **limits)
                    self.assertEqual(observed["rust_report"], expected)
                    self.assertEqual(observed["request"]["policy"]["allocation_fail_at"], fail)
                    reports.append(observed)
            type(self).compatibility.append({"version": version, "unchanged": True, "reports": reports})
        with patch.object(crosscheck, "_verified_executable_bytes") as launch:
            for index, api in enumerate(apis):
                limits = {} if index == 0 else {"max_call_depth": 32}
                for arguments, fail in (((7,), None), ([7], 1 << 64)):
                    with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                        api(scalar_program(), "identity", arguments, self.executable,
                            executable_sha256=self.digest, allocation_fail_at=fail, **limits)
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()

