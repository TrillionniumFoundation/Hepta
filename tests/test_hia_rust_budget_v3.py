"""Actual bound-v3 dual execution, not a production-authority promotion."""
from copy import deepcopy
from hashlib import sha256
import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_rust_crosscheck as crosscheck
from hepta.hia_program import HIAProgramRejected, verify_program
from tests import test_hia_rust_bound_depth as depth_v2
from tests import test_hia_rust_execution_crosscheck as legacy
from tests.test_hia_rust_crosscheck import scalar_program, owned_program
from tests.test_hia_rust_scalar_vm import recursive_call, depth_boundary
from tests.test_hia_returned_loans import loan_program
from tests.test_hia_rust_returned_chains import recursive_chain_head
from tests.test_hia_rust_owned_memory import recursive_chain
from tests.test_hia_composite_abi import nominal_identity_program
from tests.test_hia_program import f, b, m, jump

ROOT = depth_v2.ROOT
wire = depth_v2.wire
policy = depth_v2.policy


def endless_loop():
    return m(f("looping", [], [], [], [
        b("entry", [], [], jump("loop")),
        b("loop", [], [], jump("loop")),
    ]))


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cargo"),
                     "Actual bound-v3 qualification requires Linux/Cargo; NOT qualified")
class RustBudgetV3Parity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        depth_v2.RustBoundDepthParity.setUpClass.__func__(cls)

    def compare(self, source, entry, arguments, *, depth=256, **limits):
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
            result = crosscheck.crosscheck_rust_execution_v3(source, entry, arguments, self.executable,
                executable_sha256=self.digest, max_call_depth=depth, **limits)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["executable_sha256"], self.digest)
        self.assertEqual(captured[0]["stdin_sha256"], core.sha256)
        self.assertEqual(result["schema"], "hepta.hia.rust-execution-crosscheck.v3")
        self.assertEqual(result["request"]["schema"], "hepta.hia.rust-execution-request.v3")
        self.assertEqual(result["rust_report"]["max_call_depth"], depth)
        self.assertIs(result["claims"]["rust_is_production_admission_authority"], False)
        self.assertIs(result["claims"]["native_backend_refinement_proved"], False)
        type(self).observations.append({"test": self.id(), "crosscheck": result,
                                       "process": captured[0], "matched": True})
        return result["rust_report"]

    def raw(self, raw_core, entry, raw_arguments, raw_policy, *, mode="--owned-run-bound-v3"):
        return depth_v2.RustBoundDepthParity.raw(
            self, raw_core, entry, raw_arguments, raw_policy, mode=mode)

    reject_raw = depth_v2.RustBoundDepthParity.reject_raw

    def test_all_256_depths_have_actual_returns_and_exact_call_stops(self):
        for selected_depth in range(1, 257):
            with self.subTest(depth=selected_depth):
                stopped = self.compare(recursive_call(), "recur", [9], depth=selected_depth)
                self.assertEqual(stopped["error"], {"code": "calls"})
                self.assertEqual(stopped["steps"], 2 * selected_depth)
                normal = self.compare(depth_boundary(), "bounded", [selected_depth - 1], depth=selected_depth)
                self.assertEqual(normal["values"], [0])
                boundary = self.compare(depth_boundary(), "bounded", [selected_depth], depth=selected_depth)
                self.assertEqual(boundary["error"], {"code": "calls"})

    def test_deep_returned_loans_and_chains_keep_exact_stopped_ledgers(self):
        for selected_depth in (33, 64, 128, 255, 256):
            for kind in ("loan", "chain_head", "owned_chain"):
                for normal in (False, True):
                    recursion = selected_depth - (2 if normal else 1)
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
                    with self.subTest(depth=selected_depth, kind=kind, normal=normal):
                        result = self.compare(source, entry, arguments, depth=selected_depth)
                        ledger = result["resources"]
                        if normal:
                            self.assertEqual(result["values"], [True] if kind == "owned_chain" else [42])
                            self.assertEqual((ledger["live_bytes"], ledger["live_owners"],
                                              ledger["live_local_loans"]), (0, 0, 0))
                        else:
                            self.assertEqual(result["error"], {"code": "calls"})
                            self.assertEqual(ledger["live_bytes"], 2 if kind == "loan" else
                                             25 if kind == "owned_chain" else 26)
                            self.assertEqual(ledger["live_owners"], 1 if kind == "loan" else 2)
                            self.assertEqual(ledger["live_local_loans"], 0 if kind == "owned_chain" else 1)
                        if kind != "loan":
                            self.assertEqual(ledger["live_chain_nodes"], 0 if normal else 1)
                            self.assertEqual(ledger["live_chains"], 0 if normal else 1)

    def test_ten_million_ticks_execute_and_old_step_limit_still_rejects(self):
        result = self.compare(endless_loop(), "looping", [], depth=1,
                              max_steps=10_000_000, max_heap_bytes=0, timeout=120)
        self.assertEqual(result["error"], {"code": "steps"})
        self.assertEqual(result["steps"], 10_000_001)
        self.reject_raw(wire(endless_loop()), "looping", "[]",
                        wire(policy(1, steps=10_000_001, heap=0)).decode(), reason="v3 step ceiling")
        with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
            crosscheck.crosscheck_rust_execution_v2(endless_loop(), "looping", [], self.executable,
                executable_sha256=self.digest, max_call_depth=1, max_steps=1_000_001)

    def test_larger_payload_is_allocated_and_heap_denial_precedes_host_allocation(self):
        amount = 16 * 1024 * 1024 + 1
        for heap in (amount, 1024 * 1024 * 1024):
            result = self.compare(owned_program(), "allocate_release", [amount], max_heap_bytes=heap)
            self.assertEqual(result["status"], "returned")
            self.assertEqual(result["resources"]["peak_bytes"], amount)
            self.assertEqual(result["resources"]["live_bytes"], 0)
        # At the upper policy limit, an over-limit request must stop before
        # allocation. This is not presented as a successful 1 GiB allocation.
        denied = self.compare(owned_program(), "allocate_release", [1024 * 1024 * 1024 + 1],
                              max_heap_bytes=1024 * 1024 * 1024)
        self.assertEqual(denied["error"], {"code": "heap"})
        self.assertEqual(denied["resources"]["live_bytes"], 0)
        injected = self.compare(owned_program(), "allocate_release", [amount],
            max_heap_bytes=1024 * 1024 * 1024, allocation_fail_at=1)
        self.assertEqual(injected["error"], {"code": "allocation"})
        self.assertEqual(injected["resources"]["live_bytes"], 0)

    def test_deep_step_stops_and_traps_retain_real_prefixes(self):
        source = recursive_chain_head(depth=254)
        entry = source["exports"][0]
        complete = self.compare(source, entry, [2, 37], depth=256)
        for steps in (1, 2, 3, 31, 255, 511, complete["steps"] // 2,
                      complete["steps"] - 4, complete["steps"] - 3,
                      complete["steps"] - 2, complete["steps"] - 1):
            with self.subTest(steps=steps):
                stopped = self.compare(source, entry, [2, 37], depth=256, max_steps=steps)
                self.assertEqual(stopped["error"], {"code": "steps"})
                self.assertEqual(stopped["steps"], steps + 1)
        trapping = recursive_chain_head(depth=254)
        recursive = trapping["functions"][0]
        terminal = next(block for block in recursive["blocks"] if block["term"]["op"] == "ret")
        terminal["term"] = {"op": "trap", "code": "user"}
        if "trap" not in recursive["effects"]:
            recursive["effects"].append("trap")
        trapped = self.compare(trapping, trapping["exports"][0], [2, 37], depth=256)
        self.assertEqual(trapped["error"], {"code": "user"})
        self.assertGreater(trapped["resources"]["live_owners"], 0)
        self.assertGreater(trapped["resources"]["live_chain_nodes"], 0)

    def test_raw_policy_and_original_entry_admission_remain_strict(self):
        valid = policy(256, steps=10_000_000, heap=1024 * 1024 * 1024)
        variants = []
        for field in valid:
            changed = deepcopy(valid)
            del changed[field]
            variants.append(("missing " + field, wire(changed).decode()))
            for value in (True, False, "1", [], {}, 1.0):
                variants.append(("inexact " + field, wire({**valid, field: value}).decode()))
        for field, value in (("max_call_depth", 0), ("max_call_depth", 257),
                ("max_steps", 0), ("max_steps", 10_000_001),
                ("max_heap_bytes", -1), ("max_heap_bytes", 1024 * 1024 * 1024 + 1),
                ("allocation_fail_at", 0), ("allocation_fail_at", 1 << 64), ("unknown", False)):
            variants.append(("outside " + field, wire({**valid, field: value}).decode()))
        encoded = wire(valid).decode()
        variants += [("duplicate", encoded[:-1] + ',"max_call_depth":256}'),
                     ("exponent", encoded.replace('"max_call_depth":256', '"max_call_depth":256e0')),
                     ("trailing", encoded + "{}"), ("oversize", " " * 1025)]
        for label, raw_policy in variants:
            with self.subTest(label=label):
                self.reject_raw(wire(scalar_program()), "identity", "[7]", raw_policy, reason=label)
        with patch.object(crosscheck, "_verified_executable_bytes") as launch:
            for field, value in (("max_call_depth", 257), ("max_call_depth", True),
                    ("max_steps", 10_000_001), ("max_heap_bytes", 1024 * 1024 * 1024 + 1),
                    ("timeout", 121), ("allocation_fail_at", 1 << 64)):
                with self.subTest(field=field), self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    crosscheck.crosscheck_rust_execution_v3(scalar_program(), "identity", [7],
                        self.executable, executable_sha256=self.digest, **{field: value})
            with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                crosscheck.crosscheck_rust_execution_v3(nominal_identity_program(), "inspect_packet", [7],
                    self.executable, executable_sha256=self.digest)
            launch.assert_not_called()
        hidden = scalar_program()
        bad = deepcopy(hidden["functions"][0])
        bad["name"] = "hidden"
        bad["blocks"][0]["ops"] = [{"op": "future.unsafe", "args": [], "out": [], "attrs": {}}]
        hidden["functions"].append(bad)
        with self.assertRaises(HIAProgramRejected) as denied:
            verify_program(wire(hidden))
        self.reject_raw(wire(hidden), "identity", "[7]", wire(policy(256, steps=1, heap=0, fail=1)).decode(),
                        reason="whole-module refusal before early stop", python_error=str(denied.exception))

    def test_v1_v2_reports_remain_unchanged_for_all_primitive_schemas(self):
        for version in range(1, 9):
            source = recursive_call()
            source["schema"] = f"hepta.hia.program.v{version}"
            observed = self.compare(source, "recur", [9], depth=32,
                max_steps=100_000, max_heap_bytes=1024 * 1024)
            prior = []
            for api in (crosscheck.crosscheck_rust_execution, crosscheck.crosscheck_rust_execution_v2):
                kwargs = {"max_call_depth": 32} if api is crosscheck.crosscheck_rust_execution_v2 else {}
                result = api(source, "recur", [9], self.executable,
                    executable_sha256=self.digest, **kwargs)
                self.assertEqual(result["rust_report"], observed)
                prior.append(result)
            type(self).compatibility.append({"version": version, "unchanged": True,
                                             "v1": prior[0], "v2": prior[1]})

    def test_rehashed_tampering_and_cross_protocol_replay_reject(self):
        self.compare(owned_program(), "allocate_release", [3], depth=256, max_steps=2)
        original = json.loads(type(self).observations[-1]["process"]["stdout"])
        mutations = [
            lambda r: r["request"]["policy"].update(max_call_depth=255),
            lambda r: r["request"]["policy"].update(max_steps=1_000_001),
            lambda r: r["request"]["policy"].update(max_heap_bytes=1024 * 1024 * 1024),
            lambda r: r["execution"]["resources"].update(live_owners=0),
            lambda r: r["execution"].update(max_call_depth=True),
            lambda r: r["execution"]["claims"].update(production_admission_authorized=True),
            lambda r: r.update(schema="hepta.hia.rust-bound-execution.v2"),
            lambda r: r["request"].update(schema="hepta.hia.rust-execution-request.v2"),
        ]
        for index, mutate in enumerate(mutations):
            changed = deepcopy(original)
            mutate(changed)
            changed["request_sha256"] = sha256(wire(changed["request"])).hexdigest()
            with self.subTest(mutation=index), tempfile.TemporaryDirectory() as directory:
                executable, digest = legacy.RustExecutionCrosscheck.fake(self, directory, wire(changed) + b"\n")
                with self.assertRaises(crosscheck.HIARustCrosscheckRejected):
                    crosscheck.crosscheck_rust_execution_v3(owned_program(), "allocate_release", [3],
                        executable, executable_sha256=digest, max_steps=2)


if __name__ == "__main__":
    unittest.main()
