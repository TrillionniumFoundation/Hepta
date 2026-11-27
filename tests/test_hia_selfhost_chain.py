"""Core references for finite dynamic-chain successor witnesses."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_chain_cases import cases
from tools.hia_selfhost_chain_flow_cases import cases as flow_cases, refusals, profile_refusal_ids, expanded_name_cases as flow_name_cases, historical_refusals as historical_flow_refusals
from tools.hia_selfhost_owned_elf_cases import reference
from tools.hia_selfhost_parameter_cases import cases as parameter_cases, refusals as parameter_refusals, expanded_name_cases as parameter_name_cases, historical_refusals as historical_parameter_refusals


class ChainSourceTests(unittest.TestCase):
    def test_all_six_operations_have_valid_typed_core_witnesses(self):
        observed = set()
        for case in cases():
            checked = assemble_program(case["source"]).as_dict()
            observed.update(op["op"] for fn in checked["functions"] for block in fn["blocks"] for op in block["ops"])
        self.assertEqual({op for op in observed if op.startswith("chain.")},
            {"chain.empty", "chain.try_push", "chain.pop", "chain.is_empty", "chain.head_read", "chain.head_mut"})

    def test_independent_core_observes_results_traps_and_prior_writes(self):
        rows = cases()
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({case["id"] for case in rows}), len(rows))
        for case in rows:
            with self.subTest(case=case["id"]):
                result = reference(case)
                self.assertEqual(result["external_output_hex"], case["expected_output_hex"])
                if "expected_trap" in case:
                    self.assertEqual(result["status"], "trapped")
                    self.assertEqual(result["error"]["code"], "bounds")
                else:
                    self.assertEqual(result["result"], case["expected_result"])
                    for field in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
                        self.assertEqual(result["resources"][field], 0)
                    self.assertEqual(result["resources"]["loans_started"], result["resources"]["loans_ended"])

    def test_runtime_sized_chains_release_payload_and_node_storage(self):
        for case in cases():
            if case["id"] in {"lifo-pop-loop-5000", "iterative-drop-loop-5000"}:
                with self.subTest(case=case["id"]):
                    resources = reference(case)["resources"]
                    self.assertEqual(resources["chain_nodes_created"], 5000)
                    self.assertEqual(resources["chain_nodes_dropped"], 5000)
                    self.assertEqual(resources["allocations"], 10000)
                    self.assertEqual(resources["frees"], 10000)

    def test_independent_flow_inputs_close_chain_roots_and_nested_loans(self):
        rows = flow_cases()
        self.assertEqual(len(rows), 14)
        for case in rows:
            with self.subTest(case=case["id"]):
                resources = reference(case)["resources"]
                for field in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
                    self.assertEqual(resources[field], 0)

    def test_invalid_core_stays_distinct_from_valid_profile_exclusions(self):
        rows, outside = refusals(), profile_refusal_ids()
        self.assertEqual(len(rows), 59)
        self.assertEqual(len(outside), 3)
        expanded = flow_name_cases()
        self.assertEqual(len(expanded), 15)
        self.assertEqual(set(rows) | {r["id"] for r in expanded}, set(historical_flow_refusals()))
        for case in expanded:
            self.assertEqual(reference(case)["result"], case["expected_result"])
        for name, source in rows.items():
            with self.subTest(case=name):
                if name in outside:
                    assemble_program(source)
                else:
                    with self.assertRaises(HIAProgramRejected):
                        assemble_program(source)

    def test_resource_block_parameters_reach_the_exact_ssa_boundary(self):
        rows = parameter_cases()
        self.assertEqual(len(rows), 4)
        for case in rows:
            with self.subTest(case=case["id"]):
                result = reference(case)
                self.assertEqual(result["status"], "returned")
                self.assertEqual(result["result"], case["expected_result"])

    def test_high_resource_parameter_names_are_valid_core_profile_exclusions(self):
        rows = parameter_name_cases()
        self.assertEqual(len(rows), 24)
        self.assertEqual({r["id"] for r in rows}, set(historical_parameter_refusals()))
        self.assertEqual(parameter_refusals(), {})
        for case in rows:
            with self.subTest(case=case["id"]):
                self.assertEqual(reference(case)["result"], case["expected_result"])


class ChainAllocatorChildBoundaryTests(unittest.TestCase):
    def test_dumpable_setup_and_readback_fail_before_loading_a_fixture(self):
        import errno
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from types import SimpleNamespace
        from unittest.mock import Mock, call, patch
        from tools import hia_selfhost_chain_allocator_child as child

        for name, results in (("set-failed", [-1]), ("still-dumpable", [0, 1]),
                              ("readback-failed", [0, -1])):
            with self.subTest(name=name), TemporaryDirectory() as temporary:
                request = Path(temporary) / "request.json"
                request.write_text(json.dumps({}))
                library = SimpleNamespace(prctl=Mock(side_effect=results))
                with patch.object(child.sys, "argv", ["child", str(request)]), \
                     patch.object(child.resource, "setrlimit") as limit, \
                     patch.object(child.ctypes, "CDLL", return_value=library), \
                     patch.object(child.ctypes, "get_errno", return_value=errno.EPERM):
                    with self.assertRaises(OSError) as raised:
                        child.main()
                self.assertEqual(raised.exception.errno, errno.EPERM)
                self.assertEqual(library.prctl.call_args_list,
                    [call(4, 0, 0, 0, 0)] + ([] if len(results) == 1 else [call(3, 0, 0, 0, 0)]))
                limit.assert_called_once_with(child.resource.RLIMIT_CORE, (0, 0))
                self.assertEqual(list(Path(temporary).iterdir()), [request])

    def test_actual_child_disables_dumpability_before_native_entry(self):
        from hashlib import sha256
        import json
        from pathlib import Path
        import shutil
        import subprocess
        import sys
        from tempfile import TemporaryDirectory
        from tools import hia_selfhost_chain_allocator_child as child

        if sys.platform != "linux" or shutil.which("cc") is None:
            self.skipTest("the allocator witness requires Linux and its explicit C test compiler")
        source = r"""
#include <stdint.h>
#include <sys/prctl.h>
void hia_test_begin(uint64_t a, void *b, void *c, uint64_t d) {
    (void)a; (void)b; (void)c; (void)d;
}
uint64_t f0(const void *input, uint64_t input_len, unsigned char *output,
            uint64_t output_len, void *workspace, uint64_t workspace_len) {
    (void)input; (void)input_len; (void)workspace; (void)workspace_len;
    int dumpable = prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
    if (output_len) output[0] = (unsigned char)dumpable;
    return dumpable < 0 ? 1 : 0;
}
"""
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            fixture_source, image = directory / "probe.c", directory / "probe.so"
            fixture_source.write_text(source)
            subprocess.run([shutil.which("cc"), "-std=c11", "-O2", "-shared", "-fPIC",
                "-Wall", "-Wextra", "-Werror", str(fixture_source), "-o", str(image)],
                check=True, capture_output=True, timeout=20)
            request = directory / "request.json"
            output, counters = directory / "output.bin", directory / "counters.bin"
            request.write_text(json.dumps({"image": str(image),
                "image_sha256": sha256(image.read_bytes()).hexdigest(), "allocation_fail_at": 0,
                "event_capacity": child.EVENT_CAPACITY, "output": str(output),
                "counters": str(counters), "return_encoding": "zero-extended-u32"}))
            process = subprocess.run([sys.executable, "-I", "-B", child.__file__, str(request)],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=20, cwd=directory)
            self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
            observed = json.loads(process.stdout)
            self.assertEqual(observed["status"], "returned")
            self.assertEqual(observed["core_u32"], 0)
            self.assertEqual(observed["forbidden_compiler_modules_loaded"], [])
            self.assertEqual(output.read_bytes(), b"\x00" + b"\xa5" * 7)
            self.assertEqual(counters.stat().st_size, child.STATS_BYTES)


if __name__ == "__main__":
    unittest.main()
