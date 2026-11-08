"""Real fixed-Core self-hosting, independently observable machine behavior."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import platform
import shutil
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected
from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, SAMPLE, SOURCE,
    compile_stage, invalid_sources, invoke, mutate_compiler, qualify, readonly_call_source,
    inspect_selfhost_object)
from tools.hia_selfhost_contract import validate_contract
from tools.hia_selfhost_limits import MAX_INSTRUCTIONS
from tools.hia_selfhost_cases import (backward_bytesum_source, backward_chain_source,
                                     call_graph_invalid_sources, recursion_refusals)

NATIVE = platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"} and shutil.which("ld")


class SelfhostSourceTests(unittest.TestCase):
    def test_qualification_phase_merge_requires_complete_disjoint_boolean_results(self):
        from tools.qualify_hia_selfhost import QUALIFICATION_FAMILIES, _merge_qualification_phases
        rows = [({"family": family, "compiler_label": label, "status": "PASS",
                  "checks": {family + "-" + label: True}}, {})
                for family in QUALIFICATION_FAMILIES for label in ("original", "modified")]
        checks = {"generation_chain": True}
        self.assertEqual(len(_merge_qualification_phases(rows, checks)), 20)
        self.assertEqual(len(checks), 21)
        variants = [rows[:-1], [*rows[:-1], rows[0]]]
        for mutation in ("nonboolean", "overwritten", "empty", "inconsistent-status"):
            broken = deepcopy(rows)
            if mutation == "nonboolean":
                broken[-1][0]["checks"] = {"bad": 1}
            elif mutation == "overwritten":
                broken[-1][0]["checks"] = {"generation_chain": True}
            elif mutation == "empty":
                broken[-1][0]["checks"] = {}
            else:
                broken[-1][0]["status"] = "FAIL"
            variants.append(broken)
        for broken in variants:
            original = {"generation_chain": True}
            with self.assertRaises(AssertionError):
                _merge_qualification_phases(broken, original)
            self.assertEqual(original, {"generation_chain": True})
        failed = deepcopy(rows)
        failed[-1][0]["status"] = "FAIL"
        failed[-1][0]["checks"] = {"actual_failure": False}
        accepted = {}
        _merge_qualification_phases(failed, accepted)
        self.assertFalse(all(accepted.values()))

    def test_qualification_phase_inputs_require_pinned_bytes_and_closed_inventory(self):
        from tools.qualify_hia_selfhost import _read_phase_inputs, qualification_phase
        with tempfile.TemporaryDirectory(prefix="hia-phase-input-") as temporary:
            from hashlib import sha256
            path = Path(temporary) / "input"
            path.write_bytes(b"original bytes")
            identity = {"compiler": {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}}
            self.assertEqual(_read_phase_inputs(identity), {"compiler": b"original bytes"})
            path.write_bytes(b"changed bytes")
            with self.assertRaisesRegex(ValueError, "input changed"):
                _read_phase_inputs(identity)
            request = Path(temporary) / "request.json"
            for value in ({}, {"schema": "hepta.hia.selfhost-phase-request.v1", "family": "unknown",
                              "compiler_label": "original", "directory": temporary,
                              "inputs": {}, "source_manifest_sha256": "0" * 64}):
                request.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "unknown qualification phase"):
                    qualification_phase(request)

    def test_qualification_phase_process_failures_preserve_logs_and_refuse_merge(self):
        from concurrent.futures import Future
        from hashlib import sha256
        from unittest.mock import patch
        from tools import qualify_hia_selfhost as module
        with tempfile.TemporaryDirectory(prefix="hia-phase-failure-") as temporary:
            root = Path(temporary)
            image = root / "inert-image"
            image.write_bytes(b"not executed")
            inputs = {"compiler": {"path": str(image), "sha256": sha256(image.read_bytes()).hexdigest()}}
            for failure in ("nonzero", "missing-report", "wrong-identity"):
                directory = root / failure
                directory.mkdir()

                class FakeProcess:
                    pid = 12345

                    def __init__(self, command, **kwargs):
                        kwargs["stdout"].write(b"retained phase stdout\n")
                        kwargs["stderr"].write(b"retained phase failure\n")
                        if failure == "wrong-identity":
                            Path(command[-1]).write_text(json.dumps({
                                "schema": "hepta.hia.selfhost-phase.v1", "family": "bulk",
                                "compiler_label": "original", "worker_pid": self.pid,
                                "source_manifest_sha256": "different source"}))

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        pass

                    def wait(self):
                        return 1 if failure == "nonzero" else 0

                with patch.object(module, "_phase_inputs", return_value=inputs), \
                        patch.object(module.subprocess, "Popen", FakeProcess), \
                        self.assertRaises(AssertionError):
                    module._run_qualification_phase(directory, "bulk", "original", image, "0" * 64)
                stem = directory / "phase-bulk-original"
                self.assertEqual(stem.with_suffix(".stdout.log").read_bytes(), b"retained phase stdout\n")
                self.assertEqual(stem.with_suffix(".stderr.log").read_bytes(), b"retained phase failure\n")
                receipt = json.loads(stem.with_suffix(".process.json").read_text())
                self.assertEqual(receipt["returncode"], 1 if failure == "nonzero" else 0)
                self.assertTrue(stem.with_suffix(".request.json").is_file())
                self.assertTrue((directory / "phase-runs/bulk-original").is_dir())
            scheduled = []
            for family, outcome in (("capacity", RuntimeError("first phase failed")),
                                    ("cfg", FileNotFoundError("second phase failed before launch")),
                                    ("elf", ({"status": "PASS"}, {}))):
                future = Future()
                if isinstance(outcome, Exception):
                    future.set_exception(outcome)
                else:
                    future.set_result(outcome)
                scheduled.append((family, "original", future))
            with self.assertRaisesRegex(AssertionError, "qualification_phase_exceptions"):
                module._collect_qualification_phases(root, scheduled)
            index = json.loads((root / "phase-index.json").read_text())
            self.assertEqual(index["completed"], 3)
            self.assertEqual(index["exceptions"], 2)
            self.assertEqual([row["state"] for row in index["phases"]], ["exception", "exception", "completed"])
            self.assertEqual([row["exception_message"] for row in index["phases"][:2]],
                             ["first phase failed", "second phase failed before launch"])

    def test_complete_compiler_is_valid_core_and_reproducible_source(self):
        from tools.generate_hia_selfhost import document
        source = SOURCE.read_bytes()
        checked = assemble_program(source)
        doc, names = document()
        self.assertEqual(render_assembly(checked).encode(), source)
        self.assertEqual(render_assembly(doc).encode(), source)
        self.assertEqual(names["compile"], "f0")
        self.assertEqual(names["wrapper"], validate_contract()["compiler_symbols"]["mutation_wrapper"])
        self.assertTrue(any(int(o["attrs"]["function"][1:]) < int(f["name"][1:])
            for f in doc["functions"] for b in f["blocks"] for o in b["ops"] if o["op"] == "call"))
        self.assertGreater(len(source), 200000)
        self.assertLess(sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]), MAX_INSTRUCTIONS)
        self.assertLessEqual(sum(len(f["blocks"]) for f in doc["functions"]), 1536)
        self.assertLessEqual(max(len(f["blocks"]) for f in doc["functions"]), 256)
        import re
        self.assertLessEqual(max(map(int, re.findall(rb"\bv(\d+)", source))), 2047)
        self.assertLessEqual(max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]), 16)

    def test_compiler_itself_fits_declared_per_function_block_and_ssa_limits(self):
        # General Core accepts larger functions than this native input profile.
        # Total instruction/block counts alone do not make its own source admissible.
        doc = assemble_program(SOURCE.read_bytes()).as_dict()
        limits = validate_contract()["limits"]
        self.assertLessEqual(len(doc["functions"]), limits["functions"])
        for function in doc["functions"]:
            with self.subTest(function=function["name"]):
                self.assertLessEqual(len(function["blocks"]), limits["blocks_per_function"])
                values = list(function["params"])
                for block in function["blocks"]:
                    values.extend(block["params"])
                    values.extend(value for op in block["ops"] for value in op["out"])
                self.assertLessEqual(max(int(value["name"][1:]) for value in values), limits["ssa_index_max"])

    def test_codegen_mutation_is_valid_core_and_changes_one_literal(self):
        source = SOURCE.read_bytes()
        changed = mutate_compiler(source)
        assemble_program(changed)
        self.assertEqual(len(source), len(changed))
        self.assertEqual(sum(a != b for a, b in zip(source, changed)), 2)

    def test_native_rejection_fixtures_also_fail_independent_core_frontend(self):
        for label, source in invalid_sources(SAMPLE.read_bytes()).items():
            with self.subTest(label=label), self.assertRaises(HIAProgramRejected):
                assemble_program(source)

    def test_readonly_alias_rules_distinguish_calls_from_linear_edges(self):
        assemble_program(readonly_call_source())
        invalid = invalid_sources(SAMPLE.read_bytes())
        for name in ("readonly-jump-alias", "readonly-branch-alias"):
            with self.subTest(case=name), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_RESOURCE"):
                assemble_program(invalid[name])

    def test_resource_reference_and_refusals_are_independent_core_observations(self):
        from tools.hia_selfhost_resources import independent_resource_reference
        result = independent_resource_reference()
        self.assertEqual(len(result["cases"]), 9)
        self.assertEqual(sum(row["trap"] for row in result["cases"]), 5)
        self.assertEqual(len(result["rejections"]), 5)
        for row in result["cases"]:
            self.assertEqual(row["reference_result"]["status"], "trapped" if row["trap"] else "returned")

    def test_call_graph_admission_distinguishes_general_core_from_fixed_profile(self):
        assemble_program(backward_bytesum_source(SAMPLE.read_bytes()))
        assemble_program(backward_chain_source())
        for name, source in recursion_refusals().items():
            with self.subTest(case=name):
                assemble_program(source)  # valid general Core; outside this bounded recursive profile
        for name, source in call_graph_invalid_sources(SAMPLE.read_bytes()).items():
            with self.subTest(case=name), self.assertRaises(HIAProgramRejected):
                assemble_program(source)

    def test_tail_reference_uses_real_recursion_and_preserves_vm_budget_refusal(self):
        from tools.hia_selfhost_tailcalls import independent_tail_reference
        result = independent_tail_reference()
        self.assertEqual(len(result["scalar_cases"]), 5)
        self.assertEqual(len(result["buffer_cases"]), 3)
        self.assertEqual(len(result["rejections"]), 6)
        self.assertEqual(sum(r["general_core"] == "accepted" for r in result["rejections"]), 3)
        self.assertEqual(result["deep_case"]["reference_result"]["status"], "budget_exceeded")
        self.assertGreater(result["deep_case"]["native_frame_bytes"] * result["deep_case"]["count"], 8 << 20)

    def test_expanded_capacity_has_independent_execution_and_exact_structural_boundary(self):
        from tools.hia_selfhost_capacity import independent_capacity_reference
        from tools.hia_selfhost_limits import MAX_CORE_NODES
        rows = {row["case"]: row for row in independent_capacity_reference()["observations"]}
        maximum = rows["instructions-" + str(MAX_INSTRUCTIONS)]
        self.assertEqual(maximum["expected_result"], 8176)
        self.assertEqual(maximum["reference_result"]["result"], 8176)
        self.assertEqual(rows["instructions-" + str(MAX_INSTRUCTIONS + 1)]["general_core"], "accepted")
        self.assertEqual(rows["structural-nodes-" + str(MAX_CORE_NODES)]["general_core"], "accepted")
        self.assertEqual(rows["structural-nodes-" + str(MAX_CORE_NODES + 1)]["code"], "E_HIA_LIMIT")
        self.assertEqual(rows["structural-alloc-nodes-" + str(MAX_CORE_NODES)]["general_core"], "accepted")
        self.assertEqual(rows["structural-alloc-nodes-" + str(MAX_CORE_NODES + 1)]["code"], "E_HIA_LIMIT")

    def test_select_reference_covers_all_scalar_types_and_rejects_bad_signatures(self):
        from tools.hia_selfhost_select import independent_select_reference
        result = independent_select_reference()
        self.assertEqual(len(result["cases"]), 64)
        self.assertEqual(len(result["rejections"]), 13)
        self.assertEqual({row["type"] for row in result["cases"]}, {"u8", "u32", "u64", "usize", "bool"})
        for typ in ("u8", "u32", "u64", "usize", "bool"):
            self.assertEqual({row["condition"] for row in result["cases"] if row["type"] == typ}, {False, True})

    def test_loan_reference_covers_live_capability_graphs_and_lifecycle_refusals(self):
        from tools.hia_selfhost_loans import independent_loan_reference
        result = independent_loan_reference()
        self.assertEqual(len(result["cases"]), 23)
        self.assertEqual(len(result["rejected"]), 39)
        self.assertEqual(len(result["outside_profile"]), 6)
        names = {row["id"] for row in result["cases"]}
        self.assertTrue({"loan-through-loop-backedge", "incoming-from-later-source-block",
                         "root-parent-index-fifteen", "nested-graph-through-permuted-edge"} <= names)
        self.assertTrue(all(row["reference_result"]["status"] == "returned" for row in result["cases"]))
        codes = {row["id"]: row["code"] for row in result["rejected"]}
        for name in ("merge-disagrees-root", "merge-disagrees-parent", "end-parent-before-child"):
            self.assertEqual(codes[name], "E_HIA_LOAN")
        self.assertFalse(result["claims"]["all_input_proof"])

    def test_cfg_worklist_preserves_the_review_subjects_and_block_boundaries(self):
        from hashlib import sha256
        from tools.hia_selfhost_cfg_worklist import reverse_source, future_capability_source, cases
        subjects = (
            (reverse_source(), "5d26b74b3609f213e5205e22a68ad9b284ff4643fcf2fc8b60c439d85dd3b555"),
            (reverse_source(loan=True), "2e42fb643c05d95ff9860d1f9d967f3214c0fa58b7266746b615b6a20f804ede"),
            (future_capability_source(), "13346fbc7217cdce1c449a0b1d38de6f1ccfcf6eeb6db2a6cddc88365889b2fb"),
        )
        for source, expected in subjects:
            self.assertEqual(sha256(source).hexdigest(), expected)
        for source, _ in subjects[:2]:
            function = assemble_program(source).as_dict()["functions"][0]
            self.assertEqual(len(function["blocks"]), 256)
            self.assertEqual(function["blocks"][0]["term"]["target"], "b255")
            for index in range(2, 256):
                self.assertEqual(function["blocks"][index]["term"]["target"], "b" + str(index - 1))
        boundary = next(row for row in cases() if row["id"] == "reverse-1536-six-functions")
        functions = assemble_program(boundary["source"].encode()).as_dict()["functions"]
        self.assertEqual([len(fn["blocks"]) for fn in functions], [256] * 6)

    def test_cfg_worklist_reference_covers_replays_and_late_join_refusals(self):
        from tools.hia_selfhost_cfg_worklist import independent_reference
        result = independent_reference()
        self.assertEqual(len(result["cases"]), 12)
        self.assertEqual(len(result["refusals"]), 14)
        self.assertTrue(all(row["reference_result"]["status"] == "returned" for row in result["cases"]))
        codes = {row["id"]: row["code"] for row in result["refusals"]}
        for name in ("late-inconsistent-root-join", "late-inconsistent-parent-join",
                     "queued-owner-consumed-with-live-child"):
            self.assertEqual(codes[name], "E_HIA_LOAN")
        self.assertFalse(result["all_input_correctness_or_performance_proved"])


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld seed linker required")
class SelfhostNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-selfhost-test-")
        cls.output = Path(cls.temporary.name) / "qualification.json"
        cls.report = qualify(cls.output)
        cls.directory = cls.output.with_suffix(".evidence")
        cls.compiler = cls.directory / "B3.image.bin"

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_B1_B2_B3_are_executed_self_compilations(self):
        self.assertEqual(self.report["status"], "SELF_HOSTED_FIXED_CORE_PASS", self.report["checks"])
        generations = self.report["generations"]
        self.assertEqual(len(generations), 3)
        self.assertEqual(len({x["produced_sha256"] for x in generations}), 1)
        for generation in generations:
            self.assertEqual(generation["input_sha256"], self.report["source_sha256"])
            self.assertGreater(generation["produced_bytes"], 300000)
            self.assertEqual(generation["workspace_header"]["48"], 2)
            self.assertEqual(generation["forbidden_compiler_modules_loaded"], [])
        for earlier, later in zip(generations, generations[1:]):
            self.assertEqual(earlier["produced_sha256"], later["artifact_sha256"])
        scheduling = self.report["qualification_scheduling"]
        self.assertEqual(scheduling["maximum_host_oracle_workers"], 2)
        self.assertTrue(scheduling["fresh_seed_and_generation_chain_sequential"])
        self.assertFalse(scheduling["native_child_processes_reused"])
        self.assertEqual(len(scheduling["phase_inventory"]), 20)
        self.assertEqual(len(scheduling["phases"]), 20)
        intervals = []
        for phase in scheduling["phases"]:
            self.assertEqual(phase["returncode"], 0)
            self.assertEqual(phase["command"][1:4], ["-I", "-S", "-B"])
            intervals += [(phase["started_monotonic_ns"], 1), (phase["completed_monotonic_ns"], -1)]
        active = 0
        for _, delta in sorted(intervals):
            active += delta
            self.assertLessEqual(active, 2)
        self.assertEqual(active, 0)

    def test_loans_keep_live_graphs_through_native_original_and_mutated_compilers(self):
        selected = {name: value for name, value in self.report["checks"].items()
                    if name.startswith(("original-loan-", "modified-loan-"))}
        self.assertEqual(len(selected), 142)
        self.assertTrue(all(selected.values()), [name for name, value in selected.items() if not value])

    def test_cfg_worklist_checks_reverse_order_replays_and_refusals_with_both_compilers(self):
        selected = {name: value for name, value in self.report["checks"].items()
                    if name.startswith(("original-cfg-worklist-", "modified-cfg-worklist-"))}
        self.assertEqual(len(selected), 52)
        self.assertTrue(all(selected.values()), [name for name, value in selected.items() if not value])
        reference = self.report["independent_cfg_worklist_reference"]
        self.assertEqual(len(reference["cases"]), 12)
        self.assertEqual(len(reference["refusals"]), 14)
        for row in self.report["cfg_worklist_observations"]:
            observed = row.get("build", row)
            self.assertEqual(observed["limits"]["cpu_seconds"], 10)
            self.assertEqual(observed["limits"]["workspace_bytes"], 1048576)

    def test_native_capacity_boundary_and_original_modified_node_accounting(self):
        from tools.hia_selfhost_capacity import count_nodes
        from tools.hia_selfhost_limits import MAX_CORE_NODES
        nodes = count_nodes(assemble_program(SOURCE.read_bytes()).as_dict())
        for generation in self.report["generations"]:
            self.assertEqual(generation["workspace_header"]["248"], nodes)
        for name, accepted in self.report["checks"].items():
            if "-capacity-" in name:
                self.assertTrue(accepted, name)
        rows = {r["case"]: r for r in self.report["expanded_capacity_observations"]}
        for compiler in ("original", "modified"):
            limit = rows[compiler + "-capacity-" + str(MAX_INSTRUCTIONS)]
            self.assertEqual(limit["workspace_header"]["112"], MAX_INSTRUCTIONS)
            self.assertGreater(limit["produced_bytes"], 100000)
            rejected = rows[compiler + "-capacity-over-limit"]
            self.assertEqual(rejected["core_u32"], INVALID)
            self.assertTrue(rejected["output_unchanged"])
            for prefix in ("-capacity-nodes-", "-capacity-alloc-nodes-"):
                allowed = rows[compiler + prefix + str(MAX_CORE_NODES)]
                self.assertEqual(allowed["core_u32"], NO_SPACE)
                self.assertEqual(allowed["workspace_header"]["248"], MAX_CORE_NODES)
                self.assertEqual(allowed["workspace_header"]["40"], 0)
                refused = rows[compiler + prefix + str(MAX_CORE_NODES + 1)]
                self.assertEqual(refused["core_u32"], INVALID)
                self.assertEqual(refused["workspace_header"]["248"], MAX_CORE_NODES + 1)
                self.assertEqual(refused["workspace_header"]["40"], 58)
                for observed in (allowed, refused):
                    self.assertTrue(observed["output_unchanged"])
                    self.assertTrue(observed["source_unchanged"])

    def test_modified_emitter_propagates_and_rebuilds_modified_self(self):
        m1, m2, m3 = self.report["modified_generations"]
        self.assertNotEqual(m1["produced_sha256"], m2["produced_sha256"])
        self.assertEqual(m2["produced_sha256"], m3["produced_sha256"])
        self.assertNotEqual(m3["produced_sha256"], self.report["generations"][2]["produced_sha256"])
        self.assertTrue(self.report["checks"]["modified_wrapper_machine_bytes"])
        for name, good in self.report["checks"].items():
            if "behavior" in name:
                self.assertTrue(good, name)

    def test_bad_sources_and_small_output_never_write_output(self):
        for result in self.report["rejection_observations"]:
            self.assertEqual(result["core_u32"], INVALID, result)
            self.assertTrue(result["output_unchanged"], result)
        for result in self.report["capacity_observations"]:
            self.assertEqual(result["core_u32"], NO_SPACE, result)
            self.assertTrue(result["output_unchanged"], result)

    def test_native_edges_reject_readonly_duplicates_but_calls_keep_legal_aliases(self):
        rejected = {row["case"]: row for row in self.report["rejection_observations"]}
        for name in ("readonly-jump-alias", "readonly-branch-alias"):
            result = rejected["reject-" + name]
            self.assertEqual(result["core_u32"], INVALID, result)
            self.assertTrue(result["output_unchanged"], result)
        self.assertTrue(self.report["checks"]["readonly_call_alias_remains_legal"])
        self.assertEqual(self.report["readonly_call_observations"][1]["core_u32"], 28)

    def test_backward_calls_and_full_depth_execute_in_original_and_modified_compilers(self):
        for compiler in ("original", "modified"):
            self.assertTrue(self.report["checks"][compiler + "_128_function_backward_chain"])
            for index in range(3):
                self.assertTrue(self.report["checks"][compiler + "_backward_call_behavior_" + str(index)])
        self.assertTrue(self.report["checks"]["own_compiler_uses_backward_direct_calls"])
        references = self.report["independent_core_reference"]["general_core_observations"]
        self.assertEqual(references[-1]["result"], 127)

    def test_non_tail_recursion_and_bad_backward_signatures_are_transactionally_refused(self):
        results = [row for row in self.report["call_graph_observations"] if "-reject-" in row["case"]]
        self.assertEqual(len(results), 14)
        for result in results:
            self.assertEqual(result.get("core_u32"), INVALID, result)
            self.assertTrue(result.get("output_unchanged"), result)
            self.assertTrue(result.get("source_unchanged"), result)
        differences = self.report["independent_core_reference"]["admission_differences"]
        self.assertEqual(sum(row["general_core"] == "accepted" for row in differences), 3)

    def test_tail_self_calls_bootstrap_and_keep_frame_resource_and_capacity_boundaries(self):
        self.assertTrue(self.report["checks"]["own_compiler_uses_direct_tail_self_calls"])
        for name, accepted in self.report["checks"].items():
            if "-tail-" in name:
                self.assertTrue(accepted, name)
        rejections = [r for r in self.report["tail_call_observations"] if "-tail-refuse-" in r["case"]]
        self.assertEqual(len(rejections), 12)
        for result in rejections:
            self.assertEqual(result["core_u32"], INVALID)
            self.assertTrue(result["output_unchanged"])

    def test_hia_writes_elf_objects_that_link_and_rebuild_the_compiler(self):
        rows = [row for row in self.report["elf_object_observations"] if "inventory" in row]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["inventory"]["exports"], ["f0"])
            self.assertEqual(row["inventory"]["undefined_symbols"], [])
            self.assertEqual(row["inventory"]["external_relocations"], [])
            self.assertTrue(row["inventory"]["nonexecuting_stack_note"])
        for name, accepted in self.report["checks"].items():
            if "elf" in name:
                self.assertTrue(accepted, name)
        self.assertTrue(self.report["claims"]["HIA_successor_ELF_writer_used"])
        self.assertFalse(self.report["claims"]["Python_successor_ELF_writer_used"])
        self.assertFalse(self.report["claims"]["external_linker_in_flat_bootstrap_chain"])
        self.assertFalse(self.report["claims"]["python_parser_or_codegen_in_successor_compilation"])
        self.assertTrue(self.report["claims"]["host_reference_codegen_after_B0"])
        self.assertTrue(self.report["claims"]["python_parser_or_codegen_after_B0"])
        self.assertTrue(self.report["claims"]["external_assembler_after_B0"])
        self.assertFalse(self.report["claims"]["external_assembler_in_successor_compilation"])
        self.assertTrue(self.report["claims"]["host_native_fixture_compilation_after_B0"])

    def test_independent_elf_inspector_refuses_changed_class_flags_symbols_and_extent(self):
        row = next(row for row in self.report["elf_object_observations"]
                   if row["case"] == "original-elf-bytesum")
        data = Path(row["compilation"]["produced_image"]).read_bytes()
        shoff = struct.unpack_from("<Q", data, 40)[0]
        symoff = struct.unpack_from("<Q", data, shoff + 2 * 64 + 24)[0]
        for label, offset, replacement in (("class", 4, b"\x01"),
                ("executable-stack", shoff + 5 * 64 + 8, struct.pack("<Q", 4)),
                ("undefined-f0", symoff + 48 + 6, b"\0\0"),
                ("bad-header-extent", 40, struct.pack("<Q", len(data)))):
            with self.subTest(case=label), self.assertRaises(ValueError):
                inspect_selfhost_object(data[:offset] + replacement + data[offset + len(replacement):])

    def test_swap_effects_bounds_refusals_and_trap_observer_positive_control(self):
        rows = self.report["resource_observations"]
        observations = [r for r in rows if "shared_output_observation" in r]
        self.assertEqual(len(observations), 20)
        for result in observations:
            self.assertTrue(result["shared_output_observation"]["available"], result)
            if result["status"] == "child_failed":
                self.assertEqual(result["returncode"], -4)
                # The positive control stores before a trapping swap; its
                # mutation must remain observable when the child has died.
                self.assertEqual(result["shared_output_observation"]["unchanged"],
                                 not result["case"].endswith("observer-control"), result)
        for name, accepted in self.report["checks"].items():
            if "swap" in name:
                self.assertTrue(accepted, name)

    def test_generated_byte_bounds_and_checked_shift_really_trap(self):
        sample = self.directory / "original-bytesum.image.bin"
        result, _ = invoke(self.directory, "bounds-trap", sample, b"x", capacity=0, workspace_size=1)
        self.assertEqual(result["status"], "child_failed", result)
        self.assertEqual(result["returncode"], -4, result)  # UD2 / SIGILL
        source = SAMPLE.read_bytes().replace(b'{"value":33}', b'{"value":32}').replace(b"int.mul.wrap(v0,v2)", b"int.shl.checked(v0,v2)")
        executable, _ = compile_stage(self.directory, "shift-trap-code", self.compiler, source)
        result, _ = invoke(self.directory, "shift-trap", executable, b"x", capacity=1, workspace_size=1)
        self.assertEqual(result["status"], "child_failed", result)
        self.assertEqual(result["returncode"], -4, result)

    def test_boolean_and_unsigned_comparison_encodings(self):
        cases = [
            '  v3:bool = const() {"value":true}\n'
            '  v4:bool = const() {"value":false}\n'
            '  v5:bool = bool.or(v3,v4)\n'
            '  v6:bool = bool.not(v5)\n'
            '  v7:bool = bool.and(v3,v6)\n',
            '  v3:u64 = const() {"value":18446744073709551615}\n'
            '  v4:u64 = const() {"value":1}\n'
            '  v7:bool = compare.lt(v3,v4)\n',
        ]
        for index, operations in enumerate(cases):
            source = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
                "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n" + operations +
                "  branch v7 b1() b2()\nblock b1()\n"
                '  v8:u32 = const() {"value":1}\n  ret(v8)\nblock b2()\n'
                '  v9:u32 = const() {"value":2}\n  ret(v9)\nend\n').encode()
            executable, _ = compile_stage(self.directory, "bool-code-" + str(index), self.compiler, source)
            result, _ = invoke(self.directory, "bool-" + str(index), executable, b"", capacity=0, workspace_size=0)
            self.assertEqual(result["status"], "returned", result)
            self.assertEqual(result["core_u32"], 2, result)

    def test_width_normalization_uses_real_generated_machine_code(self):
        cases = [("u8", 250, 10, "int.add.wrap", 4),
                 ("u32", 0x80000000, 1, "int.shl.checked", 0),
                 ("u64", 0xffffffffffffffff, 2, "int.add.wrap", 1),
                 ("u64", 0xffffffffffffffff, 63, "int.shr.checked", 1)]
        for index, (typ, left, right, operation, expected) in enumerate(cases):
            source = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
                "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n"
                f'  v3:{typ} = const() {{"value":{left}}}\n'
                f'  v4:{typ} = const() {{"value":{right}}}\n'
                f"  v5:{typ} = {operation}(v3,v4)\n"
                '  v6:u32 = int.cast(v5) {"mode":"wrap"}\n'
                "  ret(v6)\nend\n").encode()
            executable, _ = compile_stage(self.directory, "width-code-" + str(index), self.compiler, source)
            result, _ = invoke(self.directory, "width-" + str(index), executable, b"", capacity=0, workspace_size=0)
            self.assertEqual(result["status"], "returned", result)
            self.assertEqual(result["core_u32"], expected, result)

    def test_native_select_uses_input_dependent_values_and_full_width_outputs(self):
        rows = self.report["select_observations"]
        for compiler in ("original", "modified"):
            cases = [row for row in rows if row["case"].startswith(compiler + "-select-") and "-case-" in row["case"]]
            self.assertEqual(len(cases), 64)
            for row in cases:
                self.assertTrue(self.report["checks"][row["case"]], row)
                self.assertEqual(row["core_u32"], int(row["expected"]) & 0xffffffff)
            for typ in ("u8", "u32", "u64", "usize", "bool"):
                chosen = [row for row in cases if row["type"] == typ]
                self.assertEqual({row["condition"] for row in chosen}, {False, True})
                self.assertGreater(len({row["input_sha256"] for row in chosen}), 1)
                self.assertGreater(len({row["core_u32"] for row in chosen}), 1)
            for key, accepted in self.report["checks"].items():
                if key.startswith(compiler + "-select-"):
                    self.assertTrue(accepted, key)


if __name__ == "__main__":
    unittest.main()
