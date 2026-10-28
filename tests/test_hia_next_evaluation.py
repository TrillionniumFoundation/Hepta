"""Regression checks for the registered follow-up's actual evaluation boundaries."""
from copy import deepcopy
import json
import os
import shutil
from pathlib import Path
import unittest
from unittest import mock
import tempfile
import tarfile

from tools import qualify_hia_optimizer_bench as bench
from tools import qualify_hia_agent_holdout as holdout
from tools import qualify_hia_batch_study as batch
from tools.qualify_hia_edit_study import ARMS
from experiments.hia_optimizer_eval.next_20261028 import upgrade_pilot as upgrade
from experiments.hia_optimizer_eval.next_20261028 import run_agent, archive_run


class NextBenchmarkTests(unittest.TestCase):
    def test_original_and_guarded_arms_pair_with_every_strong_baseline(self):
        policy = bench.next_protocol()
        order = bench.sample_order(policy, policy["backends"])
        self.assertEqual(len(order), 98)
        self.assertEqual(len(set(order)), 98)
        self.assertEqual(policy["backends"], ["hia_original", "hia_verified", *bench.BACKENDS[1:]])
        self.assertFalse(set(policy["holdout_sizes"]) & set(policy["training_sizes"]))
        self.assertFalse(set(policy["holdout_seeds"]) & set(policy["training_seeds"]))
        self.assertIn("#define HOLDOUT_SIZE_COUNT 9", bench.workload_header(policy))

    def test_guarded_candidate_still_must_beat_each_baseline_with_no_exclusions(self):
        policy = bench.next_protocol()
        rows = []
        for i, (group, kernel, backend) in enumerate(bench.sample_order(policy, policy["backends"])):
            rows.append({"group": group, "kernel": kernel, "backend": backend, "sample_index": i,
                "status": "measured", "elapsed_ns": 32_000_000, "process_cpu_ns": 31_500_000,
                "process_peak_rss_kib": 4096, "outer_wall_ns": 36_000_000,
                "batch_ns": [1_000_000] * 31, "checksum": bench.timed_checksum(kernel, protocol=policy)})
        good = bench.evaluate_samples(rows, policy, policy["backends"], "hia_verified")
        self.assertTrue(good["noninferiority_passed"])
        self.assertEqual(len(good["comparisons"]), 12)
        for row in rows:
            if row["backend"] == "hia_verified":
                row["elapsed_ns"] *= 2
                row["batch_ns"] = [n * 2 for n in row["batch_ns"]]
        slow = bench.evaluate_samples(rows, policy, policy["backends"], "hia_verified")
        self.assertTrue(slow["quality_passed"])
        self.assertFalse(slow["noninferiority_passed"])
        self.assertEqual(slow["samples_excluded"], 0)
        self.assertFalse(slow["thresholds_adjusted"])


class NextAgentTests(unittest.TestCase):
    def test_new_seed_changes_hidden_inputs_and_never_changes_primary_prompts(self):
        old, new = holdout.tasks(), holdout.tasks(0x20261028)
        self.assertNotEqual(old[0]["cases"], new[0]["cases"])
        for before, after in zip(old, new):
            self.assertEqual(len(after["cases"]), 77)
            for arm in ARMS:
                self.assertEqual(batch.prompt(before, arm), batch.prompt(after, arm))
        for value in (-1, 2**32, True, "7"):
            with self.assertRaises(ValueError):
                holdout.tasks(value)

    def test_upgrade_hidden_cases_and_references_never_enter_prompt(self):
        for task in upgrade.fixtures():
            changed = deepcopy(task)
            changed["hidden_cases"] = [[17, 23, 41]]
            changed["hidden_expected"] = [777777777777]
            changed["correct_hia"] = {}
            changed["correct_rust"] = {}
            for language in ("hia", "rust"):
                self.assertEqual(upgrade.prompt(task, language), upgrade.prompt(changed, language))
            self.assertFalse({tuple(row) for row in task["public_cases"]} &
                             {tuple(row) for row in task["hidden_cases"]})

    def test_upgrade_changes_both_real_interfaces_and_binds_whole_module(self):
        for task in upgrade.fixtures():
            for language in ("hia", "rust"):
                good = json.dumps({"files": task["correct_" + language]})
                candidate, receipt = upgrade.parse_files(task, language, good)
                if language == "hia":
                    self.assertIsNotNone(receipt)
                    self.assertEqual(len(candidate.as_dict()["functions"]), 2)
                with self.assertRaises(ValueError):
                    upgrade.parse_files(task, language, json.dumps({"files": task["original_" + language]}))
            for mask in (1, 2):
                names = upgrade.FILE_NAMES["hia"]
                files = {name: task[("correct_" if mask & (1 << i) else "original_") + "hia"][name]
                         for i, name in enumerate(names)}
                with self.assertRaises(ValueError):
                    upgrade.parse_files(task, "hia", json.dumps({"files": files}), enforce_contract=False)

    def test_upgrade_rejects_extra_files_external_code_and_unbound_public_api(self):
        task = upgrade.fixtures()[0]
        for payload in (
            {"files": {**task["correct_rust"], "extra.rs": ""}},
            {"files": {**task["correct_rust"], "api.rs": "pub fn wire_length(length:u32)->u64 { std::process::exit(0) }"}},
            {"files": {**task["correct_rust"], "api.rs": "pub fn wire_length(length:u32)->u64 { unsafe { length as u64 } }"}},
        ):
            with self.assertRaises(ValueError):
                upgrade.parse_files(task, "rust", json.dumps(payload))
        files = deepcopy(task["correct_hia"])
        files["client.hia.json"]["returns"] = ["u32"]
        with self.assertRaises(ValueError):
            upgrade.parse_files(task, "hia", json.dumps({"files": files}))

    def test_rust_finite_profile_rejects_paths_comments_turbofish_methods_and_calls(self):
        task = upgrade.fixtures()[0]
        snippets = (
            "std :: process :: exit(0)", "::std::process::exit(0)",
            "std/**/::process::exit(0)", "Vec::<u8>::new()", "Vec :: new()",
            "core :: hint :: spin_loop()", "super::outside()", "crate::main()",
            "println!(123)", "length.to_string()", "drop(length)",
            "(api::wire_length)(length)", "Some(api::wire_length).unwrap()(length)",
            "length /* comment */ as u64", "length // comment\n as u64",
            "let z:Option<Box<u64>>=None; let boxed=z.unwrap_or_default(); (length as u64)+*boxed",
            "let result={wire_length}(length); result", "(0..length as u64).max().unwrap_or(0)",
            "let provider_call=wire_length; provider_call(length)",
        )
        for snippet in snippets:
            files = deepcopy(task["correct_rust"])
            files["api.rs"] = "pub fn wire_length(length:u32)->u64 { " + snippet + "; length as u64 }\n"
            with self.subTest(snippet=snippet), self.assertRaises(ValueError):
                upgrade.parse_files(task, "rust", json.dumps({"files": files}))
        files = deepcopy(task["correct_rust"])
        files["api.rs"] = "pub fn wire_length(length:u32)->u64 { (length as u64).wrapping_add(0) }\n"
        upgrade.parse_files(task, "rust", json.dumps({"files": files}))
        files["api.rs"] = "pub fn wire_length(length:u32)->u64 { let zero:Option<u64>=None; (length as u64).wrapping_add(zero.unwrap_or_default()) }\n"
        upgrade.parse_files(task, "rust", json.dumps({"files": files}))
        window = upgrade.fixtures()[1]
        files = deepcopy(window["correct_rust"])
        files["api.rs"] = "pub fn advance(offset:u32,amount:u32,capacity:u32)->(bool,u32) { let end = (offset as u64) + (amount as u64); let invalid = end > capacity as u64; (!invalid, end as u32) }\n"
        upgrade.parse_files(window, "rust", json.dumps({"files": files}))

    def test_native_rust_caller_refuses_a_changed_public_return_type(self):
        rustc = os.environ.get("HEPTA_RUSTC") or shutil.which("rustc")
        if not rustc:
            self.skipTest("Rust compiler is required for the native public-signature control")
        task = upgrade.fixtures()[0]
        files = deepcopy(task["correct_rust"])
        files["client.rs"] = "use crate::api;\npub fn entrypoint(tag:u32,length:u32,reserved:u32)->u128 { let _ = reserved; (((tag & 255) as u128) << 32) | (api::wire_length(length) as u128) }\n"
        text = json.dumps({"files": files})
        with self.assertRaisesRegex(ValueError, "E_UPGRADE_PUBLIC_INTERFACE"):
            upgrade.parse_files(task, "rust", text)
        with tempfile.TemporaryDirectory() as directory:
            # Bypass front-door API admission solely for this negative control:
            # the actual trusted Rust caller must still refuse the u128 API.
            result = upgrade.build(task, "rust", text, Path(directory) / "bad", "unused-clang", rustc,
                                   enforce_contract=False)
            self.assertFalse(result["native_built"])
            self.assertEqual(result["status"], "compile_rejected")
            self.assertIn("E0308", result["compile"]["stderr"])
            self.assertIn("u128", result["compile"]["stderr"])
            self.assertIn("u64", result["compile"]["stderr"])

    def test_same_core_vm_observes_unreachable_call_and_wrong_arguments(self):
        controls = json.loads((run_agent.HERE / "ADMISSION_CONTROLS.json").read_bytes())
        tasks = {task["id"]: task for task in upgrade.fixtures()}
        for label in ("dead_provider_hia", "wrong_argument_hia"):
            item = next(row for row in controls if row["id"] == label)
            task = tasks[item["task"]]
            core, _ = upgrade.parse_files(task, "hia", json.dumps({"files": item["files"]}))
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "program.hia"; path.write_bytes(core.canonical_bytes)
                rows = upgrade.hia_provider_audit({"core_path": str(path), "core_sha256": core.sha256,
                    "audit_task": task["id"], "audit_provider": task["provider"]}, task["public_cases"])
            self.assertEqual([row["entry_vm"]["result"] for row in rows], task["public_expected"])
            if label == "dead_provider_hia":
                self.assertEqual([row["provider_calls_in_entry"] for row in rows], [0, 0, 0])
                self.assertNotEqual([row["provider_result"] for row in rows],
                    [upgrade.provider_expected(task["id"], case) for case in task["public_cases"]])
            else:
                self.assertEqual([row["provider_calls_in_entry"] for row in rows], [1, 1, 1])
                self.assertFalse(all(row["provider_arguments_match"] for row in rows))

    def test_actual_rust_counter_refuses_correct_entry_with_dead_provider(self):
        rustc = os.environ.get("HEPTA_RUSTC") or shutil.which("rustc")
        if not rustc or not hasattr(os, "memfd_create"):
            self.skipTest("Rust compiler and Linux sealed-executable execution required")
        controls = json.loads((run_agent.HERE / "ADMISSION_CONTROLS.json").read_bytes())
        item = next(row for row in controls if row["id"] == "dead_provider_rust")
        task = upgrade.fixtures()[1]
        with tempfile.TemporaryDirectory() as directory:
            built = upgrade.build(task, "rust", json.dumps({"files": item["files"]}),
                                  Path(directory) / "dead", "unused-clang", rustc)
            self.assertTrue(built["native_built"], built)
            # Exercise the actual kernel and Rust executable even on Python
            # builds whose fcntl module exports none of the Linux seal names.
            try:
                raise ValueError("earlier candidate rejected")
            except ValueError:
                # Recovery while another exception is being handled must not
                # make the sealing helper close its successfully transferred fd.
                with mock.patch.dict(upgrade.fcntl.__dict__):
                    for name in ("F_SEAL_WRITE", "F_SEAL_SHRINK", "F_SEAL_GROW", "F_SEAL_SEAL",
                                 "F_ADD_SEALS", "F_GET_SEALS"):
                        upgrade.fcntl.__dict__.pop(name, None)
                    observed = upgrade.execute(built, task["public_cases"], task["public_expected"])
        self.assertEqual(observed["actual"], task["public_expected"])
        self.assertEqual(observed["seals"] & 15, 15)
        self.assertEqual(observed["provider_call_counts"], [0, 0, 0])
        self.assertFalse(observed["provider_contract_passed"])
        self.assertEqual(observed["status"], "observable_wrong")

    def test_upgrade_refuses_missing_kernel_seals_before_native_execution(self):
        if not hasattr(os, "memfd_create"):
            self.skipTest("Linux sealed-executable admission required")
        from hepta.hia_native_differential import HIADifferentialRejected
        real_fcntl = upgrade.fcntl.fcntl
        get_seals = getattr(upgrade.fcntl, "F_GET_SEALS", 1034)
        def missing_seals(descriptor, command, *arguments):
            return 0 if command == get_seals else real_fcntl(descriptor, command, *arguments)
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "unexecuted-candidate"
            candidate.write_bytes(b"This negative control must never be executed.")
            built = {"native_built": True, "artifact": upgrade.file_identity(candidate)}
            with mock.patch.object(upgrade.fcntl, "fcntl", side_effect=missing_seals), \
                    mock.patch.object(upgrade.subprocess, "run") as child:
                with self.assertRaisesRegex(HIADifferentialRejected, "sealed executable-byte snapshot"):
                    upgrade.execute(built, [], [])
                child.assert_not_called()

    def test_independent_oracle_covers_widening_and_overflow(self):
        self.assertEqual(upgrade.oracle("wire_length_v2", (256, 2**32-1, 17)), 2**32-1)
        self.assertEqual(upgrade.oracle("wire_length_v2", (255, 65536, 0)), (255 << 32) | 65536)
        self.assertEqual(upgrade.oracle("bounded_window_v2", (2**32-1, 1, 2**32-1)), 2**64-1)
        self.assertEqual(upgrade.oracle("bounded_window_v2", (8, 2, 10)), 10)
        tasks = upgrade.fixtures()
        self.assertEqual([len(t["hidden_cases"]) for t in tasks], [110, 160])

    def test_public_feedback_cannot_pick_hidden_diagnostics_from_build_record(self):
        feedback = upgrade.public_feedback({"status": "compile_rejected",
            "compile": {"stderr": "type mismatch"}, "hidden_cases": [[99, 98, 97]],
            "hidden_expected": [123]}, None)
        self.assertEqual(feedback, {"compile_status": "compile_rejected", "compiler_stderr": "type mismatch"})

    def test_registration_has_four_upgrade_and_sixteen_primary_prompt_hashes(self):
        values = run_agent.inventory()
        prompts = run_agent.prompt_inventory(values)
        self.assertEqual(len(prompts["primary"]), 16)
        self.assertEqual(len(prompts["upgrade"]), 4)
        self.assertTrue(all(len(value) == 64 for group in prompts.values() for value in group.values()))


class EvidenceArchiveTests(unittest.TestCase):
    def test_reclamation_happens_only_after_every_raw_member_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "run"; source.mkdir()
            (source / "candidate").write_bytes(bytes([127]) + b"ELF" + b"frozen native bytes")
            (source / "failure.json").write_text('{"status":"observable_wrong"}')
            result = archive_run.pack(source, root / "run.tar.xz", prune_elf=True)
            self.assertTrue(result["all_member_hashes_verified"])
            self.assertEqual(result["member_count"], 2)
            self.assertEqual(result["pruned_elf_files"], ["candidate"])
            self.assertFalse((source / "candidate").exists())
            self.assertTrue((source / "failure.json").exists())
            with tarfile.open(root / "run.tar.xz", "r:xz") as archive:
                self.assertEqual(archive.extractfile("candidate").read(), bytes([127]) + b"ELF" + b"frozen native bytes")
            with self.assertRaises(ValueError):
                archive_run.pack(source, root / "run.tar.xz")


if __name__ == "__main__":
    unittest.main()
