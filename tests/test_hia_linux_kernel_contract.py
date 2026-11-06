"""Independent denominator/claim counterexamples using explicit synthetic files.

No fixture in this module is a Linux image, executed guest or qualification
result. Real Kbuild, native-object and guest checks have separate execution
lanes. These tests challenge whether their receipts can be rebound, truncated
or promoted to a stronger claim by the final read-only assessment.
"""
from __future__ import annotations

from collections import Counter
import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_linux_kernel as contract
from tools.qualify_hia_linux_baseline import create_initramfs, parse_guest_serial, qemu_command, qemu_machine_command


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def binding(path):
    path = Path(path).absolute()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


CONFIG = b"""CONFIG_X86_64=y
CONFIG_64BIT=y
CONFIG_CC_IS_CLANG=y
CONFIG_MITIGATION_RETHUNK=y
CONFIG_FUNCTION_ALIGNMENT=16
"""
CHECKS = ("pid1", "mount_proc", "mount_sysfs", "mount_devtmpfs", "mount_tmpfs",
          "kernel_identity", "cpu_count", "fork_exec_wait", "pipe_roundtrip", "mmap_pages",
          "mprotect_fault", "file_lifecycle", "unix_socketpair", "loopback_tcp")
ARMS = ("linux-stock", "hia-static", "hia-best-fixed", "hia-state-greedy", "hia-ordinary-mpc",
        "hia-same-objective", "hia-fixed-preference-ndu", "hia-dynamic-ndu")


class KernelContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.protocol = json.loads(contract.PROTOCOL.read_bytes())
        self.source = self.root / "synthetic-upstream"
        self.source.mkdir()
        self.manifest_rows = []
        kinds = {".c": "c", ".h": "header", ".S": "asm_cpp", ".s": "asm", ".rs": "rust"}
        for name in ("kernel/a.c", "kernel/b.c", "include/a.h", "arch/entry.S", "rust/a.rs", "Kconfig", "arch/kernel.lds"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("synthetic contract fixture " + name + "\n").encode())
            self.manifest_rows.append({"path": name, "type": "file", "kind": kinds.get(path.suffix, "other"),
                                       "bytes": path.stat().st_size, "lines": 1, "sha256": binding(path)["sha256"]})
        self.manifest_rows.append({"path": "fixture-link", "type": "symlink", "target": "kernel/a.c"})
        self.inventory = self.inventory_for(self.manifest_rows)
        self.baseline = self.stock_fixture()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if type(data) is bytes else canonical(data))
        return binding(path)

    def jsonl(self, name, rows):
        raw = b"".join(canonical(row) + b"\n" for row in rows)
        return {**self.write(name, gzip.compress(raw, mtime=0)), "uncompressed_jsonl_sha256": hashlib.sha256(raw).hexdigest()}

    def inventory_for(self, rows):
        regular = [row for row in rows if row["type"] == "file"]
        counts = Counter(row["kind"] for row in regular)
        return {"schema": "hepta.linux-source-inventory.v1", "kernel_version": "6.18.60",
            "source_archive_sha256": contract.ARCHIVE_SHA256,
            "source_receipt": {"version": "6.18.60", "sha256": contract.ARCHIVE_SHA256,
                               "stable_git_commit": contract.LINUX_COMMIT},
            "source_directory": str(self.source), "scope": "complete_upstream_archive_all_architectures_and_files",
            "regular_files": len(regular), "symlinks": len(rows) - len(regular), "total_files": len(rows),
            "total_bytes": sum(row["bytes"] for row in regular), "files_by_kind": dict(counts),
            "bytes_by_kind": {kind: sum(row["bytes"] for row in regular if row["kind"] == kind) for kind in counts},
            "lines_by_kind": {kind: sum(row["lines"] for row in regular if row["kind"] == kind) for kind in counts},
            "source_files_total": sum(value for key, value in counts.items() if key != "other"),
            "c_source_files_total": counts["c"], "manifest": self.jsonl("source-manifest.jsonl.gz", rows),
            "function_denominator": None, "function_denominator_status": "not_parsed",
            "all_configurations_compiled": False}

    def command(self, name, argv, stdout=b"", exit_code=0):
        return {"name": name, "argv": list(map(str, argv)), "cwd": str(self.root),
                "exit_code": exit_code, "timed_out": False, "elapsed_ns": 10,
                "process_group": 12345,
                "process_group_cleanup": {"group": 12345, "scope": "owned_linux_process_group",
                    "drained": True, "signals": [], "live_members_after": [], "errors": [], "elapsed_ns": 0},
                "stdout": self.write("commands/" + name + ".stdout", stdout),
                "stderr": self.write("commands/" + name + ".stderr", b"")}

    def stock_fixture(self):
        build = self.root / "build"
        self.write("build/.config", CONFIG)
        config = self.write("exact.config", CONFIG)
        kernel = self.write("build/arch/x86/boot/bzImage", b"SYNTHETIC IMAGE FIXTURE; NOT EXECUTABLE")
        linked = self.write("build/vmlinux", b"SYNTHETIC LINK FIXTURE; NOT ELF")
        original = [{"directory": str(self.source), "file": str(self.source / file),
                     "command": command} for file, command in (
                         ("kernel/a.c", "clang -D__KERNEL__ -c kernel/a.c -o a.o"),
                         ("tools/host.c", "clang -c tools/host.c -o host.o"),
                         ("kernel/b.c", "clang -D__KERNEL__ -c kernel/b.c -o b.o"))]
        full_db = self.write("compile_commands.json", original)
        target_db = self.write("target-compile_commands.json", [original[0], original[2]])
        make = self.command("full-kbuild", ["make", "-C", self.source, "O=" + str(build), "ARCH=x86_64",
                                             "LLVM=/synthetic/", "-j2", "vmlinux", "bzImage", "modules"])
        init = self.write("guest/init", b"SYNTHETIC PID1 FIXTURE; NOT EXECUTABLE")
        initrd = self.root / "guest/initramfs.cpio.gz"
        create_initramfs(init["path"], initrd)
        qemu = {**self.write("tools/qemu", b"SYNTHETIC QEMU FIXTURE; NOT EXECUTABLE"),
                "bios": self.write("tools/bios.bin", b"SYNTHETIC BIOS FIXTURE")}
        modules = [self.write("tools/modules/accel-tcg-x86_64.so", b"SYNTHETIC MODULE; NOT EXECUTABLE"),
                   self.write("tools/modules/fixture-module.so", b"SECOND SYNTHETIC MODULE")]
        qemu.update(module_dir=str(self.root / "tools/modules"), modules=modules)
        environment = self.write("build-environment.json", {"QEMU_MODULE_DIR": qemu["module_dir"]})
        preflight = self.command("qemu-tcg-runtime-preflight",
            qemu_machine_command(qemu["path"], self.root / "tools", qemu["bios"]["path"], paused=True),
            b"SYNTHETIC QEMU MONITOR RECORD; NOT EXECUTION\n")
        preflight.update(timeout_seconds=15, stdin=self.write("commands/qemu-tcg-runtime-preflight.stdin", b"quit\n"))
        qemu["runtime_preflight"] = {"status": "PASS", "scope": "paused_tcg_startup_no_kernel_execution", "command_receipt": preflight}
        run_id = "0123456789abcdef01234567"
        events = [{"event": "begin", "run_id": run_id, "pid": 1}]
        events += [{"event": "check", "run_id": run_id, "id": name, "passed": True, "errno": 0} for name in CHECKS]
        events += [{"event": "complete", "run_id": run_id, "total": 14, "passed": 14, "failed": 0},
                   {"event": "shutdown", "run_id": run_id, "operation": "poweroff"}]
        serial = b"\n".join(b"HIA_LINUX_SMOKE " + canonical(event) for event in events) + b"\nreboot: Power down\n"
        argv = qemu_command(qemu["path"], self.root / "tools", qemu["bios"]["path"], kernel["path"], initrd, run_id, "6.18.60")
        boot = self.command("boot-stock-kernel-tcg", argv, serial)
        verdict = parse_guest_serial(serial.decode(), run_id, 0, False)
        source_snapshot = [{key: row[key] for key in (("path", "type", "target") if row["type"] == "symlink"
                           else ("path", "type", "bytes", "sha256"))} for row in self.manifest_rows]
        return {"schema": "hepta.hia.linux.stock-baseline.v1", "status": "PASS", "build_status": "PASS", "boot_status": "PASS",
            "kernel_version": "6.18.60", "source_archive_sha256": contract.ARCHIVE_SHA256,
            "image_kind": "stock_linux", "hia_compiled_units": 0, "active_compile_units": 2, "fallback_c_units": 2,
            "kernel_image": kernel, "vmlinux": linked, "config": config, "config_sha256": config["sha256"],
            "compile_commands": target_db, "compile_commands_sha256": target_db["sha256"],
            "original_compile_commands": full_db, "original_compile_commands_sha256": full_db["sha256"],
            "target_compile_indices": [0, 2], "guest_init": init, "initramfs": binding(initrd), "qemu": qemu,
            "build_environment": environment,
            "run_id": run_id, "commands": [preflight, make, boot], "boot": {**verdict, "command_receipt": boot},
            "guest_tests": verdict["guest_tests"], "linux_source_unchanged": True,
            "linux_source_inventory": self.write("source-before.json.gz", gzip.compress(canonical(source_snapshot), mtime=0)),
            "linux_source_after_inventory": self.write("source-after.json.gz", gzip.compress(canonical(source_snapshot), mtime=0)),
            "source_before": {"commit": "a" * 40, "development_only": False},
            "source_after": {"commit": "a" * 40, "development_only": False}}

    def intake_fixture(self, states=("rejected", "not_run")):
        entries = json.loads(Path(self.baseline["compile_commands"]["path"]).read_bytes())
        self.write("intake/compile_commands.original.json", Path(self.baseline["compile_commands"]["path"]).read_bytes())
        self.write("intake/config.original", CONFIG)
        rows = []
        for index, (entry, state) in enumerate(zip(entries, states)):
            rows.append({"index": index, "original_entry": entry, "entry_sha256": digest(entry),
                "intake_status": state, "declaration_analysis": "complete" if state == "admitted" else "not_reached",
                "hepta_translation": "not_run", "rust_bridge_build": "not_run", "hia_native_build": "not_run",
                "kernel_object": "not_built", "whole_translation_unit_rewritten": False, "source": entry["file"],
                "rejection": {"code": "E_SYNTHETIC_UNSUPPORTED", "message": "fixture unsupported input"},
                "reason": "fixture not attempted after the registered finite budget"})
        counts = Counter(states)
        result = {"schema": "hepta.linux-translation-intake.v1", "status": "blocked" if counts["rejected"] else "intake_completed_not_kernel_built",
            "active_compile_units": 2, "attempted_compile_units": 2 - counts["not_run"], "not_run_compile_units": counts["not_run"],
            "unique_source_files": 2, "intake_status_counts": dict(counts),
            "config_sha256": self.baseline["config_sha256"], "compile_commands_sha256": self.baseline["compile_commands_sha256"],
            "declaration_inventory_complete_units": counts["admitted"], "whole_translation_units_hia_native": 0,
            "hia_compiled_units": 0, "source_files_rewritten": 0, "ndu_calls": 0, "fallback_c_units": 2,
            "fallback_policy": "retained_stock_baseline_not_counted_as_hia", "all_configurations_translated": False,
            "function_denominator": None, "kernel_image": None, "hia_kernel_status": "not_built",
            "per_command_intake_is_full_project_capture": False, "ledger": self.jsonl("intake/translation-units.jsonl.gz", rows)}
        return result, rows

    def registration(self):
        expected = self.protocol["comparison"]
        shared = {name: hashlib.sha256(name.encode()).hexdigest() for name in expected["shared_fields"]}
        budget = {"wall_ns": 1000000, "expanded_actions": 100, "resident_bytes": 1048576}
        arms = [{"id": arm, "shared": dict(shared), "planning_budget": dict(budget),
                 "internal_objective": expected["internal_objectives"][arm],
                 "implementation_sha256": hashlib.sha256(arm.encode()).hexdigest(),
                 **({"native_backend_required": True, "native_backend_sha256": "b" * 64} if arm in ARMS[-2:] else {})} for arm in ARMS]
        workloads = [{"id": name, "regime": name} for name in ("stationary", "adaptive", "misleading_feedback")]
        cells = [{"id": f"{arm}:{work['id']}:holdout-0:0", "arm": arm, "workload": work["id"],
                  "trace_id": "holdout-0", "repeat": 0} for work in workloads for arm in ARMS]
        return {"schema": "hepta.hia.linux-comparison-registration.v1", "protocol_sha256": digest(self.protocol),
            "scope": "whole_config_system", "online_information": {"current_and_past_only": True, "future_tape_visible": False, "holdout_labels_visible": False},
            "holdout_used_for_selection": False, "fixed_selection": "development_or_calibration_ex_ante_once", "shared": shared,
            "planning_budget": budget, "arms": arms, "splits": {"development": ["dev-0"], "calibration": ["cal-0"], "holdout": ["holdout-0"]},
            "costs": {"categories": list(expected["cost_categories"]), "outer_total_required": True, "nested_costs_additive": False,
                      "runtime_compute_debits_real_resources": True, "unknown_lifecycle_costs_reported_unknown": True},
            "workloads": workloads, "planned_cells": cells}

    def component_fixture(self, config=CONFIG):
        """Contract fixture only; native/link proof functions are explicitly mocked.

        Their real object/byte gates are covered in test_hia_linux_component.
        All file, configuration, raw boot and final claim checks here stay real.
        """
        from hepta.hia_linux_kernel import config_profile
        cfg = config_profile(config)
        configuration = self.write("component/exact.config", config)
        native = self.write("component/hia.o", b"SYNTHETIC COMPONENT OBJECT; NOT NATIVE EVIDENCE")
        inspection = {"defined": ["hia_sw_hweight32"], "undefined": ["__x86_return_thunk"] if cfg["rethunk"] else []}
        artifact = {**native, "schema": "hepta.hia.kernel-object.v1", "status": "PASS",
            "profile": "hepta.hia.linux-x86_64-kernel-u32-leaf.v1", "config": cfg,
            "exports": ["hia_sw_hweight32"], "inspection": inspection, "disassembly": "synthetic mocked inspection",
            "core_sha256": "c" * 64, "claims": {"actual_hia_core_to_native_object": True,
                "c_codegen_used": False, "rust_codegen_used": False, "fallback_used": False, "whole_kernel_rewrite": False}}
        prepared = {"schema": "hepta.hia.linux-component.v1", "status": "PASS", "formal_evidence": True,
            "source": {"linux_commit": contract.LINUX_COMMIT, "configuration": configuration,
                       "files": {"kernel/a.c": binding(self.source / "kernel/a.c")}}, "artifact": artifact,
            "native_gate": {"status": "PASS"}, "oracle_diff": {"status": "PASS"},
            "translated_body": {"upstream_function": "__sw_hweight32", "target": "hia_sw_hweight32",
                                "core_sha256": "c" * 64, "authored_translation": True},
            "routing": {"whole_kernel_rewrite": False, "hia_implementation_bodies": 1, "asm_bridge_count": 1,
                "replaced_symbols": ["__sw_hweight32"], "retained": ["__sw_hweight64", "remaining Linux C/assembly/Rust"],
                "hia_body_symbols": ["hia_sw_hweight32"]}, "guest_gate": {"status": "NOT_RUN"}}
        receipt = self.write("component/PREPARED.json", prepared)
        boot = copy.deepcopy(self.baseline)
        boot.update(schema="hepta.hia.linux.component-system-arm.v1", image_kind="hybrid_linux_hia_component",
                    config=configuration, config_sha256=cfg["sha256"])
        boot["kernel_image"] = self.write("component/build/arch/x86/boot/bzImage", b"SYNTHETIC MIXED IMAGE; NOT EXECUTABLE")
        boot["vmlinux"] = self.write("component/build/vmlinux", b"SYNTHETIC MIXED LINK; NOT ELF")
        record = boot["boot"]["command_receipt"]
        record["name"] = "boot-hybrid-kernel-tcg"
        record["argv"][record["argv"].index("-kernel") + 1] = boot["kernel_image"]["path"]
        gate = {"status": "PASS", "kernel_image": boot["kernel_image"], "vmlinux": boot["vmlinux"],
                "serial_log": record["stdout"], "kernel_config": configuration,
                "boot_report": self.write("component/BOOT.json", boot), "build_object": native,
                "applied": self.write("component/APPLIED.json", {"synthetic": True}),
                "executed_symbols": ["hia_sw_hweight32"], "execution_count": 135168,
                "execution_count_kind": "completed_driver_direct_calls"}
        final = {**prepared, "prepared_receipt": receipt, "guest_gate": gate}
        return final, inspection, copy.deepcopy(gate)

    def component_proof_mocks(self, inspection, gate):
        # Explicit proof-interface stubs, never fixture execution or qualification.
        self.addCleanup(patch.stopall)
        object_mock = patch("hepta.hia_linux_kernel.inspect_kernel_object", return_value=inspection).start()
        guest_mock = patch("tools.qualify_hia_linux_component.validate_guest_readback", return_value=gate).start()
        return object_mock, guest_mock

    def assess(self, **changes):
        values = {"protocol": self.protocol, "source_inventory": self.inventory, "baseline": self.baseline}
        values.update(changes)
        return contract.assess_kernel_claims(**values)

    def test_stock_boot_does_not_rewrite_active_c_assembly_or_other_configurations(self):
        result = self.assess()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["global_comparison_status"], "NOT_RUN")
        self.assertEqual({key for key, value in result["claims"].items() if value}, {"stock_kernel_built", "stock_kernel_booted"})
        self.assertEqual(result["denominators"]["upstream_archive_files"], 8)
        self.assertEqual(result["denominators"]["source_suffix_files"], 5)
        self.assertEqual(result["denominators"]["active_config_c_commands"], 2)
        for key in ("active_config_all_kbuild_units", "source_function_count", "linked_symbol_count"):
            self.assertIsNone(result["denominators"][key])

    def test_unknown_early_failure_counts_stay_unknown_and_unrun_tests_stay_planned(self):
        base = {key: value for key, value in self.baseline.items() if key not in ("boot", "commands", "source_after")}
        base.update(status="FAIL", build_status="FAIL", boot_status="NOT_RUN", active_compile_units=None, fallback_c_units=None,
                    guest_tests={"total": 14, "passed": 0, "failed": 0, "skipped": 0, "not_run": 14})
        result = self.assess(baseline=base)
        self.assertIsNone(result["denominators"]["active_config_c_commands"])
        self.assertFalse(any(result["claims"].values()))
        self.assertEqual(result["stock_status"], "FAIL")

    def test_stock_source_integrity_failure_withholds_prior_execution_claims(self):
        self.baseline.update(status="FAIL", linux_source_unchanged=False)
        result = self.assess()
        self.assertFalse(result["claims"]["stock_kernel_built"])
        self.assertFalse(result["claims"]["stock_kernel_booted"])

    def test_suffixed_file_count_cannot_become_a_function_denominator(self):
        self.inventory["function_denominator"] = 5
        self.inventory["function_denominator_status"] = "estimated_from_files"
        with self.assertRaisesRegex(ValueError, "function denominator"):
            self.assess()

    def test_source_manifest_duplicate_suffix_misclassification_or_count_change_rejects(self):
        for kind in ("duplicate", "suffix", "count"):
            with self.subTest(kind=kind):
                inventory = copy.deepcopy(self.inventory)
                rows = copy.deepcopy(self.manifest_rows)
                if kind == "duplicate":
                    rows.append(rows[0])
                elif kind == "suffix":
                    rows[0]["kind"] = "other"
                else:
                    inventory["source_files_total"] += 1
                inventory["manifest"] = self.jsonl(kind + ".jsonl.gz", rows)
                with self.assertRaises(ValueError):
                    self.assess(source_inventory=inventory)

    def test_same_counts_do_not_allow_repaired_or_rebound_archive_members_to_mix_with_stock(self):
        for kind in ("file_sha", "symlink_target", "after_snapshot"):
            with self.subTest(kind=kind):
                baseline = copy.deepcopy(self.baseline)
                key = "linux_source_after_inventory" if kind == "after_snapshot" else "linux_source_inventory"
                rows = json.loads(gzip.decompress(Path(baseline[key]["path"]).read_bytes()))
                if kind == "file_sha":
                    rows[0]["sha256"] = "f" * 64
                else:
                    rows[-1]["target"] = "normalized-but-different-symlink-target"
                baseline[key] = self.write("changed-source-snapshot.gz", gzip.compress(canonical(rows), mtime=0))
                with self.assertRaisesRegex(ValueError, "source snapshot differs"):
                    self.assess(baseline=baseline)

    def test_c_fallback_cannot_be_relabeled_hia_or_whole_kernel(self):
        for key, value in (("image_kind", "hia_kernel"), ("hia_compiled_units", 2)):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.baseline)
                changed[key] = value
                with self.assertRaisesRegex(ValueError, "retained C"):
                    self.assess(baseline=changed)

    def test_original_database_and_target_mapping_are_both_kept(self):
        changed = copy.deepcopy(self.baseline)
        changed["target_compile_indices"] = [0, 1]
        with self.assertRaisesRegex(ValueError, "target C subset"):
            self.assess(baseline=changed)
        target = json.loads(Path(changed["compile_commands"]["path"]).read_bytes())
        target[0]["command"] = target[0]["command"].replace("-D__KERNEL__", "-D__KERNEL__ -DFAKE")
        changed["compile_commands"] = self.write("rebound-target.json", target)
        changed["compile_commands_sha256"] = changed["compile_commands"]["sha256"]
        changed["target_compile_indices"] = [0, 2]
        with self.assertRaisesRegex(ValueError, "target C subset"):
            self.assess(baseline=changed)

    def test_partial_build_and_unbound_config_cannot_pass(self):
        changed = copy.deepcopy(self.baseline)
        next(row for row in changed["commands"] if row["name"] == "full-kbuild")["argv"].remove("modules")
        with self.assertRaisesRegex(ValueError, "partial/failed"):
            self.assess(baseline=changed)
        (self.root / "build/.config").write_bytes(CONFIG + b"CONFIG_FAKE=y\n")
        with self.assertRaisesRegex(ValueError, "configuration differs"):
            self.assess()

    def replace_serial(self, base, serial, update_verdict=False):
        record = base["boot"]["command_receipt"]
        record["stdout"] = self.write("changed-serial.stdout", serial)
        if update_verdict:
            verdict = parse_guest_serial(serial.decode(), base["run_id"], record["exit_code"], record["timed_out"])
            base["boot"] = {**verdict, "command_receipt": record}
            base["boot_status"] = verdict["status"]
            base["guest_tests"] = verdict["guest_tests"]
            base["status"] = "FAIL"

    def test_forged_pass_cannot_survive_missing_terminal_duplicate_check_or_wrong_run_id(self):
        serial = Path(self.baseline["boot"]["command_receipt"]["stdout"]["path"]).read_bytes()
        lines = serial.splitlines(keepends=True)
        candidates = {
            "missing_complete": b"".join(line for line in lines if b'"event":"complete"' not in line),
            "duplicate_check": b"".join(lines[:2] + [lines[1]] + lines[2:]),
            "wrong_run_id": serial.replace(self.baseline["run_id"].encode(), b"1" * 24, 1),
            "missing_poweroff": serial.replace(b"reboot: Power down", b"kernel remained running")}
        for name, changed_serial in candidates.items():
            with self.subTest(name=name):
                base = copy.deepcopy(self.baseline)
                self.replace_serial(base, changed_serial)
                with self.assertRaisesRegex(ValueError, "serial replay"):
                    self.assess(baseline=base)

    def test_real_partial_guest_failure_retains_not_run_denominator(self):
        lines = Path(self.baseline["boot"]["command_receipt"]["stdout"]["path"]).read_bytes().splitlines(keepends=True)
        base = copy.deepcopy(self.baseline)
        self.replace_serial(base, b"".join(lines[:2]), update_verdict=True)
        for key in ("module_dir", "modules", "runtime_preflight"):
            del base["qemu"][key]
        del base["build_environment"]
        base["commands"] = [row for row in base["commands"] if row["name"] != "qemu-tcg-runtime-preflight"]
        result = self.assess(baseline=base)
        self.assertTrue(result["claims"]["stock_kernel_built"])
        self.assertFalse(result["claims"]["stock_kernel_booted"])
        self.assertEqual(base["guest_tests"], {"total": 14, "passed": 1, "failed": 0, "skipped": 0, "not_run": 13})

    def test_wrong_boot_image_run_id_and_guest_program_binding_reject(self):
        for kind in ("image", "run_id", "init"):
            with self.subTest(kind=kind):
                base = copy.deepcopy(self.baseline)
                if kind == "image":
                    argv = base["boot"]["command_receipt"]["argv"]
                    argv[argv.index("-kernel") + 1] = self.write("wrong-image", b"other synthetic image")["path"]
                elif kind == "run_id":
                    base["run_id"] = "1" * 24
                else:
                    base["guest_init"] = self.write("different-init", b"different synthetic program")
                with self.assertRaises(ValueError):
                    self.assess(baseline=base)

    def test_original_qemu_executable_alias_is_valid_only_for_the_exact_bound_binary(self):
        argv = self.baseline["boot"]["command_receipt"]["argv"]
        argv[0] = str(self.root / "tools" / ".." / "tools" / "qemu")
        original = list(argv)
        self.assertTrue(self.assess()["claims"]["stock_kernel_booted"])
        self.assertEqual(argv, original)
        other = self.write("tools/other-qemu", Path(self.baseline["qemu"]["path"]).read_bytes())
        argv[0] = other["path"]
        with self.assertRaisesRegex(ValueError, "executed QEMU binary path differs"):
            self.assess()

    def test_boot_pass_rejects_unbound_modules_omitted_module_or_different_environment(self):
        for kind in ("missing_binding", "changed_hash", "omitted_module", "wrong_environment"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(self.baseline)
                if kind == "missing_binding":
                    del changed["qemu"]["modules"]
                elif kind == "changed_hash":
                    changed["qemu"]["modules"][0]["sha256"] = "0" * 64
                elif kind == "omitted_module":
                    changed["qemu"]["modules"].pop()
                else:
                    changed["build_environment"] = self.write("wrong-environment.json", {"QEMU_MODULE_DIR": "/unbound/host/modules"})
                with self.assertRaises(ValueError):
                    self.assess(baseline=changed)

    def test_boot_pass_rejects_failed_unpaused_or_unbound_runtime_preflight(self):
        for kind in ("failed", "timeout", "unpaused", "wrong_stdin", "missing_command"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(self.baseline)
                preflight = changed["qemu"]["runtime_preflight"]
                record = preflight["command_receipt"]
                if kind == "failed":
                    record["exit_code"] = 1
                elif kind == "timeout":
                    record["timed_out"] = True
                elif kind == "unpaused":
                    record["argv"].remove("-S")
                elif kind == "wrong_stdin":
                    record["stdin"] = self.write("wrong-preflight.stdin", b"cont\nquit\n")
                else:
                    changed["commands"] = [row for row in changed["commands"] if row["name"] != "qemu-tcg-runtime-preflight"]
                with self.assertRaises(ValueError):
                    self.assess(baseline=changed)

    def test_zero_exit_cannot_hide_observed_build_preflight_or_boot_group_failure(self):
        self.assertTrue(self.assess()['claims']['stock_kernel_booted'])
        for name in ('full-kbuild', 'qemu-tcg-runtime-preflight', 'boot-stock-kernel-tcg'):
            for failure in ({'incomplete_process_group': True},
                            {'process_group_cleanup': {'drained': False}},
                            {'interruption': {'type': 'RequestedCancellation', 'message': 'cancelled'}}):
                with self.subTest(command=name, failure=failure):
                    changed = copy.deepcopy(self.baseline)
                    record = next(row for row in changed['commands'] if row['name'] == name)
                    record.update(failure)
                    self.assertEqual(record['exit_code'], 0)
                    with self.assertRaisesRegex(ValueError, 'command process group did not complete'):
                        self.assess(baseline=changed)

    def test_summary_labels_without_raw_boot_receipt_and_fabricated_guest_totals_reject(self):
        for kind in ("no_boot", "omit_not_run", "zero_qemu_exit_without_timeout_check"):
            with self.subTest(kind=kind):
                base = copy.deepcopy(self.baseline)
                if kind == "no_boot":
                    del base["boot"]
                elif kind == "omit_not_run":
                    base["guest_tests"].update(total=13, passed=13)
                else:
                    base["boot"]["command_receipt"]["timed_out"] = True
                with self.assertRaises(ValueError):
                    self.assess(baseline=base)

    def test_c_admission_success_is_not_hia_native_compilation(self):
        intake, _ = self.intake_fixture(("admitted", "admitted"))
        result = self.assess(migration=intake)
        self.assertEqual(result["translation_intake"]["declaration_complete_units"], 2)
        self.assertFalse(result["claims"]["hia_whole_config_translated"])
        self.assertEqual(result["denominators"]["whole_config_hia_native_units"], 0)

    def test_rejected_and_not_run_commands_remain_in_planned_intake(self):
        intake, _ = self.intake_fixture()
        result = self.assess(migration=intake)
        self.assertEqual(result["translation_intake"]["counts"], {"rejected": 1, "not_run": 1})
        self.assertEqual(result["translation_intake"]["active"], 2)
        self.assertIn("REGISTERED_C_COMMANDS_REJECTED_BY_EXISTING_FRONTEND", result["blockers"])

    def test_intake_omission_rebinding_or_fake_hia_count_rejects(self):
        for kind in ("omit", "command", "fallback", "fake_hia", "fake_function"):
            with self.subTest(kind=kind):
                intake, rows = self.intake_fixture()
                if kind == "omit":
                    rows.pop()
                elif kind == "command":
                    rows[0]["original_entry"]["command"] = "clang replacement.c"
                    rows[0]["entry_sha256"] = digest(rows[0]["original_entry"])
                elif kind == "fallback":
                    intake["fallback_c_units"] = 0
                elif kind == "fake_hia":
                    intake["hia_compiled_units"] = 1
                else:
                    intake["function_denominator"] = 100
                intake["ledger"] = self.jsonl("intake/translation-units.jsonl.gz", rows)
                with self.assertRaises(ValueError):
                    self.assess(migration=intake)

    def test_prepared_or_failed_component_does_not_claim_any_guest_execution(self):
        for state in ("PASS", "FAIL"):
            component = {"schema": "hepta.hia.linux-component.v1", "status": state, "guest_gate": {"status": "NOT_RUN"}}
            if state == "PASS":
                component["routing"] = {"whole_kernel_rewrite": False, "hia_implementation_bodies": 1,
                    "asm_bridge_count": 1, "replaced_symbols": ["__sw_hweight32"], "retained": ["__sw_hweight64"]}
            result = self.assess(component=component)
            self.assertFalse(result["claims"]["hia_component_replacement_executed"])
            self.assertEqual(result["component"]["preparation_status"], state)

    def test_named_mixed_component_success_never_promotes_to_whole_config_source_or_ndu(self):
        component, inspection, gate = self.component_fixture()
        object_mock, guest_mock = self.component_proof_mocks(inspection, gate)
        result = self.assess(component=component)
        object_mock.assert_called_once()
        guest_mock.assert_called_once()
        self.assertTrue(result["claims"]["hia_component_replacement_executed"])
        for key in ("hia_whole_config_translated", "hia_kernel_booted", "whole_source_rewrite_established",
                    "global_comparison_completed", "ndu_unique_gain_established"):
            self.assertFalse(result["claims"][key])
        self.assertEqual(result["component"]["bodies"], 1)
        self.assertEqual(result["component"]["asm_bridge_count"], 1)
        self.assertEqual(result["component"]["execution_count_kind"], "completed_driver_direct_calls")
        self.assertEqual(result["denominators"]["whole_config_hia_native_units"], 0)
        self.assertEqual(result["global_comparison_status"], "NOT_RUN")

    def test_return_thunk_is_only_the_configuration_required_kernel_abi(self):
        component, inspection, gate = self.component_fixture()
        self.component_proof_mocks(inspection, gate)
        self.assertTrue(self.assess(component=component)["claims"]["hia_component_replacement_executed"])
        for symbols in ([], ["malloc"], ["__x86_return_thunk", "abort"]):
            with self.subTest(symbols=symbols):
                changed = copy.deepcopy(component)
                changed["artifact"]["inspection"]["undefined"] = symbols
                with self.assertRaisesRegex(ValueError, "configuration-required kernel ABI"):
                    self.assess(component=changed)
        patch.stopall()
        component, inspection, gate = self.component_fixture(CONFIG.replace(b"CONFIG_MITIGATION_RETHUNK=y", b"# CONFIG_MITIGATION_RETHUNK is not set"))
        self.component_proof_mocks(inspection, gate)
        self.assertTrue(self.assess(baseline=None, component=component)["claims"]["hia_component_replacement_executed"])
        component["artifact"]["inspection"]["undefined"] = ["__x86_return_thunk"]
        with self.assertRaisesRegex(ValueError, "configuration-required kernel ABI"):
            self.assess(baseline=None, component=component)

    def test_component_zero_or_wrapper_calls_and_native_label_substitution_reject(self):
        component, inspection, gate = self.component_fixture()
        self.component_proof_mocks(inspection, gate)
        for kind in ("zero", "wrapper", "whole", "profile", "core", "fallback", "replayed_gate"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(component)
                if kind == "zero":
                    changed["guest_gate"]["execution_count"] = 0
                elif kind == "wrapper":
                    changed["guest_gate"]["executed_symbols"] = ["__sw_hweight32"]
                elif kind == "whole":
                    changed["routing"]["whole_kernel_rewrite"] = True
                elif kind == "profile":
                    changed["artifact"]["profile"] = "hosted-llvm-userspace"
                elif kind == "core":
                    changed["translated_body"]["core_sha256"] = "d" * 64
                elif kind == "fallback":
                    changed["artifact"]["claims"]["c_codegen_used"] = True
                else:
                    changed["guest_gate"]["execution_count"] += 1
                with self.assertRaises(ValueError):
                    self.assess(component=changed)

    def test_component_must_match_its_actual_boot_serial_image_config_and_lifecycle(self):
        component, inspection, gate = self.component_fixture()
        for kind in ("image", "config", "raw_serial", "missing_terminal"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(component)
                original_boot = json.loads(Path(gate["boot_report"]["path"]).read_bytes())
                if kind == "image":
                    original_boot["kernel_image"] = self.baseline["kernel_image"]
                elif kind == "config":
                    original_boot["config_sha256"] = "0" * 64
                elif kind == "raw_serial":
                    original_boot["boot"]["command_receipt"]["stdout"] = self.write("detached-component.log", b"unrelated stream")
                else:
                    serial = Path(gate["serial_log"]["path"]).read_bytes().replace(b"reboot: Power down", b"no power down")
                    replacement = self.write("component-incomplete-serial.log", serial)
                    changed["guest_gate"]["serial_log"] = replacement
                    original_boot["boot"]["command_receipt"]["stdout"] = replacement
                    original_boot["commands"][-1]["stdout"] = replacement
                changed["guest_gate"]["boot_report"] = self.write("component/changed-BOOT.json", original_boot)
                with patch("hepta.hia_linux_kernel.inspect_kernel_object", return_value=inspection), \
                     patch("tools.qualify_hia_linux_component.validate_guest_readback", return_value=copy.deepcopy(changed["guest_gate"])):
                    with self.assertRaises(ValueError):
                        self.assess(component=changed)

    def test_prospective_contract_allows_declared_internal_mpc_objective_but_no_actual_gain(self):
        registration = self.registration()
        contract.validate_comparison_contract(self.protocol, registration)
        self.assertNotEqual(registration["arms"][4]["internal_objective"], registration["arms"][5]["internal_objective"])
        result = self.assess(comparison=registration)
        self.assertEqual(result["comparison_registration_status"], "VALIDATED_NOT_EXECUTED")
        self.assertEqual(result["global_comparison_status"], "NOT_RUN")
        self.assertFalse(result["claims"]["ndu_unique_gain_established"])

    def test_controller_privilege_future_leak_objective_change_or_unequal_compute_rejects(self):
        for kind in ("future", "holdout", "action", "objective", "compute", "native", "missing_arm", "fixed_selected_online"):
            with self.subTest(kind=kind):
                reg = self.registration()
                if kind == "future":
                    reg["online_information"]["future_tape_visible"] = True
                elif kind == "holdout":
                    reg["holdout_used_for_selection"] = True
                elif kind in ("action", "objective"):
                    field = "action_registry_sha256" if kind == "action" else "external_objective_sha256"
                    reg["arms"][-1]["shared"][field] = "f" * 64
                elif kind == "compute":
                    reg["arms"][-1]["planning_budget"]["wall_ns"] *= 2
                elif kind == "native":
                    reg["arms"][-1]["native_backend_sha256"] = "c" * 64
                elif kind == "missing_arm":
                    reg["arms"].pop(4)
                else:
                    reg["fixed_selection"] = "best_at_each_state_using_test_results"
                with self.assertRaises(ValueError):
                    contract.validate_comparison_contract(self.protocol, reg)

    def test_cost_omission_double_counting_and_free_planning_are_rejected(self):
        for kind in ("build_omitted", "failed_attempt_omitted", "nested", "free_cpu", "unknown_as_zero"):
            with self.subTest(kind=kind):
                reg = self.registration()
                if kind == "build_omitted":
                    reg["costs"]["categories"].remove("compilation_and_linking")
                elif kind == "failed_attempt_omitted":
                    reg["costs"]["categories"].remove("failed_attempts")
                elif kind == "nested":
                    reg["costs"]["nested_costs_additive"] = True
                elif kind == "free_cpu":
                    reg["costs"]["runtime_compute_debits_real_resources"] = False
                else:
                    reg["costs"]["unknown_lifecycle_costs_reported_unknown"] = False
                with self.assertRaises(ValueError):
                    contract.validate_comparison_contract(self.protocol, reg)

    def test_split_overlap_unbalanced_cells_or_omitted_holdout_trace_rejects(self):
        for kind in ("overlap", "cell", "trace"):
            with self.subTest(kind=kind):
                reg = self.registration()
                if kind == "overlap":
                    reg["splits"]["development"].append("holdout-0")
                elif kind == "cell":
                    reg["planned_cells"].pop()
                else:
                    reg["splits"]["holdout"].append("omitted-trace")
                with self.assertRaises(ValueError):
                    contract.validate_comparison_contract(self.protocol, reg)

    def test_failed_skipped_and_unrun_cells_remain_valid_without_becoming_a_success(self):
        reg = self.registration()
        states = ("PASS", "FAIL", "SKIP", "NOT_RUN")
        reg["results"] = [{"id": cell["id"], "status": states[i % 4], "reason": "synthetic outcome retained"}
                          for i, cell in enumerate(reg["planned_cells"])]
        contract.validate_comparison_contract(self.protocol, reg)
        self.assertFalse(self.assess(comparison=reg)["claims"]["global_comparison_completed"])
        reg["results"].pop()
        with self.assertRaisesRegex(ValueError, "result denominator"):
            contract.validate_comparison_contract(self.protocol, reg)

    def test_even_all_pass_comparison_labels_cannot_replace_a_whole_hia_kernel(self):
        reg = self.registration()
        reg["results"] = [{"id": cell["id"], "status": "PASS"} for cell in reg["planned_cells"]]
        for key in ("global_comparison_completed", "ndu_unique_gain_established"):
            with self.subTest(key=key):
                changed = copy.deepcopy(reg)
                changed[key] = True
                with self.assertRaisesRegex(ValueError, "whole-config HIA"):
                    self.assess(comparison=changed)

    def test_protocol_cannot_open_future_information_or_drop_required_controllers(self):
        for kind in ("information", "arms"):
            changed = copy.deepcopy(self.protocol)
            if kind == "information":
                changed["comparison"]["online_information"]["future_tape_visible"] = True
            else:
                changed["comparison"]["required_arms"].remove("hia-ordinary-mpc")
            with self.assertRaises(ValueError):
                self.assess(protocol=changed)

    def test_cli_retains_rejection_and_never_overwrites_prior_assessment(self):
        inv = self.write("inventory.json", self.inventory)
        base = self.write("baseline.json", self.baseline)
        output = self.root / "assessment.json"
        args = ["--source-inventory", inv["path"], "--baseline", base["path"], "--output", str(output)]
        self.assertEqual(contract.main(args), 1)
        first = output.read_bytes()
        self.assertEqual(json.loads(first)["status"], "BLOCKED")
        with self.assertRaises(FileExistsError):
            contract.main(args)
        self.assertEqual(output.read_bytes(), first)
        changed = copy.deepcopy(self.inventory)
        changed["total_files"] -= 1
        self.write("inventory.json", changed)
        args[-1] = str(self.root / "rejected.json")
        self.assertEqual(contract.main(args), 2)
        rejected = json.loads(Path(args[-1]).read_bytes())
        self.assertEqual(rejected["status"], "REJECTED")
        self.assertFalse(any(rejected["claims"].values()))


if __name__ == "__main__":
    unittest.main()
