"""Standalone performance evidence regressions; no timing samples are run."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from itertools import permutations
import os
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_llvm import HIAProgramLLVM, HIAProgramLLVMRejected
from tools import qualify_hia_program_perf as q
from tools import qualify_llvm_owned as historical


CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


class StandalonePerformancePolicyTests(unittest.TestCase):
    def test_interference_observations_never_censor_or_repair_noisy_samples(self):
        samples = [{"elapsed_ns": 1000, "process_cpu_ns": cpu, "voluntary_context_switches": 0,
                    "involuntary_context_switches": switches, "minor_page_faults": 1,
                    "major_page_faults": 0} for cpu, switches in ((250, 50), (1001, 0))]
        result = q.interference_summary(samples)
        self.assertEqual(result["sample_count"], 2)
        self.assertEqual(result["cpu_to_wall_ratio"], {"minimum": 0.25, "median": 0.6255, "maximum": 1.001})
        self.assertEqual(result["totals"]["involuntary_context_switches"], 50)
        self.assertEqual(result["samples_excluded"], 0)
        self.assertFalse(result["acceptance_thresholds_adjusted"])
        for field in ("process_cpu_ns", "involuntary_context_switches"):
            changed = [{**samples[0], field: True}]
            with self.assertRaises(ValueError):
                q.interference_summary(changed)

    def test_requested_artifacts_are_exactly_retained_after_a_failed_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "attempt"
            report = {}
            payload = b"not a rebuilt substitute\x00native bytes"
            with self.assertRaisesRegex(RuntimeError, "actual attempted failure"):
                with q.artifact_workspace(destination, report) as workspace:
                    self.assertNotEqual(workspace, destination)
                    self.assertEqual(workspace.parent, Path("/tmp"))
                    (workspace / "measured.so").write_bytes(payload)
                    (workspace / "measured.so").chmod(0o700)
                    self.assertFalse((destination / "measured.so").exists())
                    raise RuntimeError("actual attempted failure")
            self.assertEqual((destination / "measured.so").read_bytes(), payload)
            manifest_bytes = (destination / "artifact-retention.json").read_bytes()
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest["files"], {"measured.so": {"bytes": len(payload), "sha256": q.sha(payload)}})
            self.assertEqual(report["artifact_retention"]["manifest_sha256"], q.sha(manifest_bytes))
            self.assertEqual(report["artifact_retention"]["files"], manifest["files"])
            self.assertEqual(manifest["path_mapping"], {"measured.so": {
                "original": str(workspace / "measured.so"),
                "retained": str(destination / "measured.so"),
                "bytes": len(payload), "sha256": q.sha(payload),
                "source_and_copy_hashes_verified": True}})
            self.assertEqual(report["artifact_retention"]["path_mapping"], manifest["path_mapping"])
            self.assertEqual(report["artifact_retention"]["status"], "complete")
            self.assertTrue(os.access(destination / "measured.so", os.X_OK))
            self.assertFalse(workspace.exists())

    def test_no_retention_uses_the_same_explicit_tmp_layout_even_when_tmpdir_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            caller_temp = Path(directory) / ("long_caller_tmpdir_" + "x" * 140)
            caller_temp.mkdir()
            report = {}
            with patch.dict(os.environ, {"TMPDIR": str(caller_temp)}), patch.object(tempfile, "tempdir", str(caller_temp)):
                with q.artifact_workspace(None, report) as workspace:
                    self.assertEqual(workspace.parent, Path("/tmp"))
                    self.assertEqual(len(workspace.name), len(q.BUILD_PREFIX) + q.BUILD_SUFFIX_CHARACTERS)
                    self.assertEqual(report["build_layout"]["directory"], str(workspace))
            self.assertEqual(report["artifact_retention"], {"retained": False})
            self.assertFalse(workspace.exists())

    def test_corrupted_copy_is_rejected_and_not_reported_retained(self):
        original_chmod = Path.chmod
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "attempt"
            report = {}
            def corrupt_after_copy(path, mode, **kwargs):
                original_chmod(path, mode, **kwargs)
                if path == destination / "measured.so":
                    path.write_bytes(b"different bytes")
            with self.assertRaisesRegex(ValueError, "retained artifact differs"):
                with patch.object(Path, "chmod", corrupt_after_copy):
                    with q.artifact_workspace(destination, report) as workspace:
                        (workspace / "measured.so").write_bytes(b"measured bytes")
            self.assertFalse(report["artifact_retention"]["retained"])
            self.assertNotIn("manifest_sha256", report["artifact_retention"])
            self.assertFalse((destination / "artifact-retention.json").exists())

    def test_recorded_measured_identity_cannot_be_replaced_before_retention(self):
        for observation in (False, True):
            with self.subTest(resource_observation=observation), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "attempt"
                report = {}
                with self.assertRaisesRegex(ValueError, "recorded measured identity"):
                    with q.artifact_workspace(destination, report) as workspace:
                        measured = workspace / "measured.so"
                        measured.write_bytes(b"actually measured bytes")
                        expected = q.identity(measured)
                        if observation:
                            report["resource_observation"] = {"artifacts": {"measured": expected}}
                        else:
                            report["artifacts"] = {"measured": expected}
                        measured.write_bytes(b"changed before finally copies")
                self.assertFalse(report["artifact_retention"]["retained"])
                self.assertEqual((destination / "measured.so").read_bytes(), b"changed before finally copies")
                self.assertNotEqual(report["artifact_retention"]["files"]["measured.so"]["sha256"], expected["sha256"])
                self.assertNotIn("manifest_sha256", report["artifact_retention"])
                self.assertFalse((destination / "artifact-retention.json").exists())

    def test_retention_rejects_existing_directory_without_replacing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            sentinel = destination / "unchanged"
            sentinel.write_text("existing evidence")
            report = {}
            with self.assertRaisesRegex(ValueError, "must be new"):
                with q.artifact_workspace(destination, report):
                    self.fail("existing directory admitted")
            self.assertEqual(sentinel.read_text(), "existing evidence")
            self.assertNotIn("artifact_retention", report)
            self.assertFalse((destination / "artifact-retention.json").exists())

    def test_frozen_workload_and_thresholds_are_unchanged_and_c_is_not_claimed(self):
        self.assertEqual(q.PROTOCOL["id"], "hepta.hia.program.perf.v3")
        self.assertEqual(q.PROTOCOL["build_layout"]["root"], "/tmp")
        self.assertFalse(q.PROTOCOL["build_layout"]["retention_parent_used_for_build"])
        self.assertFalse(q.PROTOCOL["build_layout"]["caller_tmpdir_used_for_build"])
        self.assertEqual(len(q.sample_order()), 63)
        for key in ("paired_groups", "native_calls_per_sample", "warmup_calls_per_process",
                    "kernel_buffer_sizes", "minimum_sample_seconds", "maximum_sample_seconds",
                    "maximum_relative_mad", "maximum_geometric_mean_paired_time_ratio",
                    "maximum_kernel_paired_time_ratio", "outlier_policy"):
            self.assertEqual(q.PROTOCOL[key], q.ORIGINAL_PROTOCOL[key])
        self.assertEqual(q.PROTOCOL["c_backend_scope"],
                         "no C correctness or performance backend is executed by this qualification")

    def test_stable_kernel_index_fixes_the_historical_fixed_middle_position(self):
        old, new = historical.sample_order(), q.sample_order()
        self.assertEqual([(g, k) for g, k, _ in old], [(g, k) for g, k, _ in new])
        self.assertEqual(len(new), 63)
        self.assertEqual(len(set(new)), 63)
        for kernel in q.KERNELS:
            before = [tuple(b for g, k, b in old if g == group and k == kernel) for group in range(7)]
            after = [tuple(b for g, k, b in new if g == group and k == kernel) for group in range(7)]
            self.assertEqual(len({order[1] for order in before}), 1, "reproduce the discovered defect")
            self.assertEqual(set(after), set(permutations(q.BACKENDS)))
            for position in range(3):
                self.assertEqual(sorted(Counter(order[position] for order in after).values()), [2, 2, 3])
            # Independently express the specified stable-index rotation.
            for group, order in enumerate(after):
                offset = (group + q.KERNELS.index(kernel)) % 3
                expected = tuple(q.BACKENDS[(offset + step) % 3] for step in range(3))
                self.assertEqual(order, expected[::-1] if group % 2 else expected)

    def test_v3_evaluator_rejects_historical_or_resealed_reordered_rows(self):
        def samples(order):
            return [{"group": g, "kernel": k, "backend": b, "sample_index": i,
                     "elapsed_ns": 100_000_000, "checksum": q.timed_checksum(k)}
                    for i, (g, k, b) in enumerate(order)]
        rows = samples(q.sample_order())
        self.assertTrue(q.evaluate_samples(rows)["ok"])
        old = samples(historical.sample_order())
        self.assertTrue(historical.evaluate_samples(old)["ok"])
        with self.assertRaisesRegex(ValueError, "sample order/identity"):
            historical.evaluate_samples(rows)
        reordered = deepcopy(rows)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        for i, row in enumerate(reordered):
            row["sample_index"] = i
        duplicate = deepcopy(rows)
        duplicate[1] = {**duplicate[0], "sample_index": 1}
        for bad in (old, reordered, duplicate, rows[:-1]):
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                q.evaluate_samples(bad)
        with self.assertRaises(TypeError):
            q.evaluate_samples(reordered, expected_order=[(r["group"], r["kernel"], r["backend"]) for r in reordered])

    def test_unrelated_compiler_failure_is_not_a_successful_origin_control(self):
        ir = HIAProgramLLVM("  call void @free(ptr %data) nobuiltin\n", "0" * 64, "0" * 64, "0" * 64, ("two_alloc",))
        observation = {}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(q, "compile_program_llvm", side_effect=[{"ok": True},
                    HIAProgramLLVMRejected("E_HIA_PROGRAM_STALE: implementation changed")]):
                with patch.object(q, "execute", side_effect=AssertionError("native mutant must not run")):
                    with self.assertRaisesRegex(ValueError, "unrelated"):
                        q.observe(ir, None, Path(directory), CLANG, observation=observation)
        self.assertEqual(observation["status"], "running")
        self.assertNotIn("rehashed_llvm_rejected", observation)


@unittest.skipUnless(RUSTC, "actual pinned Rust compiler required")
class StandalonePerformanceBuildLayoutTests(unittest.TestCase):
    def code_inventory(self, path):
        """Read ELF code bytes and actual symbol addresses, without binutils."""
        data = path.read_bytes()
        self.assertEqual(data[:6], b"\x7fELF\x02\x01")
        offset = struct.unpack_from("<Q", data, 40)[0]
        entry_size, count, names_index = struct.unpack_from("<HHH", data, 58)
        self.assertEqual(entry_size, 64)
        self.assertTrue(0 < names_index < count)
        headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * entry_size) for i in range(count)]
        names_header = headers[names_index]
        names = data[names_header[4]:names_header[4] + names_header[5]]
        sections = [(i, header) for i, header in enumerate(headers)
                    if names[header[0]:].split(b"\0", 1)[0] == b".text"]
        self.assertEqual(len(sections), 1)
        section_index, section = sections[0]
        text = data[section[4]:section[4] + section[5]]
        self.assertTrue(text)
        self.assertEqual(len(text), section[5])
        functions, code = {}, {}
        for symbols in headers:
            if symbols[1] != 2:  # SHT_SYMTAB includes local allocation helpers.
                continue
            strings_header = headers[symbols[6]]
            strings = data[strings_header[4]:strings_header[4] + strings_header[5]]
            self.assertEqual(symbols[9], 24)
            for index in range(0, symbols[5], symbols[9]):
                name_offset, info, _, section_id, address, length = struct.unpack_from(
                    "<IBBHQQ", data, symbols[4] + index)
                if info & 15 != 2 or section_id != section_index or length == 0:
                    continue
                name = strings[name_offset:].split(b"\0", 1)[0].decode()
                # Compare every defined allocation-named function as well as
                # all timed kernels, including RawVec and Rust allocator shims.
                if name not in q.KERNELS and "alloc" not in name:
                    continue
                start = address - section[3]
                self.assertTrue(0 <= start < len(text) and start + length <= len(text))
                code[name] = text[start:start + length]
                functions[name] = {"address": address, "bytes": length, "sha256": q.sha(code[name])}
        self.assertTrue(set(q.KERNELS).issubset(functions))
        self.assertTrue(any("finish_grow" in name for name in functions))
        self.assertTrue(any("__rdl_alloc" in name for name in functions))
        return ({"text": {"address": section[3], "bytes": len(text), "sha256": q.sha(text)},
                 "functions": functions}, {"text": text, "functions": code})

    def test_real_rust_kernel_code_is_independent_of_retention_parent_length(self):
        analysis = q.analyze(q.SOURCE, str(q.SOURCE_PATH), native=False, crate_type="cdylib")
        self.assertTrue(analysis.report["ok"])
        sources = {"rust": analysis.rust, "handwritten_rust": q.RUST_REFERENCE}
        runner = subprocess.run
        observations, actual_code = [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parents = [root / "s", root / ("long_retention_" + "x" * 160) / ("another_component_" + "y" * 160)]
            self.assertGreater(len(str(parents[1])) - len(str(parents[0])), 300)
            for parent in parents:
                parent.mkdir(parents=True)
                destination, report, commands = parent / "attempt", {}, []
                def record_command(command, *args, **kwargs):
                    if "--crate-name=hepta_program" in command:
                        commands.append([str(argument) for argument in command])
                    return runner(command, *args, **kwargs)
                row = {"retention_parent": str(parent), "retention_parent_characters": len(str(parent)), "baselines": {}}
                code_by_baseline = {}
                with patch.dict(os.environ, {"TMPDIR": str(parent)}), patch.object(tempfile, "tempdir", str(parent)):
                    with q.artifact_workspace(destination, report) as workspace:
                        row["build_directory"] = str(workspace)
                        self.assertEqual(workspace.parent, Path("/tmp"))
                        with patch.object(subprocess, "run", side_effect=record_command):
                            for name, source in sources.items():
                                library = workspace / (name + ".so")
                                (workspace / (name + ".rs")).write_text(source)
                                receipt = q.compile_rust(source, rustc=RUSTC, crate_type="cdylib", output=library)
                                self.assertTrue(receipt["ok"], receipt)
                                inventory, code_by_baseline[name] = self.code_inventory(library)
                                row["baselines"][name] = {"binary": q.identity(library), **inventory,
                                    "source_sha256": q.sha(source.encode()), "flags": receipt["flags"],
                                    "toolchain": receipt["toolchain"]}
                        self.assertEqual(len(commands), 2)
                        for name, command in zip(sources, commands):
                            actual_source = Path(command[1])
                            self.assertEqual(actual_source.parent.parent, workspace)
                            self.assertEqual(actual_source.name, "program.rs")
                            row["baselines"][name]["actual_compiler_command"] = command
                            row["baselines"][name]["actual_source_path_characters"] = len(str(actual_source))
                        report["artifacts"] = {name: data["binary"] for name, data in row["baselines"].items()}
                row["retention"] = report["artifact_retention"]
                for name in sources:
                    retained = destination / (name + ".so")
                    self.assertEqual(q.sha(retained.read_bytes()), row["baselines"][name]["binary"]["sha256"])
                observations.append(row)
                actual_code.append(code_by_baseline)
        self.build_observations = observations
        self.build_comparison = {}
        self.assertEqual(len(observations[0]["build_directory"]), len(observations[1]["build_directory"]))
        for name in sources:
            left, right = (row["baselines"][name] for row in observations)
            left_code, right_code = (code[name] for code in actual_code)
            differences = [{"offset": i, "address": left["text"]["address"] + i,
                            "before": before, "after": after}
                           for i, (before, after) in enumerate(zip(left_code["text"], right_code["text"]))
                           if before != after]
            self.build_comparison[name] = {"whole_text_equal": left_code["text"] == right_code["text"],
                "whole_text_byte_differences": differences, "compared_function_count": len(left["functions"]),
                "function_selection": "all measured kernels and every defined allocation-named function",
                "whole_binary_equal": left["binary"]["sha256"] == right["binary"]["sha256"]}
            self.assertEqual(left["actual_source_path_characters"], right["actual_source_path_characters"])
            self.assertEqual(left["text"]["address"], right["text"]["address"])
            self.assertEqual(left["text"]["bytes"], right["text"]["bytes"])
            self.assertEqual(left["functions"], right["functions"])
            self.assertEqual(left_code["functions"], right_code["functions"])
            self.assertEqual(left["flags"], right["flags"])
            self.assertEqual(left["source_sha256"], right["source_sha256"])
            # Whole .text/ELF equality is deliberately not claimed. Random
            # source-path strings can reorder pooled strings and change RIP
            # references in unrelated std helpers, despite identical kernel
            # code and placement. Preserve all hashes and differing bytes.


@unittest.skipUnless(shutil.which(CLANG), "actual Clang required")
class StandalonePerformanceFailureCaptureTests(unittest.TestCase):
    def test_actual_native_abort_is_captured_without_terminating_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, library = folder / "abort.c", folder / "abort.so"
            source.write_text("#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n"
                              "uint64_t full_lifecycle(size_t n,uint32_t seed){(void)n;(void)seed;abort();}\n")
            q.successful(q.execute([CLANG, "-shared", "-fPIC", str(source), "-o", str(library)]))
            observation = {}
            with self.assertRaises(q.NativeCommandFailed) as rejected:
                q.check_correctness({name: library for name in q.BACKENDS}, observation=observation)
            self.assertEqual(rejected.exception.record["returncode"], -6)
            self.assertEqual(observation["process"], rejected.exception.record)
            self.assertEqual(observation["status"], "running")
            self.assertEqual(observation["observations"], [])


if __name__ == "__main__":
    unittest.main()
