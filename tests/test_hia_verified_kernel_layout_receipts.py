"""Complete synthetic v7 parser controls; these are not performance evidence.

The fixture contains all 2,281 rows, 47,901 synthetic samples and all 1,526
controlled command outputs. An explicit test-only v6 stub isolates v7 parsing;
it does not perform or replace production v6 proof, solver or binary checking.
No benchmark, compiler, native library or solver is executed. Temporary fake
binaries and receipts are deleted and must never qualify a real campaign.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import random
import shutil
import statistics
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
MASK = (1 << 64) - 1
SEED = 0x123456789abcdef
SOURCE_FILES = (
    "benchmarks/hia_verified_kernels/PROTOCOL_LAYOUT_V7.json",
    "benchmarks/hia_verified_kernels/PROTOCOL.json",
    "benchmarks/hia_verified_kernels/driver.c",
    "benchmarks/hia_verified_kernels/driver_layout.c",
    "tools/benchmark_hia_verified_kernels.py",
    "tools/benchmark_hia_verified_kernels_layout.py",
)
IDENTIFIED_SOURCES = set(SOURCE_FILES) - {
    "benchmarks/hia_verified_kernels/PROTOCOL.json",
    "benchmarks/hia_verified_kernels/driver.c",
}


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


reader = module("read_hia_verified_kernel_layout_campaign_v7.py", "v7_receipt_parser_tests")
v6 = module("read_hia_verified_kernel_campaign_v6.py", "v7_receipt_v6_inventory_only")


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def fixture_checksums(protocol):
    """Generate ordinary slice sums, separately from the reader's prefix sums."""
    state, source = 0x3c79ac492ba7b653, bytearray()
    for _ in range(max(protocol["lengths"]) + 32):
        state ^= state >> 12
        state = (state ^ (state << 25)) & MASK
        state ^= state >> 27
        source.append(((state * 0x2545f4914f6cdd1d) & MASK) >> 56)
    values = {}
    for length in protocol["lengths"]:
        calls = protocol["span_iterations"][str(length)]
        sums = [sum(source[offset:offset + length]) for offset in range(1, 17)]
        values["sum", length] = (SEED + sum(value * (calls // 16 + (index < calls % 16))
                                                   for index, value in enumerate(sums))) & MASK
        values["zero", length] = (SEED + calls) & MASK
        values["copy", length] = (SEED + calls * length) & MASK
    # This is checksum arithmetic only, not execution of a benchmark kernel.
    scalar = SEED
    for iteration in range(protocol["scalar_iterations"]):
        scalar = (scalar * 0x9e3779b97f4a7c15 + iteration) & MASK
    values["scalar", 0] = scalar
    return values


class IsolatedV6ParserStub:
    """Explicitly fake admission for v7 unit tests; never used by production CLI."""

    expected_cases = staticmethod(v6.expected_cases)
    expected_binding = staticmethod(v6.expected_binding)

    def __init__(self):
        self.calls = []
        self.error = None
        self.response = {
            "ok": True,
            "scope": "original_files_and_record_readback",
            "original_command_output_binary_and_query_bytes_checked": True,
            "solver_original_source_library_files_checked": True,
            "synthetic_fixture_only": True,
            "native_benchmark_observed": False,
            "cases": 763, "samples_checked": 16023, "commands": 807, "binaries": 33,
        }

    def readback(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        report = json.loads(args[1].read_text())
        response = deepcopy(self.response)
        # Emulate the real reader's public-projection selection, not its proof.
        if "wide_builds" in report and "builds" not in report:
            response.update(scope="public_projection_record_readback",
                            original_command_output_binary_and_query_bytes_checked=False,
                            solver_original_source_library_files_checked=False)
        return response


class LayoutReceiptParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-v7-synthetic-parser-only-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.source = cls.directory / "source"
        cls.evidence = cls.directory / "synthetic-not-a-campaign"
        cls.original = cls.evidence / "original-v6"
        cls.original.mkdir(parents=True)
        for name in SOURCE_FILES:
            path = cls.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        cls.protocol = json.loads((cls.source / SOURCE_FILES[0]).read_text())
        cls.old_protocol = json.loads((cls.source / SOURCE_FILES[1]).read_text())
        cls.sums = fixture_checksums(cls.old_protocol)
        original_cases = v6.expected_cases(cls.old_protocol)
        cls.controlled = []
        for mode, arm, length in original_cases:
            if mode == "scalar":
                continue
            layouts = ((gap, order) for gap in (131072, 131136) for order in ("src-low", "src-high"))
            if mode != "copy":
                layouts = ((131072, "src-low"),)
            for gap, order in layouts:
                cls.controlled.append({
                    "mode": mode, "arm": arm, "length": length, "gap": gap, "address_order": order,
                    "layout": f"phase0-gap{gap}-{order}" if mode == "copy" else "phase0-reduction",
                })
        random.Random(20261119).shuffle(cls.controlled)
        assert len(cls.controlled) == 1518
        random.Random(20261119).shuffle(original_cases)
        cc = cls.directory / "synthetic-cc-never-executed"
        cc.write_bytes(b"SYNTHETIC COMPILER PLACEHOLDER - DO NOT EXECUTE\n")
        libc = cls.directory / "synthetic-libc-never-loaded"
        libc.write_bytes(b"SYNTHETIC RUNTIME PLACEHOLDER - DO NOT LOAD\n")
        toolchain = {"cc": {"path": str(cc), "sha256": digest(cc)}}
        runtime = {"glibc_version": "SYNTHETIC", "libc_path": str(libc), "libc_sha256": digest(libc),
                   "memcpy_ifunc_offset": 123, "binding": "synthetic parser fixture only"}
        cls.runtime_bytes = f"SYNTHETIC\n{libc}\n123\n".encode()
        (cls.original / "runtime-identity-after.stdout").write_bytes(cls.runtime_bytes)
        legacy = {
            "schema": cls.old_protocol["schema"], "ok": True, "status": "completed",
            "synthetic_fixture_only": True, "native_benchmark_observed": False,
            "source_commit": COMMIT, "builds": {}, "rows": [], "case_order": [],
            "host": {"actual_affinity": [15], "synthetic_fixture_only": True},
            "toolchain": toolchain, "runtime_dependency": runtime, "binaries": {},
        }
        for mode, arm, length in original_cases:
            calls = (cls.old_protocol["scalar_iterations"] if mode == "scalar" else
                     cls.old_protocol["span_iterations"][str(length)])
            samples = cls.samples(calls, cls.sums[mode, length])
            library, symbol = v6.expected_binding((mode, arm, length))
            legacy["rows"].append({"mode": mode, "arm": arm, "length": length,
                                   "library": library, "symbol": symbol, "samples": samples,
                                   "median_ns_per_call": 11.0, "max_ns_per_call": 21.0})
            legacy["case_order"].append({"mode": mode, "arm": arm, "length": length})
            legacy["binaries"][library] = {}
        legacy["binaries"].update({"driver": {}, "runtime-identity": {}})
        assert len(legacy["binaries"]) == 33
        for name in legacy["binaries"]:
            path = cls.original / name
            path.write_bytes(("SYNTHETIC NOT ELF - " + name + "\n").encode())
            legacy["binaries"][name] = {"sha256": digest(path), "bytes": path.stat().st_size}
        cls.legacy_bytes = encoded(legacy)
        (cls.original / "RESULT.json").write_bytes(cls.legacy_bytes)
        (cls.evidence / "protocol-layout.json").write_bytes((cls.source / SOURCE_FILES[0]).read_bytes())
        driver = cls.evidence / "driver-layout"
        driver.write_bytes(b"SYNTHETIC NOT ELF - driver-layout\n")
        result = {
            "schema": cls.protocol["schema"], "ok": True, "status": "completed",
            "synthetic_fixture_only": True, "native_benchmark_observed": False,
            "protocol": cls.protocol, "protocol_sha256": digest(cls.source / SOURCE_FILES[0]),
            "legacy_campaign": {"path": "original-v6/RESULT.json", "ok": True, "cases": 763,
                                "sha256": sha256(cls.legacy_bytes).hexdigest(), "source_commit": COMMIT},
            "source_commit": COMMIT,
            "source_identity": {name: digest(cls.source / name) for name in IDENTIFIED_SOURCES},
            "toolchain": toolchain, "runtime_dependency": runtime, "host": legacy["host"],
            "layout_affinity_before": [15], "layout_affinity_after": [15],
            "rows": [dict(row, phase="legacy-v6", layout=None) for row in legacy["rows"]],
            "case_order": [dict(row, phase="legacy-v6", layout=None) for row in legacy["case_order"]],
            "commands": [], "binaries": {"driver-layout": {"sha256": digest(driver),
                                                           "bytes": driver.stat().st_size}},
        }
        result["case_order"] += [dict(case, phase="controlled-layout") for case in cls.controlled]

        def command(label, argv, stdout=b""):
            (cls.evidence / (label + ".stdout")).write_bytes(stdout)
            (cls.evidence / (label + ".stderr")).write_bytes(b"")
            result["commands"].append({"label": label, "argv": [str(word) for word in argv],
                                       "returncode": 0, "timed_out": False, "elapsed_seconds": 0.0,
                                       "stdout_sha256": sha256(stdout).hexdigest(),
                                       "stderr_sha256": sha256(b"").hexdigest()})

        command("layout-source-commit-before", ["git", "rev-parse", "HEAD"], (COMMIT + "\n").encode())
        command("layout-source-status-before", ["git", "status", "--porcelain=v1", "--untracked-files=no"])
        command("layout-build-driver", [cc, "-O3", "-std=c11", cls.source / SOURCE_FILES[3], "-ldl", "-o", driver])
        command("layout-disassembly-driver", ["objdump", "-d", driver], b"SYNTHETIC disassembly placeholder\n")
        command("layout-runtime-identity-before", [cls.original / "runtime-identity"], cls.runtime_bytes)
        for index, case in enumerate(cls.controlled):
            calls = cls.protocol["span_iterations"][str(case["length"])]
            observation = cls.observation(case, 0x100000000 + index * 0x100000)
            samples = cls.samples(calls, cls.sums[case["mode"], case["length"]])
            for sample in samples:
                sample.update(source_base=observation["source_base"],
                              destination_base=observation["destination_base"])
            library, symbol = v6.expected_binding((case["mode"], case["arm"], case["length"]))
            row = dict(case, phase="controlled-layout", library=library, symbol=symbol,
                       layout_observation=observation, samples=samples,
                       median_ns_per_call=11.0, max_ns_per_call=21.0)
            result["rows"].append(row)
            command(cls.label(index, case),
                    [driver, case["mode"], cls.original / library, symbol, 21, calls,
                     case["length"], case["gap"], case["address_order"]],
                    b"".join(encoded(item) for item in [observation, *samples]))
        command("layout-source-commit-after", ["git", "rev-parse", "HEAD"], (COMMIT + "\n").encode())
        command("layout-source-status-after", ["git", "status", "--porcelain=v1", "--untracked-files=no"])
        command("layout-runtime-identity-after", [cls.original / "runtime-identity"], cls.runtime_bytes)
        assert len(result["rows"]) == 2281 and sum(len(row["samples"]) for row in result["rows"]) == 47901
        assert len(result["commands"]) == 1526
        cls.result_bytes = encoded(result)
        cls.result_path = cls.evidence / "RESULT.json"
        cls.copy_index = next(index for index, case in enumerate(cls.controlled) if case["mode"] == "copy")

    @staticmethod
    def samples(calls, checksum):
        # Artificial integral timings make rounding independent of a native clock.
        return [{"batch": batch, "calls": calls, "elapsed_ns": calls * (batch + 1),
                 "ns_per_call": float(batch + 1), "checksum": checksum} for batch in range(21)]

    @staticmethod
    def observation(case, arena):
        low, high = arena + 4096, arena + 4096 + case["gap"]
        source, destination = (high, low) if case["address_order"] == "src-high" else (low, high)
        return {
            "record": "layout", "schema": "hia.kernel-layout.phase0.v1", "mode": case["mode"],
            "length": case["length"], "cpu": 15, "arena_base": arena, "arena_bytes": 262144,
            "page_bytes": 4096, "lower_base": low, "upper_base": high,
            "source_base": source, "destination_base": destination,
            "source_mod64": source % 64, "destination_mod64": destination % 64,
            "source_mod4096": source % 4096, "destination_mod4096": destination % 4096,
            "gap": case["gap"], "destination_minus_source": destination - source,
            "address_order": case["address_order"], "relative_offsets": [1, 16],
            "arena_allocated_before_dlopen": True, "validation_only": False,
        }

    @staticmethod
    def label(index, case):
        return f"layout-case-{index:04d}-{case['mode']}-{case['arm']}-{case['length']}-{case['layout']}"

    def setUp(self):
        self.result = json.loads(self.result_bytes)
        self.legacy = json.loads(self.legacy_bytes)
        self.stub = IsolatedV6ParserStub()
        self.previous, self.profiles = object(), object()
        self.solver_library = self.directory / "synthetic-explicit-solver-path"
        self.changed = {}
        self.addCleanup(self.restore)

    def restore(self):
        for path, raw in self.changed.items():
            if raw is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(raw)

    def replace(self, path, raw):
        if path not in self.changed:
            self.changed[path] = path.read_bytes() if path.exists() else None
        if raw is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def rewrite_legacy(self):
        raw = encoded(self.legacy)
        self.replace(self.original / "RESULT.json", raw)
        self.result["legacy_campaign"]["sha256"] = sha256(raw).hexdigest()

    def command(self, label):
        return next(row for row in self.result["commands"] if row["label"] == label)

    def output(self, label, raw, stream="stdout"):
        self.replace(self.evidence / (label + "." + stream), raw)
        self.command(label)[stream + "_sha256"] = sha256(raw).hexdigest()

    def rehash_row(self, index=0):
        row = self.result["rows"][763 + index]
        self.output(self.label(index, self.controlled[index]),
                    b"".join(encoded(item) for item in [row["layout_observation"], *row["samples"]]))

    def rebase_observation(self, row, observation):
        row["layout_observation"] = observation
        for sample in row["samples"]:
            sample["source_base"] = observation["source_base"]
            sample["destination_base"] = observation["destination_base"]

    def read(self):
        self.result_path.write_bytes(encoded(self.result))
        return reader.readback(self.source, self.result_path, self.stub, self.previous,
                               self.old_protocol, self.profiles, expected_commit=COMMIT,
                               solver_library=self.solver_library)

    def reject(self, message):
        with self.assertRaisesRegex(ValueError, message):
            self.read()

    def test_complete_synthetic_fixture_exercises_all_v7_rows_outputs_and_samples(self):
        checked = self.read()
        self.assertEqual((checked["cases"], checked["samples"]), (2281, 47901))
        self.assertEqual((checked["controlled_cases"], checked["controlled_samples"]), (1518, 31878))
        self.assertEqual((checked["controlled_commands"], checked["total_commands"], checked["total_binaries"]),
                         (1526, 2333, 34))
        self.assertTrue(checked["complete_original_763_rows_preserved"])
        self.assertTrue(checked["original_v6_readback"]["synthetic_fixture_only"])
        self.assertFalse(checked["original_v6_readback"]["native_benchmark_observed"])
        self.assertFalse(checked["native_components_or_installation_qualified"])
        self.assertEqual(len(self.stub.calls), 1)
        args, kwargs = self.stub.calls[0]
        self.assertEqual(args, (self.source, self.original / "RESULT.json", self.previous,
                                self.old_protocol, self.profiles))
        self.assertEqual(kwargs, {"expected_commit": COMMIT, "solver_library": self.solver_library})

    def test_rehashed_public_projection_cannot_replace_original_v6_files(self):
        self.legacy["wide_builds"] = self.legacy.pop("builds")
        self.rewrite_legacy()
        self.reject("requires the raw v6 report")
        self.assertEqual(self.stub.calls, [])

    def test_v6_delegation_cannot_downgrade_scope_or_original_file_checks(self):
        changes = {"scope": "public_projection_record_readback",
                   "original_command_output_binary_and_query_bytes_checked": False,
                   "solver_original_source_library_files_checked": False}
        for name, value in changes.items():
            with self.subTest(field=name):
                self.stub = IsolatedV6ParserStub()
                self.stub.response[name] = value
                self.reject("did not check the original")

    def test_v6_validation_failure_is_not_ignored(self):
        self.stub.error = ValueError("synthetic v6 proof failure")
        self.reject("synthetic v6 proof failure")
        self.assertEqual(len(self.stub.calls), 1)

    def test_schema_and_completion_are_required(self):
        for name, value in (("schema", "unknown"), ("ok", False), ("status", "running")):
            with self.subTest(field=name):
                original = self.result[name]
                self.result[name] = value
                self.reject("not complete or protocol bytes differ")
                self.result[name] = original
        self.assertEqual(self.stub.calls, [])

    def test_original_v6_file_hash_cannot_be_relabelled_without_actual_bytes(self):
        self.result["legacy_campaign"]["sha256"] = "0" * 64
        self.reject("original complete v6 record binding differs")
        self.assertEqual(self.stub.calls, [])

    def test_original_763_rows_cannot_be_altered_in_the_combined_report(self):
        self.result["rows"][0]["samples"][0]["checksum"] ^= 1
        self.reject("original rows changed")

    def test_controlled_rows_cannot_be_omitted_duplicated_or_reordered(self):
        original = self.result["rows"][763:]
        for change in ("omit", "duplicate", "reorder"):
            with self.subTest(change=change):
                self.result["rows"][763:] = deepcopy(original)
                if change == "omit":
                    self.result["rows"].pop()
                elif change == "duplicate":
                    self.result["rows"][764] = deepcopy(self.result["rows"][763])
                else:
                    self.result["rows"][763], self.result["rows"][764] = self.result["rows"][764], self.result["rows"][763]
                self.reject("combined inventory incomplete|controlled case identity")

    def test_self_reported_case_order_cannot_replace_independent_inventory(self):
        self.result["case_order"][-1], self.result["case_order"][-2] = (
            self.result["case_order"][-2], self.result["case_order"][-1])
        self.reject("complete two-phase ordering differs")

    def test_commands_cannot_be_omitted_duplicated_or_reordered(self):
        original = deepcopy(self.result["commands"])
        for change in ("omit", "duplicate", "reorder", "move-prefix-after-cases"):
            with self.subTest(change=change):
                self.result["commands"] = deepcopy(original)
                if change == "omit":
                    self.result["commands"].pop(5)
                elif change == "duplicate":
                    self.result["commands"][6] = deepcopy(self.result["commands"][5])
                elif change == "reorder":
                    self.result["commands"][5], self.result["commands"][6] = self.result["commands"][6], self.result["commands"][5]
                else:
                    self.result["commands"].append(self.result["commands"].pop(0))
                self.reject("exact sequence")

    def test_failed_or_timed_out_commands_reject(self):
        for name, value in (("returncode", 1), ("timed_out", True)):
            with self.subTest(field=name):
                original = self.result["commands"][5][name]
                self.result["commands"][5][name] = value
                self.reject("failed layout command")
                self.result["commands"][5][name] = original

    def test_command_output_hashes_are_checked_against_original_files(self):
        label = self.result["commands"][5]["label"]
        self.replace(self.evidence / (label + ".stdout"), b"{}\n")
        self.reject("original layout command output bytes differ")

    def test_rehashed_output_with_missing_layout_or_extra_row_rejects(self):
        row, label = self.result["rows"][763], self.result["commands"][5]["label"]
        for records in (row["samples"], [row["layout_observation"], *row["samples"], {}]):
            with self.subTest(records=len(records)):
                self.output(label, b"".join(encoded(item) for item in records))
                self.reject("stdout differs from result rows")

    def test_rehashed_samples_cannot_be_omitted_or_duplicated(self):
        row = self.result["rows"][763]
        original = deepcopy(row["samples"])
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                row["samples"] = deepcopy(original)
                if duplicate:
                    row["samples"][-1] = deepcopy(row["samples"][0])
                else:
                    row["samples"].pop()
                self.rehash_row()
                self.reject("incomplete controlled batches")

    def test_rehashed_checksum_calls_elapsed_and_timing_changes_reject(self):
        row = self.result["rows"][763]
        original = deepcopy(row["samples"][0])
        changes = (("checksum", original["checksum"] ^ 1), ("calls", original["calls"] + 1),
                   ("elapsed_ns", 0), ("elapsed_ns", float(original["elapsed_ns"])),
                   ("ns_per_call", original["ns_per_call"] + 1), ("ns_per_call", float("inf")))
        for name, value in changes:
            with self.subTest(field=name, value=value):
                row["samples"][0] = dict(original, **{name: value})
                self.rehash_row()
                self.reject("checksum, timing division or pointer stability differs")

    def test_timing_summaries_must_be_recomputed_from_all_21_samples(self):
        row = self.result["rows"][763]
        for name in ("median_ns_per_call", "max_ns_per_call"):
            with self.subTest(field=name):
                old = row[name]
                row[name] += 1
                self.reject("timing summary differs")
                row[name] = old

    def test_rehashed_batch_pointer_change_cannot_keep_the_initial_layout(self):
        self.result["rows"][763]["samples"][20]["source_base"] += 64
        self.rehash_row()
        self.reject("pointer stability differs")

    def test_rehashed_layout_requires_integer_addresses_and_real_arena_relationships(self):
        index = self.copy_index
        row = self.result["rows"][763 + index]
        original = deepcopy(row["layout_observation"])
        changes = (
            ("source_base", original["source_base"] + 262144),
            ("lower_base", original["lower_base"] + 64),
            ("upper_base", original["upper_base"] + 64),
            ("arena_base", 0),
            ("source_base", float(original["source_base"])),
            ("destination_minus_source", -original["destination_minus_source"]),
        )
        for name, value in changes:
            with self.subTest(field=name, value=value):
                observation = dict(original, **{name: value})
                self.rebase_observation(row, observation)
                self.rehash_row(index)
                self.reject("noninteger address|arena bounds|actual source/destination order")

    def test_rehashed_coherent_address_shift_cannot_change_the_fixed_page_phase(self):
        index = self.copy_index
        row = self.result["rows"][763 + index]
        observation = self.observation(self.controlled[index], row["layout_observation"]["arena_base"] + 64)
        self.rebase_observation(row, observation)
        self.rehash_row(index)
        self.reject("arena bounds, phase or fixed distance differs")

    def test_rehashed_coherent_address_wrap_rejects(self):
        index = self.copy_index
        row = self.result["rows"][763 + index]
        self.rebase_observation(row, self.observation(self.controlled[index], (1 << 64) - 4096))
        self.rehash_row(index)
        self.reject("arena bounds")

    def test_rehashed_gap_order_alignment_and_contract_metadata_reject(self):
        index = self.copy_index
        row = self.result["rows"][763 + index]
        original = deepcopy(row["layout_observation"])
        changes = (
            ("gap", 131136 if original["gap"] == 131072 else 131072),
            ("address_order", "src-high" if original["address_order"] == "src-low" else "src-low"),
            ("source_mod4096", (original["source_mod4096"] + 64) % 4096),
            ("destination_mod64", 1), ("cpu", 16), ("page_bytes", 8192),
            ("relative_offsets", [0, 15]), ("arena_allocated_before_dlopen", False),
            ("validation_only", True),
        )
        for name, value in changes:
            with self.subTest(field=name):
                self.rebase_observation(row, dict(original, **{name: value}))
                self.rehash_row(index)
                self.reject("observation|workload/gap/order|alignment phase|CPU differs|extent or offset")

    def test_case_declared_gap_order_or_phase_cannot_change_independent_cases(self):
        row = self.result["rows"][763 + self.copy_index]
        for name, value in (("gap", 131200), ("address_order", "reversed"), ("phase", "legacy-v6"),
                            ("layout", "unreviewed-layout")):
            with self.subTest(field=name):
                old = row[name]
                row[name] = value
                self.reject("controlled case identity")
                row[name] = old

    def test_wrong_library_and_symbol_cannot_reuse_a_layout_case(self):
        row = self.result["rows"][763]
        for name, value in (("library", "reference-rust.so" if row["library"] != "reference-rust.so" else "reference-c.so"),
                            ("symbol", "other_entrypoint")):
            with self.subTest(field=name):
                old = row[name]
                row[name] = value
                self.reject("case/library/symbol binding differs")
                row[name] = old

    def test_a_case_cannot_use_a_library_absent_from_original_build_inventory(self):
        del self.legacy["binaries"][self.result["rows"][763]["library"]]
        self.rewrite_legacy()
        self.reject("no original same-build library")

    def test_actual_driver_argv_cannot_substitute_layout_library_symbol_or_workload(self):
        command = self.result["commands"][5]
        original = list(command["argv"])
        for position, value in ((0, "/different/driver-layout"), (2, "/different/library.so"),
                                (3, "other_symbol"), (4, "20"), (5, "17"), (6, "999"),
                                (7, "131200"), (8, "other-order")):
            with self.subTest(position=position):
                command["argv"] = list(original)
                command["argv"][position] = value
                self.reject("actual controlled driver invocation differs")

    def test_source_identity_inventory_and_actual_source_hash_are_required(self):
        identities = deepcopy(self.result["source_identity"])
        for change in ("missing", "wrong", "extra"):
            with self.subTest(change=change):
                self.result["source_identity"] = deepcopy(identities)
                name = "tools/benchmark_hia_verified_kernels_layout.py"
                if change == "missing":
                    self.result["source_identity"].pop(name)
                elif change == "wrong":
                    self.result["source_identity"][name] = "0" * 64
                else:
                    self.result["source_identity"]["unreviewed.py"] = "0" * 64
                self.reject("source identity inventory differs|layout source hash differs")

    def test_compiler_identity_and_required_flags_cannot_change_between_phases(self):
        original = deepcopy(self.result["toolchain"])
        self.result["toolchain"]["cc"]["path"] = "/another/compiler"
        self.reject("toolchain or runtime binding changed")
        self.result["toolchain"] = original
        command = self.command("layout-build-driver")
        argv = list(command["argv"])
        for position, value in ((0, "/another/compiler"), (1, "-O0"), (2, "-std=c99"), (4, "-lm")):
            with self.subTest(position=position):
                command["argv"] = list(argv)
                command["argv"][position] = value
                self.reject("compiler flags or input differs")

    def test_actual_compiler_input_bytes_are_checked_even_for_the_same_basename(self):
        different = self.directory / "different-input/driver_layout.c"
        self.replace(different, b"int main(void) { return 0; }\n")
        self.command("layout-build-driver")["argv"][3] = str(different)
        self.reject("actual layout compiler input bytes differ")

    def test_actual_driver_binary_hash_and_size_are_checked(self):
        path = self.evidence / "driver-layout"
        original = path.read_bytes()
        for changed in (bytes([original[0] ^ 1]) + original[1:], original + b"extra"):
            with self.subTest(size=len(changed)):
                self.replace(path, changed)
                self.reject("actual controlled driver binary differs")

    def test_missing_raw_output_or_binary_cannot_pass(self):
        paths = (self.evidence / (self.result["commands"][5]["label"] + ".stdout"),
                 self.evidence / "driver-layout")
        for path in paths:
            with self.subTest(file=path.name):
                raw = path.read_bytes()
                self.replace(path, None)
                with self.assertRaises(OSError):
                    self.read()
                self.replace(path, raw)

    def test_rehashed_source_commit_status_and_runtime_receipts_still_reject_drift(self):
        changes = (("layout-source-commit-after", b"b" * 40 + b"\n", "tracked source changed"),
                   ("layout-source-status-after", b" M changed.py\n", "tracked source changed"),
                   ("layout-runtime-identity-after", b"SYNTHETIC changed IFUNC\n", "runtime IFUNC differs"))
        for label, raw, reason in changes:
            with self.subTest(command=label):
                path = self.evidence / (label + ".stdout")
                original = path.read_bytes()
                self.output(label, raw)
                self.reject(reason)
                self.output(label, original)

    def test_phase_affinity_and_host_runtime_binding_cannot_change(self):
        self.result["layout_affinity_after"] = [16]
        self.reject("CPU affinity changed")
        self.result["layout_affinity_after"] = [15]
        self.result["runtime_dependency"]["memcpy_ifunc_offset"] += 1
        self.reject("toolchain or runtime binding changed")

    def test_protocol_snapshot_and_original_v6_sources_are_checked(self):
        path = self.evidence / "protocol-layout.json"
        original = path.read_bytes()
        self.replace(path, original + b"\n")
        self.reject("protocol bytes differ")
        self.replace(path, original)
        path = self.source / "tools/benchmark_hia_verified_kernels.py"
        self.replace(path, path.read_bytes() + b"\n")
        self.reject("original v6 bytes changed")


if __name__ == "__main__":
    unittest.main()
