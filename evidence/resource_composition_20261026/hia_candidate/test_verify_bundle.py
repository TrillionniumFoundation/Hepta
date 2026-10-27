"""Small data-only rejection checks; never launch native or compiler processes."""
import base64
from copy import deepcopy
import io
import json
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

import audit
from verify_bundle import MAX_TAR, read_regular, safe_path, unpack_archive

ROOT = Path(__file__).resolve().parent


class RetainedDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.performance = audit.parse((ROOT / "performance.json").read_bytes())
        cls.manifest = audit.parse((ROOT / "run-artifacts.manifest.json").read_bytes())
        cls.members = unpack_archive(ROOT, cls.manifest)

    def test_actual_complete_failed_attempt_recomputes_without_promoting_it(self):
        result = audit.review(self.members)
        self.assertEqual(result["attempt2"]["passed_gates"], 14)
        self.assertEqual(result["performance"]["sample_count"], 63)
        self.assertEqual(len(result["performance"]["measurement_quality_failures"]), 4)
        self.assertFalse(result["performance"]["performance_qualified"])
        self.assertEqual(result["correctness"]["native_calls"], 588)
        self.assertEqual(result["artifact_retention"]["retained_files"], 16)
        self.assertIsNone(result["attempt1"]["unit_tests_completed"])

    def test_historical_source_schedule_cannot_replace_hia_v3_schedule(self):
        changed = deepcopy(self.performance)
        keyed = {(r["group"], r["kernel"], r["backend"]): r for r in changed["raw_samples"]}
        old_order = []
        for group in range(7):
            for position in range(3):
                kernel = audit.KERNELS[(group + position) % 3]
                offset = (group + position) % 3
                backends = audit.BACKENDS[offset:] + audit.BACKENDS[:offset]
                if group % 2:
                    backends = backends[::-1]
                old_order.extend((group, kernel, backend) for backend in backends)
        changed["raw_samples"] = [keyed[key] for key in old_order]
        for index, row in enumerate(changed["raw_samples"]):
            row["sample_index"] = index
        with self.assertRaisesRegex(ValueError, "stable-kernel sample order"):
            audit.recompute(changed)

    def test_missing_sample_rejected(self):
        changed = deepcopy(self.performance)
        changed["raw_samples"].pop()
        with self.assertRaisesRegex(ValueError, "all 63"):
            audit.recompute(changed)

    def test_failure_list_cannot_be_erased(self):
        changed = deepcopy(self.performance)
        changed["evaluation"]["measurement_quality_failures"] = []
        with self.assertRaisesRegex(ValueError, "failure list"):
            audit.recompute(changed)

    def test_relaxed_threshold_rejected_even_with_fresh_protocol_digest(self):
        changed = deepcopy(self.performance)
        changed["protocol"]["maximum_relative_mad"] = 0.10
        changed["protocol_sha256"] = audit.sha(audit.wire(changed["protocol"]))
        with self.assertRaisesRegex(ValueError, "frozen HIA v3 protocol"):
            audit.recompute(changed)

    def test_observation_unavailable_or_boolean_cannot_be_an_integer_measurement(self):
        for value in (None, False):
            with self.subTest(value=value):
                changed = deepcopy(self.performance)
                changed["raw_samples"][0]["process_cpu_ns"] = value
                with self.assertRaisesRegex(ValueError, "noninteger native sample"):
                    audit.recompute(changed)

    def test_counter_not_bound_to_native_stdout_is_rejected(self):
        changed = deepcopy(self.performance)
        changed["raw_samples"][0]["involuntary_context_switches"] += 1
        with self.assertRaisesRegex(ValueError, "native output fields"):
            audit.recompute(changed)

    def test_sample_cannot_be_rebound_to_another_library(self):
        changed = deepcopy(self.performance)
        changed["raw_samples"][0]["execution"]["command"][1] = changed["artifacts"]["llvm"]["path"]
        with self.assertRaisesRegex(ValueError, "sample artifact or command"):
            audit.recompute(changed)

    def test_paired_median_forgery_is_rejected(self):
        changed = deepcopy(self.performance)
        changed["evaluation"]["summary"]["full_lifecycle"]["comparisons"]["rust"]["median_paired_time_ratio"] = 0.5
        with self.assertRaisesRegex(ValueError, "paired ratios"):
            audit.recompute(changed)

    def test_actual_archived_library_bytes_are_checked(self):
        changed = dict(self.members)
        name = "attempt2/performance-artifacts/llvm.so"
        changed[name] = b"X" + changed[name][1:]
        with self.assertRaisesRegex(ValueError, "retained native bytes"):
            audit.verify_artifacts(self.performance, changed)

    def test_missing_free_negative_control_cannot_become_a_zero_exit(self):
        changed = deepcopy(self.performance)
        changed["resource_observation"]["negative"]["returncode"] = 0
        with self.assertRaisesRegex(ValueError, "recorded process exit"):
            audit.verify_artifacts(changed, self.members)

    def test_interrupted_attempt_cannot_claim_a_completed_zero_unit_count(self):
        changed = dict(self.members)
        path = "attempt1/interruption-observation.json"
        observation = audit.parse(changed[path])
        observation["unit_completed_test_count"] = 0
        changed[path] = audit.wire(observation)
        with self.assertRaisesRegex(ValueError, "interrupted attempt promoted"):
            audit.review(changed)

    def test_unit_count_in_actual_terminal_log_is_bound(self):
        changed = dict(self.members)
        name = "attempt2/unit_regression.stderr.log"
        changed[name] = changed[name].replace(b"Ran 2093", b"Ran 2092")
        with self.assertRaisesRegex(ValueError, "gate log identity"):
            audit.review(changed)

    def test_report_cannot_be_replaced_by_another_attempt(self):
        changed = dict(self.members)
        report = audit.parse(changed["attempt2/qualification.json"])
        report["git_commit"] = "bdb8690" + "0" * 33
        changed["attempt2/qualification.json"] = audit.wire(report)
        with self.assertRaisesRegex(ValueError, "original report bytes"):
            audit.review(changed)


class ContainerBoundaryTests(unittest.TestCase):
    def fixture(self, directory, *, member_name="data", member_type=tarfile.REGTYPE):
        payload = b"retained bytes\n"
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(member_name)
            info.type = member_type
            info.mode = 0o644
            info.size = len(payload) if member_type == tarfile.REGTYPE else 0
            if member_type == tarfile.SYMTYPE:
                info.linkname = "/outside"
            archive.addfile(info, io.BytesIO(payload) if info.size else None)
        tar = stream.getvalue()
        # Tiny synthetic container only; this does not recompress the full run.
        packed = lzma.compress(tar, preset=0)
        encoded = base64.b64encode(packed) + b"\n"
        name = "fixture.tar.xz.b64"
        (Path(directory) / name).write_bytes(encoded)
        return {"schema": "hepta.hia-candidate.archive.v1", "archive": name,
            "encoding": "base64", "compression": "xz-preset-6-dict-64MiB",
            "parts": [{"path": name, "bytes": len(encoded), "sha256": audit.sha(encoded)}],
            "encoded_bytes": len(encoded), "encoded_sha256": audit.sha(encoded),
            "decoded_bytes": len(packed), "decoded_sha256": audit.sha(packed),
            "tar_bytes": len(tar), "tar_sha256": audit.sha(tar), "member_count": 1,
            "uncompressed_bytes": len(payload) if member_type == tarfile.REGTYPE else 0,
            "members": [{"path": member_name, "bytes": info.size, "sha256": audit.sha(payload if info.size else b""), "mode": 0o644}]}

    def test_real_decoder_checks_content_and_rejects_member_digest_change(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.fixture(directory)
            self.assertEqual(unpack_archive(directory, manifest), {"data": b"retained bytes\n"})
            manifest["members"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "member digest"):
                unpack_archive(directory, manifest)

    def test_symlink_tar_member_and_traversal_are_rejected_without_extraction(self):
        for name, kind in (("data", tarfile.SYMTYPE), ("../outside", tarfile.REGTYPE), ("/outside", tarfile.REGTYPE)):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                manifest = self.fixture(directory, member_name=name, member_type=kind)
                with self.assertRaises(ValueError):
                    unpack_archive(directory, manifest)
                self.assertEqual([p.name for p in Path(directory).iterdir()], ["fixture.tar.xz.b64"])

    def test_part_and_expansion_bounds_are_checked_before_unpack(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.fixture(directory)
            manifest["tar_bytes"] = MAX_TAR + 1
            with self.assertRaisesRegex(ValueError, "expansion bound"):
                unpack_archive(directory, manifest)
            manifest = self.fixture(directory)
            manifest["parts"][0]["path"] = "../../outside"
            with self.assertRaisesRegex(ValueError, "part names/order"):
                unpack_archive(directory, manifest)

    def test_nonregular_input_is_rejected_before_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_bytes(b"x")
            (root / "link").symlink_to(root / "file")
            os.mkfifo(root / "fifo")
            for name in ("link", "fifo"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    read_regular(root, name)

    def test_duplicate_nonfinite_json_and_path_aliases_are_rejected(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                audit.parse(data)
        for name in ("a/../b", "a//b", "./data", "", "a\\b"):
            with self.subTest(path=name), self.assertRaises(ValueError):
                safe_path(name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
