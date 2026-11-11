"""Fail-closed boundaries of the versioned finite compiler-extension contract."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
import json
import sys

from tools.qualify_hia_original_select_extension import (
    SAMPLE, PROFILE, registered_domain, digest, bytesum_reference,
    native_observation, equal_emitted_bytes, check_coverage, recover_original_inputs,
    run_retained, process_group_members)


class FiniteCompilerExtensionTests(unittest.TestCase):
    def test_domain_registers_original_sources_and_exact_new_inputs(self):
        domain = registered_domain(SAMPLE.read_bytes())
        self.assertEqual(domain["profile"], PROFILE)
        self.assertEqual(domain["domain_kind"], "exact-source-bytes-and-exact-input-bytes")
        self.assertEqual([row["id"] for row in domain["old_sources"]], ["bytesum", "compiler-c0"])
        self.assertEqual([row["id"] for row in domain["new_sources"]], ["u8", "u32", "u64", "usize", "bool"])
        self.assertEqual(sum(len(row["inputs"]) for row in domain["new_sources"]), 64)
        self.assertFalse(domain["historical_support_declaration_is_complete_domain_proof"])
        with self.assertRaisesRegex(ValueError, "old source bytes"):
            registered_domain(SAMPLE.read_bytes() + b"\n")

    def test_old_byte_identity_does_not_accept_replaced_or_empty_output(self):
        self.assertEqual(equal_emitted_bytes(b"\x48\x31\xc0\xc3", b"\x48\x31\xc0\xc3"),
                         digest(b"\x48\x31\xc0\xc3"))
        for before, after in ((b"", b""), (b"\x31\xc0\xc3", b"\x31\xd2\xc3"),
                              (b"\xc3", b"\xc3\x90")):
            with self.subTest(before=before, after=after):
                with self.assertRaisesRegex(ValueError, "old source output"):
                    equal_emitted_bytes(before, after)

    def test_native_observation_binds_result_source_image_and_original_output(self):
        output = b"\x05"
        receipt = {"status": "returned", "abi_status": 0, "core_u32": 5381,
            "source_unchanged": True, "forbidden_compiler_modules_loaded": [],
            "artifact_sha256": "a" * 64, "input_sha256": digest(b""),
            "output_sha256": digest(output)}
        kwargs = {"image_sha256": "a" * 64, "input_sha256": digest(b""),
                  "expected_return": bytesum_reference(b""), "expected_output": output}
        native_observation(receipt, output, **kwargs)
        mutations = {"status": "timeout", "abi_status": 1, "core_u32": 0,
            "source_unchanged": False, "forbidden_compiler_modules_loaded": ["hepta.hia_program_native"],
            "artifact_sha256": "b" * 64, "input_sha256": "c" * 64, "output_sha256": "d" * 64}
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = {**receipt, field: value}
                with self.assertRaisesRegex(ValueError, "native observation"):
                    native_observation(changed, output, **kwargs)
        with self.assertRaisesRegex(ValueError, "native observation"):
            native_observation(receipt, b"\x06", **kwargs)

    def coverage_fixture(self):
        domain = registered_domain(SAMPLE.read_bytes())
        old = [{"id": row["id"], "source_sha256": row["source_sha256"],
                "exact_emitted_bytes_equal": True,
                "observations": [{"version": version, "input_sha256":
                    item.get("input_sha256") or digest(bytes.fromhex(item["input_hex"]))}
                    for item in row["inputs"] for version in ("before", "after")]}
               for row in domain["old_sources"]]
        new = [{"type": row["id"], "source_binding": {"source_sha256": row["source_sha256"]},
                "whole_generated_program_finite_calls": len(row["inputs"]),
                "status": "smt_validated", "agent_proof_receipt_issued": False}
               for row in domain["new_sources"]]
        controls = [{"id": row["id"]} for row in domain["old_refusal_controls"]]
        return domain, old, new, controls

    def test_empty_dropped_duplicate_or_substituted_domains_fail(self):
        values = self.coverage_fixture()
        check_coverage(*values)
        variants = []
        for index in (1, 2, 3):
            empty = copy.deepcopy(values)
            empty[index].clear()
            variants.append(empty)
        dropped = copy.deepcopy(values)
        dropped[1][0]["observations"].pop()
        variants.append(dropped)
        duplicate = copy.deepcopy(values)
        duplicate[1][0]["observations"][0] = copy.deepcopy(duplicate[1][0]["observations"][1])
        variants.append(duplicate)
        substituted = copy.deepcopy(values)
        substituted[2][0]["source_binding"]["source_sha256"] = "f" * 64
        variants.append(substituted)
        missing_new_input = copy.deepcopy(values)
        missing_new_input[2][0]["whole_generated_program_finite_calls"] -= 1
        variants.append(missing_new_input)
        unknown_proof = copy.deepcopy(values)
        unknown_proof[2][0]["status"] = "unknown"
        variants.append(unknown_proof)
        promoted_claim = copy.deepcopy(values)
        promoted_claim[2][0]["agent_proof_receipt_issued"] = True
        variants.append(promoted_claim)
        for index, variant in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    check_coverage(*variant)

    @unittest.skipUnless(sys.platform == "linux", "qualifier process ownership is Linux-specific")
    def test_timeout_terminates_only_the_owned_group_including_a_stubborn_grandchild(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            pidfile = directory / "grandchild.pid"
            child = ("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)")
            parent = ("import subprocess,sys,time; from pathlib import Path; "
                      "p=subprocess.Popen([sys.executable,'-c',sys.argv[2]]); "
                      "Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)")
            with self.assertRaisesRegex(ValueError, "timed out"):
                run_retained([sys.executable, "-c", parent, str(pidfile), child],
                             directory, "owned-timeout", 0.3, own_process_group=True)
            record = json.loads((directory / "owned-timeout.process.json").read_bytes())
            self.assertEqual(record["status"], "timeout")
            self.assertEqual(record["termination"]["remaining_live_pids"], [])
            self.assertIn(15, record["termination"]["signals"])
            self.assertIn(9, record["termination"]["signals"])
            self.assertTrue(pidfile.exists())
            self.assertFalse(any(row["state"] not in {"Z", "X"}
                for row in process_group_members(record["owned_process_group"])))

    def test_unpinned_archive_is_not_inspected_or_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "not-the-original.zip"
            archive.write_bytes(b"not an original archive")
            with self.assertRaisesRegex(ValueError, "archive byte count"):
                recover_original_inputs(archive, root / "output")
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
