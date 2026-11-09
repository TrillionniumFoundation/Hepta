"""Proof boundary checks; real positive execution runs in both CI rows."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import qualify_hia_entry_proof as proof

class EntryProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = [Path(self.temp.name) / n for n in ("source", "object", "image")]
        for p in self.paths: p.write_bytes(p.name.encode())
        expected = {"caller_contract_nonvacuous":"sat", "machine_memory_access_bounds":"unsat",
            "sysv_stack_alignment_and_preservation":"unsat", "all_inputs_reach_a_terminal_model_outcome":"unsat",
            "core_to_final_image_return_abort_and_caller_bytes":"unsat"}
        self.report = {"ok":True, "status":"smt_validated_not_executed",
            "inputs":{n:proof.identity(p) for n,p in zip(("source","object","image"),self.paths)},
            "compiler_invoked":False, "linker_invoked":False, "native_execution_observed":False,
            "adopted":False, "unproved_obligations":[{"status":"unproved"}],
            "validation":{"profile":proof.PROFILE,"ok":True,"complete":True,
                "subject":{"object_sha256":proof.identity(self.paths[1])["sha256"],
                           "final_image_sha256":proof.identity(self.paths[2])["sha256"]},
                "obligations":[{"name":k,"expected":v,"result":v} for k,v in expected.items()]}}

    def test_unchanged_complete_receipt_boundary(self):
        proof.validate_proof(self.report, *self.paths)

    def test_each_changed_artifact_is_rejected(self):
        for path in self.paths:
            original = path.read_bytes(); path.write_bytes(original + b"changed")
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                proof.validate_proof(self.report, *self.paths)
            path.write_bytes(original)

    def test_wrong_profile_or_incomplete_proof_is_rejected(self):
        for key,value in (("profile","other-profile"),("complete",False),("ok",False)):
            row=deepcopy(self.report); row["validation"][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):
                proof.validate_proof(row,*self.paths)

    def test_missing_duplicate_unknown_and_failed_obligations_are_rejected(self):
        changes = [lambda r:r.pop(), lambda r:r.__setitem__(0,r[1]),
                   lambda r:r[0].update(result="unknown"), lambda r:r[1].update(result="sat")]
        for change in changes:
            row=deepcopy(self.report); change(row["validation"]["obligations"])
            with self.assertRaises(ValueError): proof.validate_proof(row,*self.paths)

    def test_subject_substitution_is_rejected(self):
        for key in ("object_sha256","final_image_sha256"):
            row=deepcopy(self.report); row["validation"]["subject"][key]="0"*64
            with self.assertRaises(ValueError): proof.validate_proof(row,*self.paths)

    def test_proof_scope_cannot_be_promoted(self):
        for key in ("compiler_invoked","linker_invoked","native_execution_observed","adopted"):
            row=deepcopy(self.report); row[key]=True
            with self.assertRaises(ValueError): proof.validate_proof(row,*self.paths)
        row=deepcopy(self.report); row["unproved_obligations"]=[]
        with self.assertRaises(ValueError): proof.validate_proof(row,*self.paths)

    def test_evidence_cannot_modify_pinned_source(self):
        root=Path(self.temp.name)
        with self.assertRaises(ValueError): proof.qualify("current",root,root,root/"evidence")

    def test_existing_evidence_is_never_replaced(self):
        root=Path(self.temp.name)
        with self.assertRaises(FileExistsError): proof.qualify("current",root/"source-tree",root/"runtime-tree",root)

    def test_timeout_preserves_command_cost_and_stream_identities(self):
        root=Path(self.temp.name)
        with patch.object(proof.subprocess,"run",side_effect=proof.subprocess.TimeoutExpired(["python"],180)):
            report=proof.qualify("current",root/"source-tree",root/"runtime-tree",root/"timeout")
        self.assertFalse(report["ok"])
        command=report["commands"][0]
        self.assertTrue(command["timed_out"])
        self.assertIsNone(command["exit_code"])
        self.assertGreaterEqual(command["elapsed_seconds"],0)
        self.assertEqual(command["stdout"]["bytes"],0)
        self.assertEqual(command["stderr"]["bytes"],0)
        self.assertTrue((root/"timeout/REPORT.json").is_file())

    def test_launch_error_is_retained_without_success_or_replay(self):
        root=Path(self.temp.name)
        with patch.object(proof.subprocess,"run",side_effect=FileNotFoundError("missing interpreter")) as run:
            report=proof.qualify("current",root/"source-tree",root/"runtime-tree",root/"launch-error")
        self.assertEqual(run.call_count,1)
        self.assertFalse(report["ok"])
        command=report["commands"][0]
        self.assertFalse(command["timed_out"])
        self.assertEqual(command["execution_error"]["type"],"FileNotFoundError")
        self.assertGreaterEqual(command["elapsed_seconds"],0)

if __name__ == "__main__": unittest.main()
