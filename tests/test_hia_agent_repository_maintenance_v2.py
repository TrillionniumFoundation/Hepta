"""Protocol/ledger regressions; synthetic events are never model outcomes."""
import json
import io
import hashlib
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from types import SimpleNamespace

from tools import qualify_hia_agent_repository_maintenance_v2 as study


class CohortProtocolTests(unittest.TestCase):
    def active(self):
        events = study.CohortEvents([])
        events.line(json.dumps({"type":"thread.started","thread_id":"fixture"}))
        events.line('{"type":"turn.started"}')
        return events

    def test_reasoning_is_not_answer_and_tools_still_reject(self):
        events = self.active()
        events.line(json.dumps({"type":"item.completed","item":{
            "id":"r","type":"reasoning","text":"parser fixture"}}))
        self.assertEqual(events.messages,[])
        with self.assertRaises(study.EventFailure):
            events.line(json.dumps({"type":"item.started","item":{
                "id":"t","type":"command_execution","command":"forbidden"}}))

    def test_reasoning_cannot_smuggle_fields_or_cross_turn(self):
        for item in ({"id":"r","type":"reasoning","text":"x","command":"no"},
                     {"id":"r","type":"reasoning","text":["not text"]}):
            with self.assertRaises(study.EventFailure):
                self.active().line(json.dumps({"type":"item.completed","item":item}))
        with self.assertRaises(study.EventFailure):
            study.CohortEvents([]).line(json.dumps({"type":"item.completed","item":{
                "id":"r","type":"reasoning","text":"out of turn"}}))

    def test_actual_usage_and_single_answer_required(self):
        events = self.active()
        usage = {"input_tokens":15,"cached_input_tokens":10,"cache_write_input_tokens":0,
                 "output_tokens":3,"reasoning_output_tokens":2}
        events.line(json.dumps({"type":"item.completed","item":{
            "id":"m","type":"agent_message","text":"{}"}}))
        events.line(json.dumps({"type":"turn.completed","usage":usage}))
        self.assertEqual(events.complete(),{"text":"{}","usage":usage})
        with self.assertRaises(study.EventFailure):
            events.line('{"type":"item.completed","item":{"id":"late","type":"reasoning"}}')

    def test_fixed_models_and_inherited_budget(self):
        value = study.protocol()
        self.assertEqual(value["generation"],study.base.cfg()["generation"])
        self.assertEqual(value["model_order"],["qwen_coder1_5b","qwen_coder7b","codex_gpt61_sol"])
        self.assertEqual(value["generation"]["attempts_per_cell"],2)
        self.assertIn("benchmarks/hia_agent_public_tools/PROTOCOL.json",study.bindings())

    def test_missing_compiler_is_infrastructure_not_candidate_feedback(self):
        task = study.base.cfg()["tasks"][0]
        with TemporaryDirectory() as directory, patch.object(study.base,"build_program_native",side_effect=FileNotFoundError("fixture unavailable clang")):
            result = study.evaluate(task,"hia_full",study.base.reference(task,"hia_full"),Path(directory)/"case","/missing/clang")
        self.assertEqual(result["status"],"infrastructure_failure")
        self.assertEqual(result["failure_stage"],"compiler")
        self.assertFalse(result["accepted"])

    def test_runtime_symlink_cannot_escape_archive_binding(self):
        with TemporaryDirectory() as directory:
            root = Path(directory);assets = root/"assets";assets.mkdir()
            receipts = root/"receipts";receipts.mkdir()
            (assets/"m.gguf").write_bytes(b"m")
            model_hash = hashlib.sha256(b"m").hexdigest()
            (receipts/"m.json").write_text(json.dumps({"verified":True,"observed_sha256":model_hash,
                "observed_bytes":1,"complete_wall_ns":1}))
            archive = assets/"fixture.tar.gz"
            with tarfile.open(archive,"w:gz") as bundle:
                for name,data in (("runtime/llama-server",b"x"),("runtime/libfixture.so.1",b"good")):
                    member = tarfile.TarInfo(name);member.size=len(data);bundle.addfile(member,io.BytesIO(data))
                member = tarfile.TarInfo("runtime/libfixture.so")
                member.type=tarfile.SYMTYPE;member.linkname="libfixture.so.1";bundle.addfile(member)
            with tarfile.open(archive,"r:gz") as bundle:
                bundle.extractall(assets,filter="data")
            identity = study.file_identity(archive)
            (receipts/"llama-runtime.json").write_text(json.dumps({"complete_wall_ns":1}))
            configuration = {"models":[{"id":"m","provider":"local_gguf","filename":"m.gguf",
                "sha256":model_hash,"bytes":1}],"runtime":{"archive":archive.name,
                "sha256":identity["sha256"],"bytes":identity["bytes"]}}
            args = SimpleNamespace(assets=assets,downloads=receipts)
            self.assertEqual(len(study.admitted_assets(args,configuration)["runtime"]["identity"]),3)
            external = root/"external.so";external.write_bytes(b"good")
            link = assets/"runtime/libfixture.so";link.unlink();link.symlink_to(external)
            with self.assertRaisesRegex(ValueError,"symlink differs"):
                study.admitted_assets(args,configuration)


class CohortCostTests(unittest.TestCase):
    def result(self):
        usage = {"input_tokens":15,"cached_input_tokens":10,"cache_write_input_tokens":1,
                 "output_tokens":3,"reasoning_output_tokens":2}
        return {"status":"completed","wall_ns":47,"cells":[
            {"task":str(i),"arm":arm,"wall_ns":10,"correct":i==0,"status":"correct" if i==0 else "public_failed",
             "attempts":[{"usage":dict(usage),"generation_requested":True}]}
            for arm in study.base.cfg()["arms"] for i in range(2)]}

    def test_shared_wall_balances_and_acquisition_is_explicit(self):
        probe = {"probe_wall_ns":5,"probe_usage":{"separate_fixture":True}}
        result = study.summarize_model({"provider":"codex_cli"},self.result(),100,0,
                                      campaign_share=9,probe=probe)
        arms = list(result["arms"].values())
        self.assertEqual(sum(a["allocated_noncell_runtime_ns"] for a in arms),7)
        self.assertEqual(sum(a["allocated_campaign_admission_ns"] for a in arms),9)
        self.assertEqual(sum(a["allocated_execution_and_acquisition_ns"] for a in arms),47+9+200+10)
        self.assertEqual(arms[0]["cached_input_tokens"],20)
        self.assertEqual(arms[0]["cache_write_input_tokens"],2)
        self.assertEqual(arms[0]["known_total_reported_tokens"],36)
        self.assertFalse(arms[0]["cross_provider_token_cost_comparable"])

    def test_unknown_usage_never_yields_complete_cost_per_success(self):
        value = self.result()
        value["cells"][1]["status"]="incomplete"
        value["cells"][1]["attempts"][0]["usage"]=None
        arms = study.summarize_model({"provider":"codex_cli"},value,0,0)["arms"]
        affected = arms[study.base.cfg()["arms"][0]]
        self.assertEqual(affected["unknown_usage_attempts"],1)
        self.assertFalse(affected["complete_coverage_and_usage"])
        self.assertIsNone(affected["tokens_per_success"])
        self.assertIsNone(affected["runtime_ns_per_success"])

    def test_infrastructure_failure_cannot_claim_coverage(self):
        value = self.result();value["status"]="infrastructure_failure"
        summaries = study.summarize_model({"provider":"codex_cli"},value,0,0)["arms"]
        self.assertTrue(all(not s["complete_coverage_and_usage"] for s in summaries.values()))

    def test_campaign_drift_revokes_per_success_without_erasing_raw_cost(self):
        summaries = study.summarize_model({"provider":"codex_cli"},self.result(),100,0,campaign_valid=False)["arms"]
        for row in summaries.values():
            self.assertFalse(row["complete_coverage_and_usage"])
            self.assertIsNone(row["tokens_per_success"])
            self.assertGreater(row["known_total_reported_tokens"],0)
            self.assertGreater(row["allocated_execution_and_acquisition_ns"],0)


if __name__=="__main__":
    unittest.main()
