"""Evaluator/orchestration controls; none of these are model task successes."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from experiments.hia_agent_matched_v3_20261028 import fixtures, evaluator, run_study
from tools.provider_adapter.llama_cpp_engine import canonical


class FakeEngine:
    def __init__(self, outputs, directory):
        self.outputs=list(outputs);self.generation_count=0;self.output=Path(directory)
        self.messages=[]

    def generate(self,messages,**kwargs):
        self.messages.append(copy.deepcopy(messages));self.generation_count+=1
        path=self.output/("transport-"+str(self.generation_count).zfill(3)+".request.json")
        path.write_bytes(canonical({"payload":{"prompt":[1,2,3]}}))
        value=self.outputs.pop(0)
        if isinstance(value,Exception):
            raise value
        return {"text":value,"usage":{"input_tokens":3,"output_tokens":7,"total_tokens":10},"wall_nanoseconds":17}


class ProtocolControls(unittest.TestCase):
    def setUp(self):
        self.tasks=fixtures.make_fixtures();self.task=self.tasks[0]

    def test_reference_interfaces_and_common_answer_free_envelope(self):
        for task in self.tasks:
            for language in ("hia","rust"):
                evaluator.parse_files(task,language,canonical({"files":task["correct_"+language]}).decode())
                schema=fixtures.response_schema(language)
                self.assertEqual(schema["required"],["files"])
                self.assertEqual(set(schema["properties"]["files"]["properties"]),set(fixtures.FILE_NAMES[language]))
                self.assertNotIn(task["provider"],canonical(schema).decode())
        self.assertTrue(all(set(map(tuple,t["public_cases"])).isdisjoint(map(tuple,t["hidden_cases"])) for t in self.tasks))

    def test_wrapper_missing_extra_duplicate_or_injected_path_rejected(self):
        for language in ("hia","rust"):
            files=self.task["correct_"+language]
            variants=[canonical(files).decode(),canonical({"files":files,"extra":0}).decode(),
                      '{"files":'+canonical(files).decode()+',"files":'+canonical(files).decode()+'}',
                      canonical({"files":{**files,"../api.rs":""}}).decode()]
            for text in variants:
                with self.assertRaises(ValueError):
                    evaluator.parse_files(self.task,language,text)

    def test_provider_or_public_signature_and_bypass_rejected(self):
        for language in ("hia","rust"):
            files=copy.deepcopy(self.task["correct_"+language])
            if language=="hia":
                files["api.hia.json"]["params"][0]["type"]="u16"
            else:
                files["api.rs"]=files["api.rs"].replace("a:u32","a:u16")
            with self.assertRaises(Exception):
                evaluator.parse_files(self.task,language,canonical({"files":files}).decode())
        files=copy.deepcopy(self.task["correct_rust"])
        files["client.rs"]="use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (a as u64) + (b as u64) }"
        with self.assertRaisesRegex(ValueError,"PROVIDER_CALL_COUNT"):
            evaluator.parse_files(self.task,"rust",canonical({"files":files}).decode())

    def test_scalar_exfiltration_allocation_alias_and_loop_are_not_admitted(self):
        for source in (
            "pub fn total(a:u32,b:u32)->u64 { unsafe { a as u64 } }",
            "pub fn total(a:u32,b:u32)->u64 { std::process::exit(1) }",
            "pub fn total(a:u32,b:u32)->u64 { let x:Option<Vec<u32>>=None; x.unwrap_or_default();0 }",
            "pub fn total(a:u32,b:u32)->u64 { loop { } }",
            "pub fn total(a:u32,b:u32)->u64 { (|x|x)(a) as u64 }",
        ):
            files=copy.deepcopy(self.task["correct_rust"]);files["api.rs"]=source
            with self.assertRaises(ValueError):
                evaluator.parse_files(self.task,"rust",canonical({"files":files}).decode())

    def cell(self):
        return {"id":"carry_sum_tag_hia","task":"carry_sum_tag","stratum":"maintenance","language":"hia"}

    def protocol(self):
        return {"attempts_per_cell":2,"max_output_tokens":2048,"request_wall_seconds":180}

    def test_timeout_is_terminal_unknown_output_not_zero_or_second_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            engine=FakeEngine([TimeoutError("budget")],td)
            row,usable=run_study.run_cell(self.cell(),self.task,Path(td)/"cell",engine,"clang","rustc",{},self.protocol())
            self.assertFalse(usable);self.assertFalse(row["correct"])
            self.assertEqual(len(row["attempts"]),1);self.assertEqual(row["input_tokens"],3)
            self.assertIsNone(row["output_tokens"]);self.assertIsNone(row["total_tokens"])
            self.assertEqual(row["automatic_repair_rounds"],0)

    def test_public_failure_gets_one_repair_and_hidden_failure_no_more_feedback(self):
        with tempfile.TemporaryDirectory() as td:
            engine=FakeEngine(["bad","good"],td)
            first={"status":"response_rejected","native_built":False,"error":{"message":"wrong field"}}
            second={"status":"compiled","native_built":True}
            public={"status":"correct","artifact_unchanged":True,"cases":[[1,2,3]],"expected":[4],"actual":[4]}
            hidden={"status":"observable_wrong","artifact_unchanged":True,"cases":[[98765,0,0]],"expected":[98765],"actual":[0]}
            with patch.object(evaluator,"build",side_effect=[first,second]),patch.object(evaluator,"execute",side_effect=[public,hidden]):
                row,usable=run_study.run_cell(self.cell(),self.task,Path(td)/"cell",engine,"clang","rustc",{},self.protocol())
            self.assertTrue(usable);self.assertEqual(row["status"],"hidden_validation_failed")
            self.assertEqual(len(engine.messages),2);self.assertEqual(row["automatic_repair_rounds"],1)
            self.assertNotIn("98765",canonical(engine.messages).decode())
            self.assertIn("wrong field",canonical(engine.messages[-1]).decode())

    def test_source_drift_before_request_prevents_any_generation(self):
        with tempfile.TemporaryDirectory() as td:
            engine=FakeEngine(["bad"],td)
            with self.assertRaisesRegex(RuntimeError,"source drift"):
                run_study.run_cell(self.cell(),self.task,Path(td)/"cell",engine,"clang","rustc",{"missing.py":"x"},self.protocol())
            self.assertEqual(engine.generation_count,0)

    def test_native_infrastructure_failure_retains_submission_and_stops(self):
        with tempfile.TemporaryDirectory() as td:
            engine=FakeEngine(["complete response"],td)
            with patch.object(evaluator,"build",side_effect=RuntimeError("artifact identity drift")):
                row,usable=run_study.run_cell(self.cell(),self.task,Path(td)/"cell",engine,"clang","rustc",{},self.protocol())
            self.assertFalse(usable);self.assertEqual(row["status"],"native_infrastructure_failure")
            self.assertEqual(row["total_tokens"],10)
            self.assertTrue((Path(td)/"cell"/"attempt-0.evaluation.json").exists())
            self.assertTrue((Path(td)/"cell"/"CELL.json").exists())

    def fake_cohort(self, first_error=None, native_error=False, boundary_error=False):
        instances=[]
        model=run_study.read(run_study.HERE/"PROTOCOL.json")["models"][0]

        class Process:
            def __init__(self): self.exited=False
            def poll(self): return 0 if self.exited else None

        class Session(FakeEngine):
            def __init__(self, **kwargs):
                directory=Path(kwargs["output_dir"]);directory.mkdir()
                super().__init__([],directory)
                self.response_count=0;self.process=Process();instances.append(self)
            def generate(self,messages,**kwargs):
                self.outputs.append(first_error if first_error is not None and len(instances)==1 and self.generation_count==0 else "mock candidate")
                result=super().generate(messages,**kwargs);self.response_count+=1;return result
            def verify_final_identity(self): return {"model_unchanged":True,"runtime_unchanged":True}
            def close(self): self.process.exited=True

        def identity(path):
            return {"path":str(path),"bytes":model["bytes"] if str(path)=="model.gguf" else 1,
                    "sha256":model["sha256"] if str(path)=="model.gguf" else "fixed"}

        def execute(built,task,cases,expected):
            if native_error: raise RuntimeError("native image identity drift")
            return {"status":"correct","artifact_unchanged":True,"cases":cases,"expected":expected,"actual":expected}

        with tempfile.TemporaryDirectory() as td,ExitStack() as stack:
            for name,value in (("validate_registration",lambda:{"sources":{}}),("file_identity",identity),
                ("runtime_bindings",lambda _:[]),("validate_runtime_environment",lambda _:{"matches":True}),
                ("EnvelopeEngine",Session)):
                stack.enter_context(patch.object(run_study,name,value))
            stack.enter_context(patch.dict("os.environ",{"LLAMA_ARG_REPACK":"0"}))
            stack.enter_context(patch.object(evaluator,"reference_controls",return_value={"count":24,"passed":24}))
            stack.enter_context(patch.object(evaluator,"build",return_value={"status":"compiled","native_built":True}))
            stack.enter_context(patch.object(evaluator,"execute",side_effect=execute))
            if boundary_error:
                stack.enter_context(patch.object(run_study,"check_cell_identities",return_value={"passed":False,"wall_ns":1}))
            result=run_study.run(output=str(Path(td)/"cohort"),model_id=model["id"],model_path="model.gguf",binary="binary",clang="clang",rustc="rustc")
        return result,instances

    def test_timeout_next_distinct_cell_uses_fresh_process_without_retry(self):
        result,engines=self.fake_cohort(first_error=TimeoutError("budget"))
        self.assertEqual(len(result["cells"]),8)
        self.assertTrue(result["valid_observation"]);self.assertFalse(result["usage_complete"])
        self.assertEqual([e.generation_count for e in engines],[1,7])
        self.assertTrue(all(e.process.exited for e in engines))
        self.assertEqual(result["cells"][0]["status"],"budget_timeout")
        self.assertEqual(result["new_requests"],8);self.assertEqual(result["responses_received"],7)
        self.assertEqual(sum(r["correct"] for r in result["cells"]),7)

    def test_native_failure_and_boundary_drift_stop_before_next_cell(self):
        for kwargs in ({"native_error":True},{"boundary_error":True}):
            result,engines=self.fake_cohort(**kwargs)
            self.assertFalse(result["valid_observation"]);self.assertEqual(len(result["cells"]),1)
            self.assertEqual(result["new_requests"],1);self.assertEqual(result["responses_received"],1)
            self.assertEqual(result["cells"][0]["total_tokens"],10)
            self.assertEqual(len(engines),1);self.assertTrue(engines[0].process.exited)

    def test_engine_identity_protocol_failure_is_fatal_not_restart(self):
        result,engines=self.fake_cohort(first_error=RuntimeError("E_GGUF_OWNER: peer differs"))
        self.assertFalse(result["valid_observation"]);self.assertEqual(len(result["cells"]),1)
        self.assertEqual(result["cells"][0]["status"],"generation_infrastructure_failure")
        self.assertEqual(len(engines),1);self.assertEqual(result["new_requests"],1)

    def test_missing_cells_fail_gates_and_unknown_total_not_partial_sum(self):
        result=run_study.summarize_cells([],[])
        self.assertFalse(any(result["descriptive_stratum_gates"].values()))
        with tempfile.TemporaryDirectory() as td:
            engine=FakeEngine([TimeoutError("budget")],td)
            row,_=run_study.run_cell(self.cell(),self.task,Path(td)/"cell",engine,"clang","rustc",{},self.protocol())
            report=run_study.summarize_cells([row],[self.cell()])
            self.assertIsNone(report["groups"]["maintenance:hia"]["total_tokens"])
            self.assertFalse(report["descriptive_stratum_gates"]["maintenance"])


if __name__=="__main__":
    unittest.main()
