"""Evaluator/orchestration controls; none of these are model task successes."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import signal
import time
import unittest
from unittest.mock import patch
from contextlib import ExitStack

from experiments.hia_agent_assembly_v4_20261030 import fixtures, evaluator, run_study
from experiments.hia_agent_assembly_v4_20261030.engine import EnvelopeEngine, generation_deadline
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
            for language in ("hia","assembly","rust"):
                evaluator.parse_files(task,language,canonical({"files":task["correct_"+language]}).decode())
                schema=fixtures.response_schema(language)
                self.assertEqual(schema["required"],["files"])
                self.assertEqual(set(schema["properties"]["files"]["properties"]),set(fixtures.FILE_NAMES[language]))
                self.assertNotIn(task["provider"],canonical(schema).decode())
        self.assertTrue(all(set(map(tuple,t["public_cases"])).isdisjoint(map(tuple,t["hidden_cases"])) for t in self.tasks))

    def test_wrapper_missing_extra_duplicate_or_injected_path_rejected(self):
        for language in ("hia","assembly","rust"):
            files=self.task["correct_"+language]
            variants=[canonical(files).decode(),canonical({"files":files,"extra":0}).decode(),
                      '{"files":'+canonical(files).decode()+',"files":'+canonical(files).decode()+'}',
                      canonical({"files":{**files,"../api.rs":""}}).decode()]
            for text in variants:
                with self.assertRaises(ValueError):
                    evaluator.parse_files(self.task,language,text)

    def test_provider_or_public_signature_and_bypass_rejected(self):
        for language in ("hia","assembly","rust"):
            files=copy.deepcopy(self.task["correct_"+language])
            if language=="hia":
                files["api.hia.json"]["params"][0]["type"]="u16"
            elif language=="assembly":
                files["api.hiaasm"]=files["api.hiaasm"].replace("a:u32","a:u16")
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
            "pub fn average(a:u32,b:u32)->u64 { unsafe { a as u64 } }",
            "pub fn average(a:u32,b:u32)->u64 { std::process::exit(1) }",
            "pub fn average(a:u32,b:u32)->u64 { let x:Option<Vec<u32>>=None; x.unwrap_or_default();0 }",
            "pub fn average(a:u32,b:u32)->u64 { loop { } }",
            "pub fn average(a:u32,b:u32)->u64 { (|x|x)(a) as u64 }",
        ):
            files=copy.deepcopy(self.task["correct_rust"]);files["api.rs"]=source
            with self.assertRaises(ValueError):
                evaluator.parse_files(self.task,"rust",canonical({"files":files}).decode())

    def cell(self):
        return {"id":"average_floor_stamp_hia","task":"average_floor_stamp","stratum":"maintenance","language":"hia"}

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
                ("check_qualified_tools",lambda *_:True),
                ("EnvelopeEngine",Session)):
                stack.enter_context(patch.object(run_study,name,value))
            stack.enter_context(patch.dict("os.environ",{"LLAMA_ARG_REPACK":"0"}))
            stack.enter_context(patch.object(evaluator,"reference_controls",return_value={"count":36,"passed":36}))
            stack.enter_context(patch.object(evaluator,"build",return_value={"status":"compiled","native_built":True}))
            stack.enter_context(patch.object(evaluator,"execute",side_effect=execute))
            if boundary_error:
                stack.enter_context(patch.object(run_study,"check_cell_identities",return_value={"passed":False,"wall_ns":1}))
            result=run_study.run(output=str(Path(td)/"cohort"),model_id=model["id"],model_path="model.gguf",binary="binary",clang="clang",rustc="rustc")
        return result,instances

    def test_timeout_next_distinct_cell_uses_fresh_process_without_retry(self):
        result,engines=self.fake_cohort(first_error=TimeoutError("budget"))
        self.assertEqual(len(result["cells"]),12)
        self.assertTrue(result["valid_observation"]);self.assertFalse(result["usage_complete"])
        self.assertEqual([e.generation_count for e in engines],[1,11])
        self.assertTrue(all(e.process.exited for e in engines))
        self.assertEqual(result["cells"][0]["status"],"budget_timeout")
        self.assertEqual(result["new_requests"],12);self.assertEqual(result["responses_received"],11)
        self.assertEqual(sum(r["correct"] for r in result["cells"]),11)

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

    def test_assembly_representation_has_same_core_and_no_extra_function(self):
        from hepta.hia_program import verify_program
        from experiments.hia_optimizer_eval.next_20261028.upgrade_pilot import document
        for task in self.tasks:
            for label in ("original", "correct"):
                files=task[label+"_assembly"]
                converted,receipt=fixtures.assembly_to_json(task,canonical({"files":files}).decode())
                program=verify_program(document(task,json.loads(converted)["files"]))
                self.assertEqual(program.sha256,verify_program(document(task,task[label+"_hia"])).sha256)
                self.assertFalse(receipt["implicit_repairs"])
                bad=copy.deepcopy(files)
                bad["client.hiaasm"]+=bad["api.hiaasm"]
                with self.assertRaises(ValueError):
                    fixtures.assembly_to_json(task,canonical({"files":bad}).decode())

    def test_qualified_native_tools_and_model_runtime_drift_refused(self):
        identity=lambda name:{"path":name,"bytes":1,"sha256":name}
        tools={key:identity(key) for key in ("clang","rustc","binary")}
        records={"DEVELOPMENT_CONTROLS.json":{"rows":[
            {"build":{"language":"hia","compiler":tools["clang"]}},
            {"build":{"language":"rust","compiler":tools["rustc"]}}]},
            "TOKENIZER_CAPACITY.json":{"models":[{"identity":{"runtime_files":[tools["binary"]]}}]}}
        with patch.object(run_study,"read",side_effect=lambda path:records[Path(path).name]):
            self.assertTrue(run_study.check_qualified_tools(tools,[tools["binary"]]))
            for key in tools:
                bad=copy.deepcopy(tools);bad[key]["sha256"]="changed"
                with self.subTest(key=key),self.assertRaisesRegex(RuntimeError,"identity differs"):
                    run_study.check_qualified_tools(bad,[bad["binary"]])

    def test_real_entire_generate_deadline_covers_preparation_and_drip_response(self):
        for delayed_stage in ("/apply-template", "/completion"):
            with self.subTest(stage=delayed_stage),tempfile.TemporaryDirectory() as td:
                engine=EnvelopeEngine.__new__(EnvelopeEngine)
                engine.output=Path(td);engine.context=8192;engine.generation_count=0;engine.response_count=0
                engine.tokenize=lambda *_args,**_kwargs:[1,2,3]
                def request(endpoint,*_args,**_kwargs):
                    if endpoint==delayed_stage:
                        for _ in range(100):time.sleep(0.01)
                    return {"prompt":"test"}
                engine.request=request
                started=time.monotonic()
                with self.assertRaisesRegex(TimeoutError,"entire generate"):
                    engine.generate([],language="assembly",wall_seconds=0.04)
                self.assertLess(time.monotonic()-started,0.5)
                self.assertEqual(engine.generation_count,1 if delayed_stage=="/completion" else 0)
                self.assertEqual(signal.getitimer(signal.ITIMER_REAL),(0.0,0.0))

    def test_deadline_never_steals_existing_alarm_and_restores_handler(self):
        previous_handler=signal.getsignal(signal.SIGALRM)
        signal.setitimer(signal.ITIMER_REAL,5)
        try:
            with self.assertRaisesRegex(RuntimeError,"OWNER_CONFLICT"):
                with generation_deadline(1):pass
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0],0)
        finally:
            signal.setitimer(signal.ITIMER_REAL,0)
        with generation_deadline(1):pass
        self.assertEqual(signal.getsignal(signal.SIGALRM),previous_handler)

    def test_constructor_identity_write_failure_closes_unassigned_owner(self):
        from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine
        with tempfile.TemporaryDirectory() as td:
            def initialize(self,**_):self.output=Path(td);self.identity={}
            with (patch.object(LlamaCppEngine,"__init__",initialize),patch.object(EnvelopeEngine,"close") as close,
                  patch.object(Path,"write_bytes",side_effect=OSError("identity write failed"))):
                with self.assertRaisesRegex(OSError,"identity write failed"):
                    EnvelopeEngine()
                close.assert_called_once()

    def test_duplicate_task_descriptor_and_missing_identity_cannot_pass(self):
        result,_=self.fake_cohort()
        planned=run_study.scheduled_cells(self.tasks,result["model"]["id"],0)
        cells=copy.deepcopy(result["cells"])
        for stratum in ("maintenance","upgrade"):
            for arm in fixtures.ARMS:
                indexes=[i for i,row in enumerate(cells) if row["stratum"]==stratum and row["language"]==arm]
                cells[indexes[1]]=copy.deepcopy(cells[indexes[0]])
        for rows,identities in ((cells,result["cell_identity_checks"]),(result["cells"],[])):
            checked=run_study.summarize_cells(rows,planned,identities)
            self.assertFalse(any(checked["descriptive_stratum_gates"].values()))
            self.assertFalse(any(checked["assembly_vs_json_gates"].values()))
            self.assertTrue(all(group["validation_total_ns"] is None for group in checked["groups"].values()))

    def test_cohort_rebinds_model_plan_tools_source_registration_and_recomputes_gates(self):
        result,_=self.fake_cohort()
        protocol=run_study.read(run_study.HERE/"PROTOCOL.json");model=result["model"]
        suite={key:result[key] for key in ("registration_sha256","sources","tools","runtime_files")}
        suite["protocol"]=protocol
        plan={**suite,"model":model,"model_file":{"bytes":model["bytes"],"sha256":model["sha256"]},
              "scheduled_cells":run_study.scheduled_cells(self.tasks,model["id"],0)}
        self.assertTrue(run_study.review_model_result(result,plan,suite,model,0)["valid_observation"])
        for key in ("model","registration_sha256","sources","tools","runtime_files","summary"):
            bad=copy.deepcopy(result);bad[key]="different"
            with self.subTest(key=key),self.assertRaises(ValueError):
                run_study.review_model_result(bad,plan,suite,model,0)
        wrong=copy.deepcopy(plan);wrong["scheduled_cells"][0]["model_id"]="other_family"
        with self.assertRaises(ValueError):
            run_study.review_model_result(result,wrong,suite,model,0)

    def test_partial_request_evidence_has_unknown_usage_and_no_parser_failure(self):
        with tempfile.TemporaryDirectory() as td:
            engine=FakeEngine([],td);engine.generation_count=1
            (Path(td)/"transport-001.request.json").write_text('{"payload":')
            self.assertIsNone(run_study.known_transport_input(engine))


if __name__=="__main__":
    unittest.main()
