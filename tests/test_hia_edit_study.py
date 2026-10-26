import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from tools.qualify_hia_edit_study import (ARMS, MINIMUM_SUCCESSES, classify_execution, comparison_criteria,
    control_passed, expected, fixtures, native, parse_response, prompt, query_for, run_study, summarize)


class EditStudyTests(unittest.TestCase):
    def test_all_references_execute_and_bug_controls_are_detectable(self):
        tasks=fixtures()
        self.assertEqual(len(tasks),8)
        for task in tasks:
            with self.subTest(task=task["id"]):
                good=parse_response(task,"hia_edit_query",json.dumps({task["field"]:task["good"]}))
                actual=[execute_program(good,"entrypoint",case)["result"] for case in task["cases"]]
                self.assertEqual(actual,expected(task))
                try:
                    wrong=[execute_program(verify_program(task["hia"]),"entrypoint",case)["result"] for case in task["cases"]]
                except HIAProgramTrap:
                    wrong=None
                self.assertNotEqual(wrong,expected(task))
                self.assertEqual(len(good.as_dict()["functions"]),2)
                self.assertEqual(good.as_dict()["exports"],["entrypoint"])

    def test_same_response_protocol_for_all_arms(self):
        for task in fixtures():
            for arm in ARMS:
                with self.subTest(task=task["id"],arm=arm):
                    text=(json.dumps({task["field"]:task["good"]}) if arm.startswith("hia")
                          else json.dumps({"replacement":task["rust_good"]}))
                    parse_response(task,arm,text)
                    with self.assertRaises(Exception):
                        parse_response(task,arm,"```json\n"+text+"\n```")
                    with self.assertRaises(Exception):
                        parse_response(task,arm,text+" explanatory prose")

    def test_hidden_cases_and_allowed_answers_not_leaked_in_prompt(self):
        for task in fixtures():
            for arm in ARMS:
                message=prompt(task,arm)
                self.assertNotIn('"cases":',message)
                self.assertNotIn('"good":',message)
                self.assertNotIn('"allowed":',message)
                self.assertIn("Return ONLY a JSON object",message)

    def test_rust_only_frozen_slots_are_executable(self):
        for task in fixtures():
            with self.assertRaises(ValueError):
                parse_response(task,"rust_edit_query",'{"replacement":"std::process::exit(0)"}')
            self.assertIn(task["rust_bad"],task["rust_template"].replace("@SLOT@",task["rust_bad"]))
            source=parse_response(task,"rust_full_context",json.dumps({"replacement":task["rust_good"]}))
            self.assertEqual(source,task["rust_template"].replace("@SLOT@",task["rust_good"]))

    def test_empty_execution_does_not_invent_success(self):
        for values in summarize([]).values():
            self.assertEqual(values["completed_tasks"],0)
            self.assertEqual(values["successes"],0)
            self.assertEqual(values["planned_tasks"],8)

    def test_query_context_has_definitions_for_every_displayed_instruction_input(self):
        for task in fixtures():
            context=query_for(task)["context"]
            available={value["name"] for value in context["block_params"]}
            instructions=[*context["dependencies"],*context["consumers"],
                          {"index":context["operation_index"],"operation":context["operation"]}]
            for item in sorted(instructions,key=lambda item:item["index"]):
                with self.subTest(task=task["id"],index=item["index"]):
                    op=item["operation"]
                    self.assertTrue(set(op["args"]).issubset(available))
                    available.update(value["name"] for value in op["out"])

    def test_unknown_attempt_cost_is_not_a_zero_total(self):
        arm="hia_edit_query"
        rows=[{"arm":arm,"state":"response_rejected","ok":False,
               "generation":{"usage":{"input_tokens":10,"output_tokens":2}},
               "inference_ns":50,"evaluation_ns":7},
              {"arm":arm,"state":"inference_failed","ok":False}]
        summary=summarize(rows)
        row=summary[arm]
        self.assertEqual((row["attempted_tasks"],row["completed_tasks"]),(2,1))
        self.assertEqual((row["known_input_tokens"],row["known_output_tokens"]),(10,2))
        self.assertEqual((row["known_inference_ns"],row["known_evaluation_ns"]),(50,7))
        for field in ("input_tokens","output_tokens","inference_ns","evaluation_ns"):
            self.assertIsNone(row[field])
        for field in ("unknown_usage_tasks","unknown_inference_tasks","unknown_evaluation_tasks"):
            self.assertEqual(row[field],1)
        for field in ("usage_complete","inference_time_complete","evaluation_time_complete"):
            self.assertFalse(row[field])
        row["successes"]=MINIMUM_SUCCESSES
        self.assertEqual(comparison_criteria(summary,True),(False,False))
        complete=summarize(rows[:1])[arm]
        self.assertTrue(complete["usage_complete"])
        self.assertEqual((complete["input_tokens"],complete["output_tokens"]),(10,2))

    def test_declared_structure_matches_actual_hia_and_rust_sources(self):
        for task in fixtures():
            for arm in ARMS:
                text=prompt(task,arm)
                self.assertNotIn("two-module maintenance",text)
                self.assertIn("two functions in one HIA module" if arm.startswith("hia") else
                              "a Rust caller and kernel in two source files",text)

    def test_comparison_requires_seven_actual_successes(self):
        summary=summarize([])
        for row in summary.values():row.update(completed_tasks=8,input_tokens=100,output_tokens=10)
        summary["hia_edit_query"].update(input_tokens=50)
        self.assertEqual(comparison_criteria(summary,True),(False,False))
        summary["hia_edit_query"]["successes"]=MINIMUM_SUCCESSES-1
        self.assertEqual(comparison_criteria(summary,True),(False,False))
        summary["hia_edit_query"]["successes"]=MINIMUM_SUCCESSES
        self.assertEqual(comparison_criteria(summary,True),(True,True))
        self.assertEqual(comparison_criteria(summary,False),(False,False))


def transcript(values,*,finish=True):
    lines=["STUDY_READY"]
    for index,value in enumerate(values):
        lines += ["STUDY_CALL "+str(index),"STUDY_VALUE "+str(index)+" "+str(value)]
    if finish:lines += ["STUDY_DONE"]
    return "\n".join(lines)+"\n"


class NativeClassificationTests(unittest.TestCase):
    def test_wrong_values_are_distinguished_from_loader_and_format_failures(self):
        task=fixtures()[0]
        values=expected(task)
        correct=classify_execution(task,"hia",0,transcript(values),"")
        self.assertTrue(correct["ok"])
        self.assertTrue(control_passed(task,True,correct))
        values[0]=1-values[0]
        wrong=classify_execution(task,"hia",0,transcript(values),"")
        self.assertEqual(wrong["status"],"observable_wrong")
        self.assertTrue(control_passed(task,False,wrong))
        for code,out,err in ((1,"","OSError: cannot load shared object"),
                             (0,"[1,2,3]",""),(-6,"","")):
            result=classify_execution(task,"hia",code,out,err)
            self.assertEqual(result["status"],"infrastructure_error")
            self.assertFalse(result["native_executed"])
            self.assertFalse(control_passed(task,False,result))

    def test_only_exact_declared_overflow_transcript_counts_as_bug_control(self):
        task=next(task for task in fixtures() if task["id"]=="next_epoch")
        prefix=transcript(expected(task)[:-1],finish=False)+"STUDY_CALL 4\n"
        for language,code,stderr in (("hia",-6,""),("rust",101,"thread 'main' panicked at kernel.rs: overflow")):
            actual=classify_execution(task,language,code,prefix,stderr,overflow_expected=True)
            self.assertEqual(actual["status"],"expected_overflow_trap")
            self.assertTrue(control_passed(task,False,actual))
            for output,err,declared in (("",stderr,True),(prefix,"not an overflow panic",True),(prefix,stderr,False)):
                result=classify_execution(task,language,code,output,err,overflow_expected=declared)
                self.assertEqual(result["status"],"infrastructure_error")


class _FakeEngine:
    fail_generation=False
    fail_identity=False
    task_text="{}"
    instances=[]

    def __init__(self,**kwargs):
        self.generation_count=0;self.response_count=0;self.closed=False
        self.instances.append(self)

    def generate(self,messages,**kwargs):
        self.generation_count+=1
        content=messages[0]["content"]
        preflight=content.startswith("Return exactly this JSON object and nothing else: ")
        if not preflight and self.fail_generation:raise TimeoutError("mock generation interruption")
        self.response_count+=1
        text=content.split(": ",1)[1] if preflight else self.task_text
        return {"text":text,"usage":{"input_tokens":3,"output_tokens":1,"total_tokens":4},"wall_nanoseconds":1}

    def verify_final_identity(self):
        if self.fail_identity:raise OSError("mock final identity failure")
        return {"model_unchanged":True,"runtime_unchanged":True}

    def close(self):self.closed=True


def fake_native(task,candidate,language,directory,clang,rustc):
    correct=str(directory).endswith("_true")
    return {"ok":correct,"native_executed":True,"status":"correct" if correct else
            "expected_overflow_trap" if task["id"]=="next_epoch" else "observable_wrong"}


class StudyFailureRetentionTests(unittest.TestCase):
    def run_mock_study(self,root,engine,*,native_impl=fake_native,identity=None):
        models=[{"id":"small","path":"/mock/small","sha256":"a"*64,"repository":"test/model","revision":"1"*40},
                {"id":"medium","path":"/mock/medium","sha256":"b"*64,"repository":"test/model","revision":"2"*40}]
        identity=identity or (lambda path:{"path":str(path),"bytes":1,"sha256":"c"*64})
        with patch("tools.qualify_hia_edit_study.LlamaCppEngine",engine), \
             patch("tools.qualify_hia_edit_study.file_identity",side_effect=identity), \
             patch("tools.qualify_hia_edit_study.bindings",return_value={"source":"fixed"}), \
             patch("tools.qualify_hia_edit_study.native",side_effect=native_impl):
            return run_study(root,models,"/mock/engine","/mock/clang","/mock/rustc")

    def test_each_model_startup_failure_has_terminal_report_and_all_pending_cells(self):
        with tempfile.TemporaryDirectory() as root, patch("builtins.print"):
            output=Path(root)/"study"
            with patch("tools.qualify_hia_edit_study.LlamaCppEngine",side_effect=RuntimeError("missing model")) as engine:
                report=self.run_mock_study(output,engine)
            self.assertEqual(report["status"],"incomplete_or_identity_failure")
            for model in report["models"]:
                self.assertEqual(model["status"],"model_startup_failed")
                self.assertEqual(len(model["unfinished_cells"]),32)
                self.assertEqual(model["requests_started"],0)
                self.assertTrue((output/model["model"]["id"]/"report.json").is_file())

    def test_interrupted_request_keeps_the_attempt_and_does_not_count_model_failure(self):
        class Interrupted(_FakeEngine):fail_generation=True
        with tempfile.TemporaryDirectory() as root, patch("builtins.print"):
            report=self.run_mock_study(Path(root)/"study",Interrupted)
            for model in report["models"]:
                self.assertEqual(model["status"],"execution_incomplete")
                self.assertEqual(len(model["rows"]),1)
                self.assertEqual(model["rows"][0]["state"],"inference_failed")
                self.assertEqual(model["unresolved_requests"],1)
                self.assertEqual(len(model["unfinished_cells"]),32)
                self.assertEqual(len(model["unstarted_cells"]),31)
                self.assertEqual(sum(x["accepted_but_wrong"] for x in model["summary"].values()),0)
                self.assertEqual(sum(x["rejected"] for x in model["summary"].values()),0)
                attempted=next(x for x in model["summary"].values() if x["attempted_tasks"])
                self.assertEqual(attempted["unknown_usage_tasks"],1)
                self.assertFalse(attempted["usage_complete"])
                self.assertIsNone(attempted["input_tokens"])
                self.assertIsNone(attempted["inference_ns"])

    def test_final_identity_failure_retains_all_completed_response_rejections(self):
        class IdentityFailure(_FakeEngine):fail_identity=True
        with tempfile.TemporaryDirectory() as root, patch("builtins.print"):
            report=self.run_mock_study(Path(root)/"study",IdentityFailure)
            self.assertEqual(report["status"],"incomplete_or_identity_failure")
            self.assertEqual(report["primary_criteria_per_model"],[False,False])
            for model in report["models"]:
                self.assertEqual(model["status"],"model_identity_failure")
                self.assertEqual(len(model["completed_cells"]),32)
                self.assertEqual(model["unfinished_cells"],[])
                self.assertEqual(model["responses_received"],34)

    def test_native_infrastructure_failure_is_unscored_and_leaves_the_study_incomplete(self):
        class CandidateEngine(_FakeEngine):task_text='{"op":"compare.lt"}'
        def infrastructure(task,candidate,language,directory,clang,rustc):
            if "/controls/" in str(directory):return fake_native(task,candidate,language,directory,clang,rustc)
            return {"ok":False,"native_executed":False,"status":"infrastructure_error","reason":"loader failed"}
        with tempfile.TemporaryDirectory() as root, patch("builtins.print"):
            report=self.run_mock_study(Path(root)/"study",CandidateEngine,native_impl=infrastructure)
            self.assertEqual(report["status"],"incomplete_or_identity_failure")
            for model in report["models"]:
                self.assertEqual(model["rows"][0]["state"],"infrastructure_error")
                self.assertEqual(len(model["completed_cells"]),0)
                self.assertEqual(sum(x["accepted_but_wrong"] for x in model["summary"].values()),0)

    def test_changed_rust_compiler_at_final_identity_prevents_completion(self):
        calls={}
        def identity(path):
            calls[path]=calls.get(path,0)+1
            digest="d"*64 if path=="/mock/rustc" and calls[path]>1 else "c"*64
            return {"path":str(path),"bytes":1,"sha256":digest}
        with tempfile.TemporaryDirectory() as root, patch("builtins.print"):
            report=self.run_mock_study(Path(root)/"study",_FakeEngine,identity=identity)
            self.assertFalse(report["toolchain_unchanged"])
            self.assertEqual(report["status"],"incomplete_or_identity_failure")


@unittest.skipUnless(shutil.which("/usr/lib/llvm-20/bin/clang") and
                     shutil.which("/tmp/hepta-ai-rust-1.90.0/bin/rustc"),"actual pinned LLVM and Rust required")
class StudyActualNativeControlTests(unittest.TestCase):
    def test_actual_values_and_both_declared_overflow_boundaries(self):
        selected=[task for task in fixtures() if task["id"] in {"capacity","next_epoch"}]
        with tempfile.TemporaryDirectory() as root:
            for task in selected:
                for language in ("hia","rust"):
                    for correct in (False,True):
                        if language=="hia":
                            candidate=(parse_response(task,"hia_edit_query",json.dumps({task["field"]:task["good"]}))
                                       if correct else verify_program(task["hia"]))
                        else:candidate=task["rust_template"].replace("@SLOT@",task["rust_good"] if correct else task["rust_bad"])
                        name=task["id"]+language+str(correct)
                        result=native(task,candidate,language,Path(root)/name,"/usr/lib/llvm-20/bin/clang","/tmp/hepta-ai-rust-1.90.0/bin/rustc")
                        with self.subTest(task=task["id"],language=language,correct=correct):
                            self.assertTrue(control_passed(task,correct,result),json.dumps(result))


if __name__=="__main__":
    unittest.main()
