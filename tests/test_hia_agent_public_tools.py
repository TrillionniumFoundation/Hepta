"""Public tool boundary, independent oracle and real owned-process controls."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools import qualify_hia_agent_public_tools as study
from tools.hia_agent_codex_transport import (CodexEvents, EventFailure, canonical,
    recover_reported_usage, run_owned)


class PublicAgentProtocolTests(unittest.TestCase):
    def test_author_references_execute_against_independent_new_oracles(self):
        for task in study.TASKS:
            verified = verify_program(study.TASK_MODULE.reference(task["id"], "hia"))
            study.candidate_constraints(task, "hia", verified.as_dict())
            for pair in study.TASK_MODULE.cases(task, hidden=True):
                with self.subTest(task=task["id"], args=pair):
                    report = execute_program(verified, "target", pair, max_steps=100000, max_heap_bytes=1048576)
                    self.assertEqual(report["result"], study.TASK_MODULE.oracle(task["id"], *pair))
                    self.assertEqual(report["resources"]["live_owners"], 0)
                    self.assertEqual(report["resources"]["live_local_loans"], 0)

    def test_prompt_never_contains_hidden_cases_or_reference_answers(self):
        for task in study.TASKS:
            for lang in ("hia", "rust"):
                prompt = study.public_prompt(task, lang)
                self.assertEqual([row["args"] for row in prompt["public_cases"]], task["public"])
                self.assertNotIn("hidden", prompt)
                self.assertNotIn("reference", prompt)
                self.assertNotEqual(prompt["representation"], study.TASK_MODULE.reference(task["id"], lang))

    def test_closed_rpc_rejects_duplicate_unknown_and_smuggled_fields(self):
        for text in ('{"action":"catalog","action":"check"}', '{"action":"exec","command":"true"}',
                     '{"action":"catalog","path":"tasks.py"}', '{"action":"final","candidate":{},"candidate_digest":"x"}',
                     '{"action":"check"}', '[{"action":"catalog"}]', '{"action":[]}', '{"action":{}}',
                     '{"action":"final","candidate_digest":[]}', '{"action":"final","candidate_digest":false}',
                     '{"action":"check","candidate":NaN}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                study.parse_action(text)

    def test_terminal_hidden_feedback_cannot_enter_model_history(self):
        with self.assertRaisesRegex(ValueError, "hidden feedback"):
            study.public_feedback({"hidden_evaluated": True, "accepted": False,
                                   "execution": {"expected": [123456789]}}, "d")

    def test_resource_task_rejects_equivalent_scalar_shortcut(self):
        task = study.task_for("buffer_lane")
        with self.assertRaisesRegex(ValueError, "allocation"):
            study.candidate_constraints(task, "hia", study.TASK_MODULE.program([
                study.TASK_MODULE.block("entry", ["x", "y"], [], study.TASK_MODULE.ret("x"))]))
        # Rust resource evidence comes from the actual audited runtime below,
        # not from searching source strings for a macro or drop token.
        study.candidate_constraints(task, "rust", "fn target(x:u32,y:u32)->u32 { 256*(x%17+1)+x.wrapping_add(y)%256 }")

    def test_fallible_allocation_obeys_the_same_owned_buffer_contract(self):
        task = study.task_for("buffer_lane")
        candidate = study.TASK_MODULE.reference(task["id"], "hia")
        operation = next(op for op in candidate["functions"][0]["blocks"][0]["ops"] if op["op"] == "buffer.new")
        operation["op"] = "buffer.try_new"
        operation["out"].append({"name": "allocation_succeeded", "type": "bool"})
        study.candidate_constraints(task, "hia", candidate)
        program = verify_program(candidate)
        for args in task["public"]:
            observed = execute_program(program, "target", args)
            self.assertEqual(observed["result"], study.TASK_MODULE.oracle(task["id"], *args))
            self.assertEqual(observed["resources"]["allocations"], 1)
            self.assertEqual(observed["resources"]["frees"], 1)

    def test_store_load_in_uncalled_helper_do_not_satisfy_resource_task(self):
        import copy
        task=study.task_for("buffer_lane")
        candidate=study.TASK_MODULE.reference(task["id"],"hia")
        helper=copy.deepcopy(candidate["functions"][0])
        helper["name"]="uncalled"
        ops=candidate["functions"][0]["blocks"][0]["ops"]
        ops[:]=[op for op in ops if op["op"] not in {"buffer.store","buffer.load"}]
        next(op for op in ops if op["out"] and op["out"][0]["name"]=="readback")["args"]=["byte"]
        candidate["functions"].append(helper)
        study.candidate_constraints(task,"hia",candidate)
        verify_program(candidate)
        with self.assertRaisesRegex(ValueError,"actual matching"):
            study.execute_hia_contract(candidate,task,[16,31])

    @unittest.skipUnless(Path(study.protocol()["rustc"]).is_file(), "requires registered Rust compiler for native ABI negative")
    def test_numerically_correct_wrong_rust_signature_is_rejected_by_native_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            # This candidate compiled and passed the old value-only wrapper.
            wrong = "fn target(x:u32,y:u32)->u64 { y.min(1000u32.saturating_sub(x)) as u64 }"
            result = study.evaluate(study.task_for("quota_clip"), "rust", Path(temporary) / "wrong-signature", candidate=wrong)
            self.assertFalse(result["accepted"])
            self.assertEqual(result["status"], "compile_rejected")
            self.assertFalse(result["hidden_evaluated"])

    @unittest.skipUnless(Path(study.protocol()["rustc"]).is_file(), "requires registered Rust compiler for resource negative")
    def test_comment_scalar_shortcut_fails_actual_public_resource_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            wrong="fn target(x:u32,y:u32)->u32 { /* vec![0u8;1]; drop(fake); fake[0] */ 256*(x%17+1)+x.wrapping_add(y)%256 }"
            result=study.evaluate(study.task_for("buffer_lane"),"rust",Path(temporary)/"comment-shortcut",candidate=wrong)
            self.assertFalse(result["accepted"])
            self.assertEqual(result["status"],"cases_failed")
            self.assertFalse(result["resource_audit"]["accepted"])

    def test_unknown_usage_or_incomplete_denominator_never_passes_advantage(self):
        rows = [{"language": lang, "correct": True, "complete_usage": lang != "hia", "requests": [],
                 "charged_tokens": 1 if lang == "hia" else 100, "public_failed_checks": 0,
                 "wall_ns": 1 if lang == "hia" else 100} for lang in ("hia", "rust") for _ in range(4)]
        self.assertFalse(study.summary(rows)["descriptive_hia_advantage_gate"])
        self.assertFalse(study.summary(rows[:1])["descriptive_hia_advantage_gate"])
        self.assertIsNone(study.summary(rows)["human_review_time_ns"])
        self.assertFalse(study.summary(rows)["general_productivity_proved"])

    @unittest.skipUnless(Path(study.protocol()["rustc"]).is_file() and Path(study.protocol()["clang"]).is_file(),
                         "requires registered native compilers for alpha-renamed interfaces")
    def test_parameter_alpha_renaming_preserves_both_actual_native_interfaces(self):
        import re
        def rename(value):
            if type(value) is str:
                return {"x":"first_input","y":"second_input"}.get(value,value)
            if type(value) is list:
                return [rename(v) for v in value]
            if type(value) is dict:
                return {k:rename(v) for k,v in value.items()}
            return value
        task=study.task_for("quota_clip")
        hia=rename(study.TASK_MODULE.reference(task["id"],"hia"))
        rust=re.sub(r"\bx\b","first_input",study.TASK_MODULE.reference(task["id"],"rust"))
        rust=re.sub(r"\by\b","second_input",rust)
        with tempfile.TemporaryDirectory() as temporary:
            for language,candidate in (("hia",hia),("rust",rust)):
                with self.subTest(language=language):
                    observed=study.evaluate(task,language,Path(temporary)/language,candidate=candidate)
                    self.assertTrue(observed["accepted"],observed.get("error"))


class CodexTransportBoundaryTests(unittest.TestCase):
    def test_real_owned_group_is_reaped_and_streams_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = run_owned([sys.executable, "-c", "print('probe')"], root, root / "transport", wall_seconds=3)
            self.assertEqual(result["status"], "exited")
            self.assertTrue(result["leader_reaped"])
            self.assertTrue(result["group_kill_before_reap"])
            self.assertEqual((root / "transport/stdout.raw").read_text(), "probe\n")

    def test_tool_events_reject_but_complete_reported_usage_can_be_retained(self):
        observer = CodexEvents([])
        observer.line(b'{"type":"thread.started","thread_id":"probe"}')
        observer.line(b'{"type":"turn.started"}')
        with self.assertRaisesRegex(EventFailure, "TOOL"):
            observer.line(b'{"type":"item.completed","item":{"id":"i","type":"command_execution","command":"pwd"}}')
        usage = {"input_tokens": 19, "cached_input_tokens": 4, "cache_write_input_tokens": 0,
                 "output_tokens": 2, "reasoning_output_tokens": 0}
        with tempfile.TemporaryDirectory() as temporary:
            raw = Path(temporary) / "raw"
            raw.write_bytes(canonical({"type": "turn.completed", "usage": usage})+b"\n")
            self.assertEqual(recover_reported_usage(raw), usage)
            raw.write_bytes(raw.read_bytes()*2)
            self.assertIsNone(recover_reported_usage(raw))

    def test_usage_boolean_and_unknown_fields_are_not_counts(self):
        good = {"input_tokens": 19, "cached_input_tokens": 4, "cache_write_input_tokens": 0,
                "output_tokens": 2, "reasoning_output_tokens": 0}
        for change in ({"input_tokens": True}, {"other": 0}, {"cached_input_tokens": 20}):
            observer = CodexEvents([])
            observer.line(b'{"type":"thread.started","thread_id":"probe"}')
            observer.line(b'{"type":"turn.started"}')
            with self.subTest(change=change), self.assertRaises(EventFailure):
                observer.line(canonical({"type": "turn.completed", "usage": {**good, **change}}))


if __name__ == "__main__":
    unittest.main()
