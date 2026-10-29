"""Model/template-only adaptation; no model, tokenizer, compiler or native run."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_agent_toolstudy_v9_20261029 import prompts as prior_prompts, support as prior_support
from experiments.hia_agent_toolstudy_v10_20261029 import prompts, support
from experiments.hia_agent_toolstudy_v10_20261029.engine import ToolStudyEngine, OriginalEngine
from tools import qualify_hia_agent_toolstudy_v9 as prior_runner
from tools import qualify_hia_agent_toolstudy_v10 as runner
from tools import qualify_hia_agent_tool_capacity_v9 as prior_capacity
from tools import qualify_hia_agent_tool_capacity_v10 as capacity


class ToolStudyV10Tests(unittest.TestCase):
    def test_all19_actual_initial_messages_and_queries_are_v9_identical(self):
        self.assertIs(prompts.prompt, prior_prompts.prompt)
        self.assertIs(prompts.messages, prior_prompts.messages)
        self.assertIs(prompts.render_nodes, prior_prompts.render_nodes)
        self.assertEqual(prompts.REPAIR, prior_prompts.REPAIR)
        count = 0
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                query = support.session_for(task, arm).query()
                self.assertEqual(query, prior_support.session_for(task, arm).query())
                text = prompts.prompt(task, arm, query)
                self.assertEqual(text, prior_prompts.prompt(task, arm, query))
                self.assertEqual(prompts.messages(text), prior_prompts.messages(text))
                self.assertEqual(prompts.messages(text, '{"edits":[]}', {"diagnostic": "public"}),
                                 prior_prompts.messages(text, '{"edits":[]}', {"diagnostic": "public"}))
                count += 1
        self.assertEqual(count, 19)

    def test_same_budgets_tasks_and_gates_only_model_template_are_new(self):
        new, old = support.protocol(), prior_support.protocol()
        for key in ("runtime", "arms", "tasks", "generation", "history", "budget", "rust_conversion_profile",
                    "hidden_seed", "hidden_random_cases_per_task", "decoder", "advantage_gate", "cell_order"):
            self.assertEqual(new[key], old[key], key)
        self.assertEqual(new["qualification"]["tasks"], old["qualification"]["tasks"])
        self.assertTrue(new["qualification"]["main_forbidden_without_qualification"])
        self.assertEqual(new["model"], support.PINNED_MODEL)
        self.assertEqual(new["official_template"], support.PINNED_TEMPLATE)
        self.assertNotEqual(new["model"], old["model"])
        self.assertFalse(new["model_provenance"]["quantization_reconstruction_verified"])
        self.assertIn("single new V10 candidate", new["prospective_amendment"]["stop_rule"])

    def test_protocol_rejects_changed_budget_or_unregistered_model(self):
        original = Path.read_text
        for field in ("attempts_per_cell", "sha256"):
            def changed(path, *args, **kwargs):
                text = original(path, *args, **kwargs)
                if path == support.HERE / "PROTOCOL.json":
                    data = json.loads(text)
                    if field == "attempts_per_cell": data["generation"][field] = 4
                    else: data["model"][field] = "0" * 64
                    return json.dumps(data)
                return text
            with self.subTest(field=field), patch.object(Path, "read_text", changed):
                with self.assertRaisesRegex(ValueError, "V10_"):
                    support.protocol()

    def test_official_config_and_every_retained_provenance_file_are_bound(self):
        cfg = support.protocol()
        for name, expected in cfg["model_provenance"]["files"].items():
            self.assertEqual(hashlib.sha256((support.HERE / name).read_bytes()).hexdigest(), expected)
        data = json.loads(prompts.TOKENIZER_CONFIG.read_text())
        self.assertIsNone(data["bos_token"])
        self.assertFalse(data["add_bos_token"])
        self.assertEqual(data["eos_token"], "<|im_end|>")
        self.assertNotIn("You are Qwen", data["chat_template"])
        original = Path.read_bytes
        def changed(path):
            data = original(path)
            return data + b" " if path == prompts.TOKENIZER_CONFIG else data
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "OFFICIAL_TEMPLATE_BYTES"):
                prompts.official_template_binding()

    def test_plain_template_preserves_entire_repair_history_without_system_injection(self):
        values = [prompts.messages("task"), prompts.messages("task", '{"text":"a\\nb"}', {"diagnostic": "type\nerror"})]
        prefix = "<|im_start|>system\nYou are Qwen, created by Alibaba Cloud. You are a helpful assistant.<|im_end|>\n"
        for messages in values:
            old = prior_prompts.plain_qwen_template(messages)
            new = prompts.plain_qwen_template(messages)
            self.assertTrue(old.startswith(prefix)); self.assertEqual(new, old[len(prefix):])
            for item in messages: self.assertIn(item["content"], new)
        for bad in ([], [{"role": "system", "content": "new hint"}], [{"role":"user","content":"x","tools":[]} ]):
            with self.assertRaises(ValueError): prompts.plain_qwen_template(bad)

    def test_generation_decoder_tokenization_and_acceptance_are_original_objects(self):
        self.assertIs(ToolStudyEngine.generate, OriginalEngine.generate)
        self.assertIs(ToolStudyEngine.tokenize, OriginalEngine.tokenize)
        self.assertIs(runner.validation, prior_runner.validation)
        self.assertIs(runner.budget, prior_runner.budget)
        self.assertIs(capacity.references, prior_capacity.references)
        self.assertIs(capacity.validation, prior_capacity.validation)
        self.assertIs(capacity.ToolStudyEngine, runner.ToolStudyEngine)

    def test_actual_template_guard_retains_initial_and_complete_repair_receipts(self):
        with tempfile.TemporaryDirectory() as folder:
            engine = object.__new__(ToolStudyEngine);engine.output=Path(folder);engine.template_checks=0
            for items in (prompts.messages("task"),prompts.messages("task",'{"edits":[]}',{"diagnostic":"public"})):
                observed={"prompt":prompts.plain_qwen_template(items)}
                with patch.object(OriginalEngine,"request",return_value=observed) as request:
                    self.assertIs(engine.request("/apply-template",{"messages":items}), observed)
                    request.assert_called_once_with("/apply-template",{"messages":items},10)
            files=sorted(Path(folder).glob('template-*.json'));self.assertEqual(len(files),2)
            for path in files:
                record=json.loads(path.read_text());self.assertTrue(record['matched'])
                self.assertFalse(record['messages_or_answers_rewritten'])

    def test_template_mismatch_is_retained_and_refused_without_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            engine=object.__new__(ToolStudyEngine);engine.output=Path(folder);engine.template_checks=0
            items=prompts.messages('task');changed={'prompt':prior_prompts.plain_qwen_template(items)}
            with patch.object(OriginalEngine,'request',return_value=changed) as request:
                with self.assertRaisesRegex(ValueError,'OFFICIAL_TEMPLATE_MISMATCH'):
                    engine.request('/apply-template',{'messages':items})
                self.assertEqual(request.call_count,1)
            record=json.loads((Path(folder)/'template-001.json').read_text())
            self.assertFalse(record['matched']);self.assertEqual(record['observed_response'],changed)
            self.assertFalse(record['model_generation_requested_by_this_check'])

    def test_added_startup_metadata_failure_closes_owned_engine(self):
        def fake_init(obj,**kwargs): obj.identity={}
        with patch.object(OriginalEngine,'__init__',fake_init),patch.object(OriginalEngine,'close') as close, \
             patch.object(prompts,'official_template_binding',side_effect=RuntimeError('injected metadata failure')):
            with self.assertRaisesRegex(RuntimeError,'injected metadata failure'): ToolStudyEngine()
            close.assert_called_once()

    def test_cli_control_preserves_literal_input_and_declared_bos_policy(self):
        text='<|im_start|>user\n{"x":"a\\nb"}<|im_end|>\n'
        with tempfile.TemporaryDirectory() as folder:
            for special in (False,True):
                result=subprocess.CompletedProcess([],0,b'[42, 7]\n',b'')
                with patch.object(capacity.subprocess,'run',return_value=result) as run:
                    record=capacity.verify_cli_tokens('tokenizer','model',text,[42,7],special=special,
                         receipt=Path(folder)/(str(special)+'.json'))
                    args=run.call_args
                    self.assertEqual(args.kwargs['input'],text.encode())
                    self.assertIn('--no-escape',args.args[0]);self.assertNotIn('--no-parse-special',args.args[0])
                    self.assertEqual('--no-bos' in args.args[0],not special)
                    self.assertTrue(record['matched']);self.assertEqual(record['model_generation_requests'],0)

    def test_cli_mismatch_and_timeout_keep_costs_and_refuse_no_id_repair(self):
        with tempfile.TemporaryDirectory() as folder:
            events=[subprocess.CompletedProcess([],0,b'[1,42,7]',b''),subprocess.TimeoutExpired('tokenizer',30,output=b'partial')]
            for i,event in enumerate(events):
                kwargs={'side_effect':event} if isinstance(event,Exception) else {'return_value':event}
                path=Path(folder)/(str(i)+'.json')
                with patch.object(capacity.subprocess,'run',**kwargs):
                    with self.assertRaisesRegex(RuntimeError,'CLI_TOKENIZER_MISMATCH'):
                        capacity.verify_cli_tokens('tokenizer','model','text',[42,7],special=True,receipt=path)
                record=json.loads(path.read_text());self.assertFalse(record['matched'])
                self.assertGreaterEqual(record['wall_ns'],0);self.assertEqual(record['server_token_ids'],[42,7])
            self.assertEqual(json.loads((Path(folder)/'0.json').read_text())['cli_token_ids'],[1,42,7])

    def test_v9_capacity_or_qualification_cannot_be_inherited(self):
        with self.assertRaisesRegex(ValueError,'CAPACITY_BINDING'):
            support.validate_capacity({'schema':'hepta.agent.tool-capacity.v9','complete':True},tools={},model={})
        with self.assertRaisesRegex(ValueError,'QUALIFICATION_BINDING'):
            support.validate_qualification({'schema':'hepta.agent.real-node-toolstudy.v9','calibration_eligible':True},
                tools={},model={},capacity_sha256='unused')

    def test_model_runner_control_flow_only_changes_two_import_bindings(self):
        new=(support.ROOT/'tools/qualify_hia_agent_toolstudy_v10.py').read_text()
        expected=(support.ROOT/'tools/qualify_hia_agent_toolstudy_v9.py').read_text().replace(
            'from experiments.hia_agent_toolstudy_v9_20261029 import prompts, support',
            'from experiments.hia_agent_toolstudy_v10_20261029 import prompts, support').replace(
            'from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine',
            'from experiments.hia_agent_toolstudy_v10_20261029.engine import ToolStudyEngine')
        self.assertEqual(new,expected)
        self.assertEqual(support.protocol()['tokenizer_controls']['independent_cli_calls'],95)


if __name__=='__main__': unittest.main()
