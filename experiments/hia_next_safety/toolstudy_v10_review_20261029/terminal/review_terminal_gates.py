"""Read-only terminal gate/template review; no SSE or token-cost recount."""
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timezone
import ast
import json
import subprocess
import sys

SOURCE = Path('/tmp/hepta-next-agent-toolstudy-v10-20261029')
RUN = Path('/tmp/hepta-next-agent-v10-qwen4b-01')
CAP = Path('/tmp/hepta-next-agent-v10-capacity-01')
FROZEN = '11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0'
RESULT_SHA = '9d528ebfdfa5e6f0e748f625a6364cbbe8786ffd54f55ab8bb3f335d50905b94'
CAP_SHA = '28a6461f287b473b3c7e0683fb638c1504d913440940741a229e57b35fab79d6'
REFUSAL = Path('/tmp/hepta-next-agent-v10-main-refusal.json')
REFUSAL_SHA = 'eab246d0a582e920af789ac67608374d8255af2392de33c8cdf3959322579fe8'
TEMPLATE_SHA = 'a62ff0a2472a0fa1b8eaabcb57c59b58afa42a22831dc141400b6e0cf2b65ce3'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return sha256(data).hexdigest()


def main():
    output = Path(sys.argv[1]); output.mkdir(parents=True, exist_ok=False)
    reads = {}
    report = {'schema': 'hepta.agent.v10.terminal-gate-independent-review.v1',
              'reviewed_at': datetime.now(timezone.utc).isoformat(),
              'reviewer_script_sha256': digest(Path(__file__).read_bytes()),
              'decision': 'HOLD pending terminal review', 'review_complete': False,
              'model_requests': 0, 'native_executions': 0, 'tokenizer_invocations': 0,
              'tests_rerun': 0, 'model_weights_rehashed': False,
              'SSE_and_token_cost_recount': False, 'production_module_imports': 0}

    def read(path):
        data = Path(path).read_bytes()
        reads[str(path)] = {'bytes': len(data), 'sha256': digest(data)}
        return json.loads(data)

    def exact_source(name, bound):
        current = (SOURCE / name).read_bytes()
        frozen = subprocess.check_output(['git', 'show', FROZEN + ':' + name], cwd=SOURCE)
        assert current == frozen
        assert digest(current) == bound[name]
        return current.decode()

    try:
        result = read(RUN / 'RESULT.json')
        capacity = read(CAP / 'CAPACITY.json')
        plan = read(RUN / 'PLAN.json')
        refusal = read(REFUSAL)
        assert reads[str(RUN / 'RESULT.json')]['sha256'] == RESULT_SHA
        assert reads[str(CAP / 'CAPACITY.json')]['sha256'] == CAP_SHA
        assert reads[str(REFUSAL)]['sha256'] == REFUSAL_SHA
        assert result['plan_sha256'] == reads[str(RUN / 'PLAN.json')]['sha256']
        assert result['source_commit'] == plan['source_commit'] == refusal['source_commit'] == FROZEN
        assert result['capacity_sha256'] == CAP_SHA
        assert result['schema'] == 'hepta.agent.real-node-toolstudy.v10'
        assert result['stage'] == 'calibration' and result['status'] == 'all_cells_attempted'
        for key in ('source_bindings', 'prompt_bindings', 'protocol_sha256', 'model', 'tools'):
            assert result[key] == capacity[key], key
        for key in ('source_bindings', 'prompt_bindings', 'model', 'tools'):
            assert result[key] == plan[key], key
        assert refusal['source_bindings'] == result['source_bindings']
        assert all(result[key] is True for key in ('valid_observation', 'source_unchanged', 'model_unchanged', 'tools_unchanged'))
        assert result['requests'] == result['responses'] == 9
        assert result['human_answer_repairs'] == result['terminal_hidden_calls'] == 0
        source_files = [
            'experiments/hia_agent_toolstudy_v10_20261029/support.py',
            'experiments/hia_agent_toolstudy_v10_20261029/engine.py',
            'experiments/hia_agent_toolstudy_v10_20261029/prompts.py',
            'experiments/hia_agent_toolstudy_v10_20261029/PROTOCOL.json',
            'experiments/hia_agent_toolstudy_v8_20261029/engine.py',
            'experiments/hia_agent_toolstudy_v8_20261029/prompts.py',
            'tools/qualify_hia_agent_toolstudy_v10.py',
        ]
        sources = {name: exact_source(name, result['source_bindings']) for name in source_files}
        cfg = json.loads(sources['experiments/hia_agent_toolstudy_v10_20261029/PROTOCOL.json'])
        expected_tasks = cfg['qualification']['tasks']
        assert [(cell['task'], cell['arm']) for cell in result['cells']] == [(name, 'rust_node') for name in expected_tasks]
        derived = all(cell.get('correct') is True and cell.get('hidden_evaluated') is True and cell.get('status') == 'correct'
                      and 1 <= len(cell.get('attempts', [])) <= 3
                      and all(attempt.get('usage') is not None for attempt in cell['attempts'])
                      for cell in result['cells'])
        assert derived is False and result['calibration_eligible'] is derived
        assert sum(cell['correct'] is True for cell in result['cells']) == 0
        assert all(len(cell['attempts']) == 3 and cell['hidden_evaluated'] is False for cell in result['cells'])
        runner = ast.parse(sources['tools/qualify_hia_agent_toolstudy_v10.py'])
        run = next(node for node in runner.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        def calls_named(name):
            return [node for node in ast.walk(run) if isinstance(node, ast.Call) and
                    ((isinstance(node.func, ast.Attribute) and node.func.attr == name) or
                     (isinstance(node.func, ast.Name) and node.func.id == name))]
        gate_line = calls_named('validate_qualification')[0].lineno
        mkdir_line = min(node.lineno for node in calls_named('mkdir'))
        engine_line = calls_named('ToolStudyEngine')[0].lineno
        assert gate_line < mkdir_line < engine_line
        assert refusal['returncode'] == 1
        assert 'E_TOOLSTUDY_NO_QUALIFIED_MODEL' in refusal['stderr']
        assert refusal['gate_rejected_before_engine_construction'] is True
        assert refusal['main_cells_started'] == refusal['model_requests'] == 0
        assert refusal['main_output_directory_created'] is False and refusal['source_unchanged'] is True
        assert refusal['qualification']['sha256'] == RESULT_SHA and refusal['capacity']['sha256'] == CAP_SHA
        args = refusal['argv']
        refused_output = Path(args[args.index('--output') + 1])
        assert not refused_output.exists()
        assert len(result['engines']) == 1
        engine_row = result['engines'][0]
        engine = Path(engine_row['folder'])
        assert engine_row['exited'] is True and engine_row['requests'] == engine_row['responses'] == engine_row['preparations'] == 9
        before = read(engine / 'identity.json'); after = read(engine / 'identity-after.json')
        assert after == engine_row['identity']
        assert after['model_unchanged'] is True and after['runtime_unchanged'] is True
        assert before['model'] == after['model'] == result['model']['file']
        assert before['runtime_files'] == after['runtime_files']
        assert before['threads'] == 4 and before['context'] == 8192
        pid = before['pid']
        pid_path = Path('/proc') / str(pid)
        owned_alive = pid_path.exists() and result['model']['file']['path'].encode() in (pid_path / 'cmdline').read_bytes().split(b'\0')
        assert not owned_alive
        official_path = SOURCE / 'experiments/hia_agent_toolstudy_v10_20261029/provenance/Qwen__Qwen3-4B-Instruct-2507__tokenizer_config.json'
        official = read(official_path)
        assert reads[str(official_path)]['sha256'] == TEMPLATE_SHA
        assert before['official_plain_template']['config_sha256'] == TEMPLATE_SHA
        assert before['official_plain_template']['chat_template_sha256'] == digest(official['chat_template'].encode())
        old_prompts_ast = ast.parse(sources['experiments/hia_agent_toolstudy_v8_20261029/prompts.py'])
        repair_text = next(ast.literal_eval(node.value) for node in old_prompts_ast.body if isinstance(node, ast.Assign) and
                           any(isinstance(target, ast.Name) and target.id == 'REPAIR' for target in node.targets))
        checked = []
        index = 0
        for cell in result['cells']:
            folder = RUN / cell['id']
            expected_initial = read(CAP / 'calibration' / cell['task'] / 'calibration/INITIAL.json')['messages'][0]
            for attempt in cell['attempts']:
                index += 1
                ai = attempt['index']
                cell_request = read(folder / ('attempt-' + str(ai) + '.request.json'))
                template = read(engine / ('template-' + str(index).zfill(3) + '.json'))
                prepared = read(engine / ('preparation-' + str(index).zfill(3) + '.json'))
                transport = read(engine / ('transport-' + str(index).zfill(3) + '.request.json'))
                messages = cell_request['messages']
                assert messages == template['request']['messages'] == prepared['messages'] == transport['messages']
                assert messages[0] == expected_initial
                if ai == 0:
                    assert len(messages) == 1
                else:
                    previous = read(folder / ('attempt-' + str(ai-1) + '.response.json'))['text']
                    budget = read(folder / ('attempt-' + str(ai-1) + '.repair-budget.json'))
                    assert budget['previous_code_truncated'] is False and budget['public_cases_removed'] is False
                    assert messages == [expected_initial, {'role':'assistant', 'content':previous},
                                        {'role':'user', 'content':repair_text + canonical(budget['feedback']).decode()}]
                assert all(set(item) == {'role','content'} and item['role'] in ('user','assistant') and type(item['content']) is str for item in messages)
                rendered = ''.join('<|im_start|>' + item['role'] + '\n' + item['content'] + '<|im_end|>\n' for item in messages) + '<|im_start|>assistant\n'
                assert template['matched'] is True and template['template_error'] is None
                assert template['messages_or_answers_rewritten'] is False and template['model_generation_requested_by_this_check'] is False
                assert template['expected_prompt'] == template['observed_response']['prompt'] == prepared['rendered_prompt'] == transport['rendered_prompt'] == rendered
                assert template['official_template'] == {'config_sha256': TEMPLATE_SHA, 'config_bytes': 9377}
                assert prepared['fits'] is True and prepared['actual_generation_submitted'] is True
                assert prepared['context'] == 8192 and prepared['reserved_output_tokens'] == 1536
                assert len(prepared['input_token_ids']) + 1536 <= 8192
                assert transport['payload']['prompt'] == prepared['input_token_ids']
                assert transport['payload']['n_predict'] == 1536 and transport['payload']['cache_prompt'] is False
                assert attempt['actual_generation_requested'] is True
                checked.append({'generation_index':index, 'task':cell['task'], 'cell_attempt_index':ai,
                                'message_count':len(messages), 'complete_render_sha256':digest(rendered.encode()),
                                'input_tokens_plus_reserved_output':len(prepared['input_token_ids'])+1536,
                                'exact_official_plain_render':True, 'history_preserved':True})
        assert index == 9
        assert len(list(engine.glob('template-*.json'))) == len(list(engine.glob('preparation-*.json'))) == len(list(engine.glob('transport-*.request.json'))) == 9
        report.update(review_complete=True,
            decision='DENY main for this completed negative qualification; retain the single-candidate stop rule. No model qualification or efficiency advantage established.',
            source_commit=FROZEN, source_bindings_matched_to_reviewed_capacity=len(result['source_bindings']),
            critical_implementation_files_checked_against_frozen_git=source_files,
            qualification_sha256=RESULT_SHA, capacity_sha256=CAP_SHA, main_refusal_sha256=REFUSAL_SHA,
            derived_correct_tasks=0, registered_qualification_tasks=3, actual_generation_templates=checked,
            derived_calibration_eligible=False, recorded_own_engine_exited=True, owned_pid_present_at_review=pid_path.exists(),
            owned_model_process_alive_at_review=False, model_tools_source_records_equal_to_reviewed_capacity=True,
            refusal_output_directory_exists=False, main_output_path=str(refused_output),
            main_generation_requests=0, main_cells_started=0,
            source_order={'qualification_call_line':gate_line,'earliest_output_mkdir_line':mkdir_line,'engine_constructor_line':engine_line},
            observed_model_or_history_template_mismatches=0,
            scope='Independent gate and exact-message/template source-and-record review; SSE/tokens/wall costs are separately audited. No model, tokenizer, compiler, native or test execution; no new model-weight hash or host attestation.')
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)}
        raise
    finally:
        report['read_json_files']=reads
        (output/'REVIEW.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({key:report[key] for key in ('review_complete','decision','model_requests','native_executions','tokenizer_invocations')}))


if __name__ == '__main__':
    main()
