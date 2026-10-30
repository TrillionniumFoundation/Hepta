#!/usr/bin/env python3
"""Independent stdlib-only review of recorded V13 files, never execute their code."""
from pathlib import Path
from hashlib import sha256
from collections import Counter
import json
import os
import stat
import time

BASE = Path('/workspace/scratch/f0c12f106c89')
FRESH = BASE / 'p7-v13-integrated-953fa62'
HERE = Path(__file__).resolve().parent
OUT = BASE / 'p7-v13-evidence-staging-20261030/P7_PEER_REVIEW.json'
SOURCE = '953fa62dee5aa563551d57b1374ab95b6d548b45'
TREE = 'aa0683509a02ca97e4e0c1dd723e4047f50d81b3'
SUMMARY_SHA = 'b33852386bb4f12655ea6fb6f2c49297c6a1345021f35c4cf32aa2fb2a2f4d89'
MODEL_SHA = '00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4'
TYPES = ['Vec<u8>', 'bool', 'u16', 'u32', 'u64', 'u8', 'usize']
CACHE = {}
IDENTITIES = {}
TOTAL = 0


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    global TOTAL
    path = Path(path)
    if path in CACHE:
        return CACHE[path]
    need(path.is_relative_to(FRESH), 'review only reads the fresh evidence tree')
    need(all(not p.is_symlink() for p in (path, *path.parents)), 'symlink input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 16 * 1024 * 1024, 'bounded regular input')
        data = bytearray()
        while True:
            b = os.read(fd, min(65536, 16 * 1024 * 1024 + 1 - len(data)))
            if not b:
                break
            data.extend(b)
            need(len(data) <= 16 * 1024 * 1024, 'file byte bound')
        after = os.fstat(fd)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        need(fields(before) == fields(after) and len(data) == before.st_size, 'input changed during read')
    finally:
        os.close(fd)
    data = bytes(data)
    TOTAL += len(data)
    need(TOTAL <= 128 * 1024 * 1024, 'aggregate byte bound')
    CACHE[path] = data
    IDENTITIES[str(path.relative_to(FRESH))] = {'bytes': len(data), 'sha256': sha256(data).hexdigest()}
    return data


def pairs(items):
    value = {}
    for k, v in items:
        need(k not in value, 'duplicate JSON key')
        value[k] = v
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda v: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def load(relative):
    return decode(read(FRESH / relative))


def wire(value, ordered=False):
    return json.dumps(value, sort_keys=not ordered, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def object_schema(properties, required):
    return {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}


def check():
    start = time.monotonic_ns()
    summary = load('SUMMARY.json')
    need(sha256(read(FRESH / 'SUMMARY.json')).hexdigest() == SUMMARY_SHA, 'summary external pin differs')
    need(summary['source_commit'] == SOURCE and summary['source_tree'] == TREE, 'summary source differs')
    plan = load('PLAN.json')
    need(plan['source_head'] == SOURCE and plan['source_tree'] == TREE
         and plan['prior_qualification_inherited'] is False and plan['generation_budget_changed'] is False
         and plan['task_examples_answers_or_selected_nodes_added'] is False, 'plan scope differs')
    capacity = load('capacity/CAPACITY.json')
    calibration = load('calibration/RESULT.json')
    need(sha256(read(FRESH / 'capacity/CAPACITY.json')).hexdigest() == calibration['capacity_sha256'], 'capacity binding')
    source_inventory = None
    executions = {}
    for phase in ('capacity', 'calibration', 'main'):
        execution = load('operations/' + phase.upper() + '_EXECUTION.json')
        executions[phase] = execution
        before = load('operations/' + phase + '.source-before.json')
        after = load('operations/' + phase + '.source-after.json')
        need(before == after and before['head'] == SOURCE and before['tree'] == TREE
             and before['status'] == '' and len(before['files']) == 6907, 'raw source snapshot changed')
        need(source_inventory is None or source_inventory == before, 'source differs between stages')
        source_inventory = before
        need(execution['source_commit'] == execution['source_commit_after'] == SOURCE
             and execution['source_clean_before'] and execution['source_clean_after']
             and execution['raw_source_unchanged'] and execution['direct_runner_reaped']
             and execution['postflight_errors'] == [], 'outer source/finalization differs')
        for key, suffix in [('source_before', '.source-before.json'), ('source_after', '.source-after.json'),
                            ('stdout', '.stdout'), ('stderr', '.stderr'), ('resource_samples', '.resources.jsonl')]:
            raw = read(FRESH / 'operations' / (phase + suffix))
            need(len(raw) == execution[key]['bytes'] and sha256(raw).hexdigest() == execution[key]['sha256'], 'outer file identity differs')
        need(execution['outer_wall_ns'] == summary['costs']['outer_wall_ns'][phase], 'stage outer cost differs')
    wrapper = read(FRESH / 'operations/run_stage.py')
    need(sha256(wrapper).hexdigest() == plan['launcher_sha256']
         and all(x['wrapper']['sha256'] == plan['launcher_sha256'] for x in executions.values()), 'launcher binding')

    for report, phase in ((capacity, 'capacity'), (calibration, 'calibration')):
        need(report['source_commit'] == SOURCE and report['model']['sha256'] == MODEL_SHA
             and report['model']['bytes'] == 2740937888, 'model/source pin')
        need(all(report[x] is True for x in ('source_unchanged', 'tools_unchanged', 'model_unchanged')), 'report identity changed')
        for name, h in report['source_bindings'].items():
            raw = read(FRESH / phase / 'source_snapshot' / name)
            need(sha256(raw).hexdigest() == h == source_inventory['files'][name], 'source snapshot binding')
    need(capacity['tools'] == calibration['tools'] and capacity['source_bindings'] == calibration['source_bindings'], 'source/tools stage mismatch')
    need(capacity['protocol_sha256'] == calibration['protocol_sha256'] == plan['protocol_sha256'], 'protocol binding')
    protocol = read(FRESH / 'calibration/source_snapshot' / plan['protocol_path'])
    need(sha256(protocol).hexdigest() == plan['protocol_sha256'], 'actual retained protocol hash')
    pins = load('calibration/source_snapshot/experiments/hia_agent_toolstudy_v11_20261030/provenance/RUNTIME_MEMBERS.json')
    need(len(pins['members']) == 40 and pins['archive_sha256'] == 'cf07c1c112d709bd67e522017471de57ed0ec8bea031d732c5422351c07f65ac', 'runtime origin pin')
    tools = calibration['tools']
    companions = {Path(k.split(':', 1)[1]).name: v for k, v in tools.items() if k.startswith('runtime_companion:')}
    need(len(companions) == 38, 'runtime companion denominator')
    for pin in pins['members']:
        entry = tools['binary'] if pin['name'] == 'llama-server' else tools['tokenizer'] if pin['name'] == 'llama-tokenize' else companions[pin['name']]
        need(entry['sha256'] == pin['payload_sha256'] and entry['bytes'] == pin['payload_bytes'], 'runtime payload mismatch')
    for phase, folder in (('capacity', 'tokenizer-runtime'), ('calibration', 'engine-00')):
        before = load(phase + '/' + folder + '/identity.json')
        after = load(phase + '/' + folder + '/identity-after.json')
        need(before['model'] == after['model'] and after['model_unchanged'] and after['runtime_unchanged']
             and before['runtime_files'] == after['runtime_files'] and len(before['runtime_files']) == 39, 'engine lifetime identity')
        expected = [v for k, v in tools.items() if k == 'binary' or k.startswith('runtime_companion:')]
        need(Counter(map(digest, before['runtime_files'])) == Counter(map(digest, expected)), 'engine/runtime list differs')
        need(before['context'] == 8192 and before['threads'] == 4
             and before['official_plain_template']['chat_template_kwargs'] == {'enable_thinking': False}, 'template/context differs')
    need(capacity['engine_exited'] and capacity['engine_finalization']['complete']
         and capacity['engine_finalization']['close_returned'], 'capacity finalization')
    need(len(calibration['engines']) == 1 and all(calibration['engines'][0][x] is True for x in ('complete', 'close_returned', 'exited', 'service_calls_saved')), 'calibration finalization')

    need(capacity['complete'] and capacity['model_requests'] == 0 and executions['capacity']['returncode'] == 0, 'capacity success accounting')
    need(len(capacity['rows']) == 19 and all(row['passed'] and not row['reference_is_model_answer'] for row in capacity['rows']), '19 controls')
    cli = capacity['independent_cli_tokenizer']
    need(cli['calls'] == len(cli['retained_call_records']) == 95 and cli['all_matched'], '95 CLI denominator')
    for call in cli['retained_call_records']:
        relative = Path(call['receipt_path']).relative_to(FRESH)
        need(load(relative) == call and call['returncode'] == 0 and call['matched']
             and call['model_generation_requests'] == 0
             and decode(call['stdout']) == call['cli_token_ids'] == call['server_token_ids'], 'CLI actual token record')
    need(sum(row['rendered_request_cli_checks'] for row in capacity['rows']) == 76, 'rendered request count')

    need(calibration['status'] == 'all_cells_attempted' and calibration['valid_observation']
         and not calibration['calibration_eligible'] and calibration['complete_usage'], 'calibration status')
    cells = calibration['cells']
    need(len(cells) == 3 and sum(c['correct'] for c in cells) == 0, 'three failed fresh cells')
    need(all(calibration[k] == 0 for k in ('unknown_usage_requests', 'human_answer_repairs', 'terminal_hidden_calls')), 'unknown/repair/hidden calls')
    attempts = [(c, i, a) for c in cells for i, a in enumerate(c['attempts'])]
    need(len(attempts) == 9 == calibration['requests'] == calibration['responses'] and all(len(c['attempts']) == 3 for c in cells), 'attempt denominator')
    actual_usage_files = sorted((FRESH / 'calibration/engine-00').glob('transport-*.usage.json'))
    need(len(actual_usage_files) == 9, 'actual generation transport denominator')
    usage_totals = Counter()
    statuses = Counter()
    checks = []
    for number, (cell, index, attempt) in enumerate(attempts, 1):
        folder = Path('calibration') / cell['id']
        need(load(folder / 'CELL.json') == cell, 'CELL and RESULT differ')
        query = load(folder / 'CAPTURED_QUERY.json')
        evaluation = load(folder / ('attempt-' + str(index) + '.evaluation.json'))
        response = load(folder / ('attempt-' + str(index) + '.response.json'))
        request = load(folder / ('attempt-' + str(index) + '.request.json'))
        wrapped = load(folder / ('candidate-' + str(index)) / 'RESPONSE.json')
        need(evaluation == attempt and attempt['actual_generation_requested'], 'persisted attempt differs')
        stem = Path('calibration/engine-00') / ('transport-' + f'{number:03d}')
        raw_request = load(str(stem) + '.request.json')
        body_bytes = read(FRESH / (str(stem) + '.request.body.json'))
        body = decode(body_bytes)
        transport = load(str(stem) + '.response.json')
        usage = load(str(stem) + '.usage.json')
        sse = read(FRESH / (str(stem) + '.response.sse'))
        events = [decode(line[5:].strip()) for line in sse.decode().splitlines() if line.startswith('data:')]
        need(events[-1]['stop'] is True and sum(e.get('stop') is True for e in events) == 1, 'terminal SSE event')
        tokens = [token for event in events for token in event.get('tokens', [])]
        need(body == raw_request['payload'] and body_bytes == wire(body, ordered=True), 'exact retained wire body')
        need(body['n_predict'] == 1536 and body['temperature'] == 0 and body['seed'] == 0
             and body['cache_prompt'] is False and body['stream'] is True, 'actual generation settings')
        need(usage['complete'] and usage['unknown_output_tokens'] is False
             and usage['events'] == len(events) and usage['response_bytes'] == len(sse)
             and usage['observed_output_token_ids'] == tokens
             and usage['input_tokens'] == len(body['prompt']) == events[-1]['tokens_evaluated']
             and usage['output_tokens'] == len(tokens) == events[-1]['tokens_predicted']
             and usage['total_tokens'] == usage['input_tokens'] + usage['output_tokens'], 'actual SSE usage')
        need(response['text'] == transport['content'] == ''.join(e.get('content', '') for e in events)
             and response['input_token_ids'] == body['prompt'] and response['output_token_ids'] == tokens, 'actual answer/tokens')
        need(request['messages'] == raw_request['messages'] and request['captured_query_sha256'] == query['query_sha256'], 'actual query/messages')
        for q in (query, query['edit_query']):
            need(q['query_sha256'] == digest({k: v for k, v in q.items() if k != 'query_sha256'}), 'public query digest')
        nodes = query['edit_query']['nodes']
        editable = {n['id']: n for n in nodes if n['fields']}
        need(all(n['fields'] in ([], ['text']) for n in nodes)
             and all(n['id'] + (' edit ' if n['fields'] else ' read-only ') in raw_request['messages'][0]['content'] for n in nodes), 'complete public source catalogue')
        categories = {}
        for n in editable.values():
            need(n['category'] in ('expression', 'type'), 'public category')
            categories.setdefault(n['category'], []).append(n['id'])
        variants = [object_schema({'node': {'enum': sorted(ids)}, 'changes': object_schema({'text': {'enum': TYPES} if category == 'type' else {'type': 'string'}}, ['text'])}, ['node', 'changes'])
                    for category, ids in sorted(categories.items())]
        schema = object_schema({'edits': {'type': 'array', 'minItems': 1, 'maxItems': 16,
                                         'items': variants[0] if len(variants) == 1 else {'oneOf': variants}}}, ['edits'])
        need(body['json_schema'] == schema and response['decoder_sha256'] == digest(schema), 'independent public schema')
        actual_items = body['json_schema']['properties']['edits']['items']
        actual_variants = actual_items.get('oneOf', [actual_items])
        need(all(list(v['properties']) == ['node', 'changes'] for v in actual_variants), 'actual wire is not selection first')
        rules = [line for line in transport['generation_settings']['grammar'].splitlines()
                 if '::=' in line and '-node-kv' in line.split('::=', 1)[1] and '-changes-kv' in line.split('::=', 1)[1]]
        need(len(rules) == len(variants) and all(line.split('::=', 1)[1].index('-node-kv') < line.split('::=', 1)[1].index('-changes-kv') for line in rules), 'native GBNF selection order')
        wire_check = attempt['decoder_wire_check']
        binding = wire_check['schema_binding']
        need(wire_check == response['decoder_wire_check'] and wire_check['rules'] == rules
             and wire_check['actual_request_body_sha256'] == sha256(body_bytes).hexdigest()
             and wire_check['selection_before_replacement'] and wire_check['model_answer_rewritten'] is False
             and wire_check['does_not_prove_candidate_semantics'], 'wire check record')
        need(binding['schema_sha256'] == digest(schema)
             and binding['ordered_schema_sha256'] == sha256(wire(body['json_schema'], ordered=True)).hexdigest()
             and binding['query_sha256'] == query['query_sha256'] and binding['source_revision'] == query['source_revision']
             and binding['all_public_editable_nodes_included'] and not binding['task_or_reference_replacement_values_embedded'], 'public schema/query binding')
        answer = decode(response['text'])
        need(set(answer) == {'edits'} and type(answer['edits']) is list and 1 <= len(answer['edits']) <= 16, 'response envelope')
        selected = []
        for edit in answer['edits']:
            need(set(edit) == {'node', 'changes'} and edit['node'] in editable
                 and type(edit['changes']) is dict and set(edit['changes']) == {'text'}
                 and type(edit['changes']['text']) is str, 'public edit schema')
            n = editable[edit['node']]
            need(n['category'] != 'type' or edit['changes']['text'] in TYPES, 'public type grammar')
            selected.append(n)
        need(wrapped['edits'] == answer['edits'] and wrapped['source_revision'] == query['source_revision']
             and wrapped['query_sha256'] == query['query_sha256'], 'host changed answer or binding')
        overlap = [[a['id'], b['id']] for i, a in enumerate(selected) for b in selected[i + 1:]
                   if a['file'] == b['file'] and max(a['start'], b['start']) < min(a['end'], b['end'])]
        result = attempt['evaluation']
        need(result['status'] == attempt['status'] and result['before_revision'] == result['after_revision'] == query['source_revision']
             and result['accepted'] is False and result['source_published'] is False
             and result['failed_transaction_left_source_unchanged'] and result['hidden_evaluated'] is False, 'failure transaction status')
        if attempt['status'] == 'response_rejected':
            need(overlap and result['error']['message'] == 'E_STRUCTURED_EDIT: overlapping ancestor/descendant Rust nodes', 'actual overlap refusal')
        elif attempt['status'] == 'compile_rejected':
            need(not overlap and result['build']['compile']['returncode'] == 1
                 and 'mismatched types' in result['build']['compile']['stderr'], 'actual compiler rejection')
        elif attempt['status'] == 'observable_wrong':
            public = result['public']
            need(not overlap and result['build']['compile']['returncode'] == 0 and public['execution']['returncode'] == 0
                 and public['expected'] == [[0, 0], [26, 21]], 'actual wrong-result execution')
            parsed = [[int(v) for v in line.split()] for line in public['execution']['stdout'].splitlines()]
            need(parsed == public['observations'] and parsed[1][:2] == [17, 12], 'observed output mismatch witness')
        else:
            raise ValueError('unexpected final observed status')
        template = load('calibration/engine-00/template-' + f'{number:03d}' + '.json')
        need(template['matched'] and not template['messages_or_answers_rewritten_by_host']
             and not template['model_generation_requested_by_this_check']
             and template['expected_prompt'] == raw_request['rendered_prompt'], 'plain template binding')
        for key in ('input_tokens', 'output_tokens', 'total_tokens'):
            need(response['usage'][key] == attempt['usage'][key] == usage[key], 'attempt usage binding')
            usage_totals[key] += usage[key]
        statuses[attempt['status']] += 1
        checks.append({'cell': cell['id'], 'attempt': index, 'transport': number, 'status': attempt['status'],
                       'usage': {k: usage[k] for k in ('input_tokens', 'output_tokens', 'total_tokens')},
                       'public_schema_matches': True, 'http_and_gbnf_selection_first': True,
                       'answer_exactly_preserved': True, 'overlap_pairs': overlap})

    need(dict(usage_totals) == summary['calibration']['usage'] == {'input_tokens': 21577, 'output_tokens': 1659, 'total_tokens': 23236}, 'actual aggregate token count')
    need(calibration['known_input_tokens'] == usage_totals['input_tokens']
         and calibration['known_output_tokens'] == usage_totals['output_tokens']
         and calibration['total_tokens'] == usage_totals['total_tokens'], 'RESULT aggregate accounting')
    need(dict(statuses) == summary['calibration']['actual_attempt_statuses'] == {'response_rejected': 7, 'compile_rejected': 1, 'observable_wrong': 1}, 'failure categories')
    main_stderr = read(FRESH / 'operations/main.stderr').decode()
    need(executions['main']['returncode'] == 1 and executions['calibration']['returncode'] == 0
         and 'validate_qualification' in main_stderr and 'E_TOOLSTUDY_NO_QUALIFIED_MODEL' in main_stderr
         and not (FRESH / 'main').exists(), 'main pre-engine qualification refusal')
    need(summary['main']['attempted_cells'] == summary['main']['generation_requests'] == 0
         and summary['main']['engine_constructed'] is False and summary['main']['output_directory_created'] is False, 'main scope')
    need(summary['historical_results_reused_as_fresh'] is False and summary['new_independent_task_holdout'] is False
         and summary['adaptive_same_task_interface_followup'] is True, 'same-task adaptive scope')
    need(summary['costs']['inner_costs_included_in_outer_do_not_add'] is True
         and summary['costs']['full_human_and_agent_development_review_cost'] is None
         and summary['costs']['new_model_acquisition_performed'] is False
         and summary['costs']['inner_experiment_wall_ns'] == {'capacity': capacity['experiment_wall_ns'], 'calibration': calibration['experiment_wall_ns']}, 'cost scope')
    report = {'schema': 'hepta.p7.independent-readback.v1', 'reviewer': 'compiler_research', 'passed': True,
        'source_commit': SOURCE, 'source_tree': TREE, 'summary_sha256': SUMMARY_SHA,
        'answers_modified': False, 'new_model_generations': 0, 'native_or_repository_code_executed_by_peer': False,
        'capacity': {'controls': 19, 'passed': 19, 'cli_tokenizer_calls': 95, 'rendered_request_checks': 76, 'model_generation_requests': 0},
        'calibration': {'tasks': 3, 'correct': 0, 'requests': 9, 'responses': 9, 'usage': dict(usage_totals),
                        'attempt_statuses': dict(statuses), 'complete_usage': True, 'unknown_usage_requests': 0,
                        'human_answer_repairs': 0, 'terminal_hidden_calls': 0, 'eligible': False,
                        'same_tasks_adaptive_followup_not_new_independent_holdout': True},
        'actual_attempt_checks': checks, 'main': summary['main'], 'costs': summary['costs'],
        'raw_source_snapshots': {'files_each': 6907, 'snapshots_compared': 6, 'unchanged': True},
        'runtime_payload_pins': 40, 'runtime_lifetime_files': 39,
        'source_bindings_each_phase': len(calibration['source_bindings']),
        'bounded_files_read_once': len(CACHE), 'bounded_bytes_read_once': TOTAL,
        'read_inventory': IDENTITIES,
        'scope': 'Independent stdlib-only read of recorded bytes and actual SSE, token, public schema, ordered wire, GBNF, edit-span and failure witnesses. Does not rerun inference/native/compiler, prove model reasoning or authenticate a hostile producer. Runtime/model identities are retained lifetime records; no model download or current weight rehash.',
        'review_wall_ns': time.monotonic_ns() - start,
        'full_human_agent_review_cost': None}
    return report


if __name__ == '__main__':
    need(not OUT.exists(), 'peer result must not be overwritten')
    report = check()
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'passed': True, 'output': str(OUT), 'sha256': sha256(OUT.read_bytes()).hexdigest(),
                      'files': report['bounded_files_read_once'], 'bytes': report['bounded_bytes_read_once'],
                      'wall_ns': report['review_wall_ns'], 'calibration': report['calibration']}, sort_keys=True))
