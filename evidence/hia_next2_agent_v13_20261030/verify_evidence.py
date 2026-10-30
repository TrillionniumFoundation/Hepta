#!/usr/bin/env python3
"""Bounded offline integrity/consistency review; never extract or execute archive data."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import lzma
import os
import stat
import time
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_MANIFEST = 8 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_COMPRESSED = 64 * 1024 * 1024
XZ_MEMORY = 64 * 1024 * 1024
MAX_CAPTURE = 128 * 1024 * 1024
PREFIX = 'p7-v13-20261030/'
SOURCE = '953fa62dee5aa563551d57b1374ab95b6d548b45'
TREE = 'aa0683509a02ca97e4e0c1dd723e4047f50d81b3'
MODEL_SHA = '00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4'
MODEL_BYTES = 2740937888
HASH = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, 'bounded regular input required')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) <= limit and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed during bounded read')
    return raw


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def safe_name(name):
    require(type(name) is str and name.startswith(PREFIX) and '\\' not in name and '\x00' not in name,
            'invalid member name/prefix')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and all(part not in ('', '.', '..') for part in path.parts),
            'noncanonical or traversing member path')
    require(not name.endswith('.gguf'), 'model weights must not be bundled')


def verify(archive, manifest_path, archive_sha, manifest_sha):
    require(HASH.fullmatch(archive_sha) and HASH.fullmatch(manifest_sha), 'external hashes must be SHA256')
    started = time.monotonic_ns()
    manifest_bytes = read_bounded(manifest_path, MAX_MANIFEST)
    archive_bytes = read_bounded(archive, MAX_COMPRESSED)
    require(hashlib.sha256(manifest_bytes).hexdigest() == manifest_sha, 'external manifest hash mismatch')
    require(hashlib.sha256(archive_bytes).hexdigest() == archive_sha, 'external archive hash mismatch')
    # Decode exactly the already hashed immutable bytes, once, with a hard XZ
    # decoder-memory limit and an aggregate tar output cap. Never reopen paths.
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY)
    tar_bytes = decoder.decompress(archive_bytes, max_length=MAX_TOTAL + 1)
    require(len(tar_bytes) <= MAX_TOTAL and decoder.eof and not decoder.unused_data,
            'oversized, incomplete or concatenated xz stream')
    manifest = json.loads(manifest_bytes)
    require(manifest.get('schema') == 'hepta.p7.evidence-manifest.v1', 'manifest schema')
    require(manifest['source_commit'] == SOURCE and manifest['archive']['bytes'] == len(archive_bytes)
            and manifest['archive']['sha256'] == archive_sha, 'manifest archive/source binding differs')
    rows = manifest.get('entries')
    require(type(rows) is list and 0 < len(rows) <= MAX_MEMBERS, 'member count bound')
    expected = {}
    for row in rows:
        name, size, sha = row['name'], row['bytes'], row['sha256']
        safe_name(name)
        require(name not in expected and type(size) is int and 0 <= size <= MAX_FILE
                and type(sha) is str and HASH.fullmatch(sha), 'duplicate or invalid manifest entry')
        expected[name] = row
    require(sum(row['bytes'] for row in rows) <= MAX_TOTAL, 'total expanded byte bound')
    seen, captured, total, captured_bytes = set(), {}, 0, 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:') as bundle:
        for member in bundle:
            safe_name(member.name)
            require(member.isfile() and not member.issym() and not member.islnk(), 'only regular files are permitted')
            require(set(member.pax_headers) <= {'path'} and
                    ('path' not in member.pax_headers or member.pax_headers['path'] == member.name),
                    'only canonical bounded PAX path extension is accepted')
            require(member.name in expected and member.name not in seen, 'unexpected or duplicate member')
            row = expected[member.name]
            require(member.size == row['bytes'] and member.size <= MAX_FILE, 'member size mismatch')
            seen.add(member.name)
            total += member.size
            require(len(seen) <= MAX_MEMBERS and total <= MAX_TOTAL, 'expanded archive bound')
            capture = member.name.endswith(('.json', '.sse', '.stderr', '.stdout'))
            chunks, size, sha = [], 0, hashlib.sha256()
            with bundle.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    size += len(block)
                    require(size <= member.size, 'overlong member payload')
                    sha.update(block)
                    if capture:
                        captured_bytes += len(block)
                        require(captured_bytes <= MAX_CAPTURE, 'semantic capture memory bound')
                        chunks.append(block)
            require(size == row['bytes'] and sha.hexdigest() == row['sha256'], 'member bytes/hash mismatch')
            if capture:
                captured[member.name] = b''.join(chunks)
        require(not bundle.pax_headers and not any(tar_bytes[bundle.offset:]), 'unexpected trailing tar data')
    require(seen == set(expected), 'manifest member denominator differs from archive')
    require(len(seen) == manifest['member_count'] and total == manifest['uncompressed_bytes'], 'manifest totals differ')

    def data(relative):
        return json.loads(captured[PREFIX + relative])

    def text(relative):
        return captured[PREFIX + relative].decode()

    fresh = 'fresh/'
    summary = data(fresh + 'SUMMARY.json')
    capacity = data(fresh + 'capacity/CAPACITY.json')
    calibration = data(fresh + 'calibration/RESULT.json')
    capacity_exec = data(fresh + 'operations/CAPACITY_EXECUTION.json')
    calibration_exec = data(fresh + 'operations/CALIBRATION_EXECUTION.json')
    main_exec = data(fresh + 'operations/MAIN_EXECUTION.json')
    plan = data(fresh + 'PLAN.json')
    require(plan['source_head'] == SOURCE and plan['source_tree'] == TREE
            and plan['prior_qualification_inherited'] is False
            and plan['generation_budget_changed'] is False
            and plan['public_generic_guidance_and_decoder_changed'] is True
            and plan['task_examples_answers_or_selected_nodes_added'] is False,
            'frozen outer plan differs')
    wrapper = PREFIX + fresh + 'operations/run_stage.py'
    require(expected[wrapper]['sha256'] == plan['launcher_sha256'], 'actual launcher binding differs')
    raw_source = None
    for execution in (capacity_exec, calibration_exec, main_exec):
        require(execution['source_commit'] == execution['source_commit_after'] == SOURCE
                and execution['source_clean_before'] is True and execution['source_clean_after'] is True,
                'stage source identity differs')
        require(type(execution['outer_wall_ns']) is int and execution['outer_wall_ns'] > 0, 'missing measured stage cost')
        require(execution['execution_attempt'] == 1 and execution['wrapper_modified_frozen_study_parameters'] is False,
                'execution/retry scope differs')
        require(execution['postflight_errors'] == [] and execution['direct_runner_reaped'] is True
                and execution['raw_source_unchanged'] is True, 'incomplete actual stage finalization')
        phase = execution['stage']
        before = data(fresh + 'operations/' + phase + '.source-before.json')
        after = data(fresh + 'operations/' + phase + '.source-after.json')
        require(before == after and before['head'] == SOURCE and before['tree'] == TREE
                and before['status'] == '' and len(before['files']) == 6907, 'raw source inventory differs')
        require(raw_source is None or raw_source == before, 'stage raw source inventory changed')
        raw_source = before
        for field, suffix in (('source_before', '.source-before.json'), ('source_after', '.source-after.json'),
                              ('stdout', '.stdout'), ('stderr', '.stderr'), ('resource_samples', '.resources.jsonl')):
            member = PREFIX + fresh + 'operations/' + phase + suffix
            require(all(expected[member][key] == execution[field][key] for key in ('bytes', 'sha256')),
                    'outer execution stream/source evidence identity differs')
        require(execution['wrapper']['sha256'] == expected[wrapper]['sha256'], 'stage wrapper changed')
    require(summary['costs']['new_model_acquisition_performed'] is False, 'V13 reused the pinned model; do not invent restoration work')
    require(capacity['complete'] is True and capacity_exec['returncode'] == 0
            and capacity['model_requests'] == 0 and len(capacity['rows']) == 19
            and all(row['passed'] is True and row['reference_is_model_answer'] is False for row in capacity['rows']),
            'capacity denominator or controls differ')
    cli = capacity['independent_cli_tokenizer']
    require(cli['calls'] == 95 and cli['all_matched'] is True and len(cli['retained_call_records']) == 95,
            'CLI tokenizer control denominator differs')
    for call in cli['retained_call_records']:
        relative = 'fresh/' + call['receipt_path'].split('/p7-v13-integrated-953fa62/', 1)[1]
        require(data(relative) == call and call['matched'] is True and call['returncode'] == 0
                and call['cli_token_ids'] == call['server_token_ids'], 'retained tokenizer call mismatch')
    require(sum(row['rendered_request_cli_checks'] for row in capacity['rows']) == 76, 'rendered request denominator')
    for report, phase in ((capacity, 'capacity'), (calibration, 'calibration')):
        require(report['source_commit'] == SOURCE and report['model']['sha256'] == MODEL_SHA
                and report['model']['bytes'] == MODEL_BYTES, 'report source/model pin differs')
        require(all(report[key] is True for key in ('source_unchanged', 'tools_unchanged', 'model_unchanged')),
                'final tool/source/model identity failed')
        for name, sha in report['source_bindings'].items():
            member = PREFIX + fresh + phase + '/source_snapshot/' + name
            require(member in expected and expected[member]['sha256'] == sha, 'source snapshot binding mismatch')
            require(raw_source['files'].get(name) == sha, 'source snapshot differs from raw committed tree inventory')
    require(capacity['tools'] == calibration['tools'] and capacity['source_bindings'] == calibration['source_bindings'],
            'calibration inherited different source/tools')
    require(capacity['protocol_sha256'] == calibration['protocol_sha256'] == plan['protocol_sha256']
            == expected[PREFIX + fresh + 'calibration/source_snapshot/' + plan['protocol_path']]['sha256'],
            'capacity/calibration/outer plan protocol bytes differ')
    pin_name = 'experiments/hia_agent_toolstudy_v11_20261030/provenance/RUNTIME_MEMBERS.json'
    pins = data(fresh + 'calibration/source_snapshot/' + pin_name)
    require(len(pins['members']) == 40 and pins['archive_sha256'] ==
            'cf07c1c112d709bd67e522017471de57ed0ec8bea031d732c5422351c07f65ac', 'runtime archive pin differs')
    tools = calibration['tools']
    for pin in pins['members']:
        key = ('binary' if pin['name'] == 'llama-server' else 'tokenizer' if pin['name'] == 'llama-tokenize'
               else next(key for key in tools if key.startswith('runtime_companion:') and
                         Path(key.split(':', 1)[1]).name == pin['name']))
        require(tools[key]['sha256'] == pin['payload_sha256'] and tools[key]['bytes'] == pin['payload_bytes'],
                'retained runtime payload identity differs')
    require(len([key for key in tools if key.startswith('runtime_companion:')]) == 38,
            'runtime companion denominator differs')
    for phase, folder in (('capacity', 'tokenizer-runtime'), ('calibration', 'engine-00')):
        first = data(fresh + phase + '/' + folder + '/identity.json')
        last = data(fresh + phase + '/' + folder + '/identity-after.json')
        require(first['model'] == last['model'] and last['model_unchanged'] is True
                and last['runtime_unchanged'] is True and first['runtime_files'] == last['runtime_files']
                and len(first['runtime_files']) == 39 and first['model']['sha256'] == MODEL_SHA,
                'engine lifetime model/runtime bindings differ')
        retained_runtime = [value for key, value in tools.items() if key == 'binary' or key.startswith('runtime_companion:')]
        require(Counter(map(digest, first['runtime_files'])) == Counter(map(digest, retained_runtime)),
                'engine runtime multiset differs from actually retained tool pins')
        require(first['context'] == 8192 and first['threads'] == 4
                and first['official_plain_template']['chat_template_kwargs'] == {'enable_thinking': False},
                'engine context/thread/template configuration differs')
        require(first['decoder']['all_public_editable_nodes_included'] is True
                and first['decoder']['reference_selected_nodes_embedded'] is False
                and first['decoder']['correct_operations_or_values_embedded'] is False
                and first['decoder']['admission_authority_changed'] is False, 'decoder scope promoted')
    require(capacity['engine_exited'] is True and capacity['engine_finalization']['complete'] is True
            and capacity['engine_finalization']['close_returned'] is True, 'capacity owner did not exit')
    require(len(calibration['engines']) == 1 and all(calibration['engines'][0][key] is True
            for key in ('complete', 'close_returned', 'exited', 'service_calls_saved')), 'calibration owner incomplete')
    cells = calibration['cells']
    require(len(cells) == 3 and calibration['status'] == 'all_cells_attempted'
            and calibration['valid_observation'] is True, 'fresh qualification was not completed')
    require(calibration['calibration_eligible'] is False and not all(cell['correct'] for cell in cells),
            'this bundle must retain the failed fresh qualification')
    require(sum(cell['correct'] for cell in cells) == summary['calibration']['correct']
            and all(calibration[key] == 0 for key in ('unknown_usage_requests', 'human_answer_repairs', 'terminal_hidden_calls')),
            'failed calibration or complete accounting scope changed')
    for cell in cells:
        require(cell == data(fresh + 'calibration/' + cell['id'] + '/CELL.json'),
                'actual cell/result differs')
    flat_attempts = [(cell, index, attempt) for cell in cells
                     for index, attempt in enumerate(cell['attempts'])]
    attempts = [attempt for cell in cells for attempt in cell['attempts']]
    require(all(0 < len(cell['attempts']) <= 3 for cell in cells), 'attempt budget differs')
    require(calibration['complete_usage'] is True and all(type(a.get('usage')) is dict for a in attempts),
            'complete token accounting is required by this observed bundle')
    totals = {key: sum(a['usage'][key] for a in attempts) for key in ('input_tokens', 'output_tokens', 'total_tokens')}
    aggregate_keys = {'input_tokens': 'known_input_tokens', 'output_tokens': 'known_output_tokens', 'total_tokens': 'total_tokens'}
    require(all(calibration[aggregate_keys[key]] == value for key, value in totals.items()), 'aggregate token totals differ')
    usage_names = sorted(name for name in captured if name.startswith(PREFIX + fresh + 'calibration/engine-')
                         and re.search(r'/transport-[0-9]+\.usage\.json\Z', name))
    require(len(usage_names) == calibration['requests'] == calibration['responses'] == len(attempts),
            'raw generation count differs')
    raw_totals = dict(input_tokens=0, output_tokens=0, total_tokens=0)
    for transport_index, name in enumerate(usage_names):
        usage = json.loads(captured[name])
        stem = name.removesuffix('.usage.json')
        request = json.loads(captured[stem + '.request.json'])
        payload = request['payload']
        require(payload['n_predict'] == 1536 and payload['temperature'] == 0 and payload['seed'] == 0
                and payload['cache_prompt'] is False and payload['stream'] is True, 'generation budget/settings differ')
        raw = captured[stem + '.response.sse']
        events = [json.loads(line[5:].strip()) for line in raw.decode().splitlines() if line.startswith('data:')]
        require(events and events[-1].get('stop') is True and sum(e.get('stop') is True for e in events) == 1,
                'SSE final event missing or duplicated')
        tokens = [token for event in events for token in event.get('tokens', [])]
        final = events[-1]
        require(usage['complete'] is True and usage['unknown_output_tokens'] is False
                and usage['observed_output_token_ids'] == tokens
                and usage['response_bytes'] == len(raw) and usage['events'] == len(events)
                and usage['input_tokens'] == len(payload['prompt']) == final['tokens_evaluated']
                and usage['output_tokens'] == len(tokens) == final['tokens_predicted']
                and usage['total_tokens'] == usage['input_tokens'] + usage['output_tokens'], 'raw SSE/usage accounting differs')
        cell, attempt_index, bound_attempt = flat_attempts[transport_index]
        folder = fresh + 'calibration/' + cell['id'] + '/'
        response = data(folder + 'attempt-' + str(attempt_index) + '.response.json')
        actual_request = data(folder + 'attempt-' + str(attempt_index) + '.request.json')
        evaluated = data(folder + 'attempt-' + str(attempt_index) + '.evaluation.json')
        query = data(folder + 'CAPTURED_QUERY.json')
        wrapped = data(folder + 'candidate-' + str(attempt_index) + '/RESPONSE.json')
        transport_response = json.loads(captured[stem + '.response.json'])
        require(evaluated == cell['attempts'][attempt_index] and evaluated['actual_generation_requested'] is True,
                'cell attempt differs from persisted evaluation')
        for sealed in (query, query['edit_query']):
            require(sealed['query_sha256'] == digest({key: value for key, value in sealed.items() if key != 'query_sha256'}),
                    'captured query digest differs')
        require(actual_request['captured_query_sha256'] == query['query_sha256']
                and actual_request['messages'] == request['messages'] and query['language'] == 'rust',
                'actual request is not bound to captured public query')
        nodes = query['edit_query']['nodes']
        require(all(node['fields'] in ([], ['text']) for node in nodes), 'unexpected public Rust fields')
        ids = sorted(node['id'] for node in nodes if node['fields'])
        require(len(ids) == len(set(ids)) and all(node['id'] + (' edit ' if node['fields'] else ' read-only ')
                in request['messages'][0]['content'] for node in nodes), 'complete public catalogue omitted from prompt')
        public_types = ['Vec<u8>', 'bool', 'u16', 'u32', 'u64', 'u8', 'usize']
        groups = {}
        for node in nodes:
            if node['fields']:
                require(node['category'] in ('expression', 'type'), 'unknown public node category')
                groups.setdefault(node['category'], []).append(node['id'])
        def object_schema(properties, required):
            return {'type': 'object', 'properties': properties,
                    'required': required, 'additionalProperties': False}
        variants = []
        for category, group_ids in sorted(groups.items()):
            replacement = {'enum': public_types} if category == 'type' else {'type': 'string'}
            changes = object_schema({'text': replacement}, ['text'])
            variants.append(object_schema({'node': {'enum': sorted(group_ids)},
                                           'changes': changes}, ['node', 'changes']))
        items = variants[0] if len(variants) == 1 else {'oneOf': variants}
        schema = object_schema({'edits': {'type': 'array', 'minItems': 1,
                                         'maxItems': 16, 'items': items}}, ['edits'])
        require(payload['json_schema'] == schema and response['decoder_sha256'] == digest(schema),
                'decoder differs from complete public node categories and disclosed type grammar')
        body_bytes = captured[stem + '.request.body.json']
        body = json.loads(body_bytes)
        require(body == payload and body_bytes == json.dumps(body, sort_keys=False,
                separators=(',', ':'), allow_nan=False).encode(), 'actual wire body differs from retained payload')
        wire_item = body['json_schema']['properties']['edits']['items']
        wire_variants = wire_item.get('oneOf', [wire_item])
        require(len(wire_variants) == len(variants) and all(list(item['properties']) == ['node', 'changes']
                for item in wire_variants), 'actual decoder wire order differs')
        grammar = transport_response['generation_settings']['grammar']
        require(type(grammar) is str, 'actual native grammar missing')
        rules = [line for line in grammar.splitlines() if '::=' in line
                 and '-node-kv' in line.split('::=', 1)[1]
                 and '-changes-kv' in line.split('::=', 1)[1]]
        require(len(rules) == len(variants) and all(line.split('::=', 1)[1].index('-node-kv')
                < line.split('::=', 1)[1].index('-changes-kv') for line in rules),
                'actual native grammar does not select target before replacement')
        wire = evaluated['decoder_wire_check']
        require(wire == response['decoder_wire_check'] and wire['rules'] == rules
                and wire['actual_request_body_sha256'] == hashlib.sha256(body_bytes).hexdigest()
                and wire['selection_before_replacement'] is True and wire['model_answer_rewritten'] is False
                and wire['does_not_prove_candidate_semantics'] is True,
                'recorded decoder check differs from independently inspected wire/grammar')
        binding = wire['schema_binding']
        ordered_schema = json.dumps(body['json_schema'], sort_keys=False,
                                    separators=(',', ':'), allow_nan=False).encode()
        require(binding['schema_sha256'] == digest(schema)
                and binding['ordered_schema_sha256'] == hashlib.sha256(ordered_schema).hexdigest()
                and binding['query_sha256'] == query['query_sha256']
                and binding['all_public_editable_nodes_included'] is True
                and binding['task_or_reference_replacement_values_embedded'] is False,
                'actual wire schema/query binding differs')
        answer = json.loads(response['text'])
        require(set(answer) == {'edits'} and type(answer['edits']) is list and 1 <= len(answer['edits']) <= 16,
                'observed answer violates its retained public envelope')
        categories = {node['id']: node['category'] for node in nodes if node['fields']}
        for edit in answer['edits']:
            require(type(edit) is dict and set(edit) == {'node', 'changes'} and edit['node'] in ids
                    and type(edit['changes']) is dict and set(edit['changes']) == {'text'}
                    and type(edit['changes']['text']) is str, 'observed answer violates public field schema')
            require(categories[edit['node']] != 'type' or edit['changes']['text'] in public_types,
                    'observed type edit violates disclosed finite grammar')
        require(wrapped['edits'] == answer['edits'] and wrapped['query_sha256'] == query['query_sha256']
                and wrapped['source_revision'] == query['source_revision'], 'host changed model edits or query/revision binding')
        require(response['text'] == transport_response['content'] == ''.join(e.get('content', '') for e in events)
                and response['input_token_ids'] == payload['prompt'] and response['output_token_ids'] == tokens,
                'captured answer/tokens differ from actual transport')
        require(all(response['usage'][key] == evaluated['usage'][key] == usage[key] for key in raw_totals),
                'attempt usage differs from exact SSE usage')
        template = data(fresh + 'calibration/engine-00/template-' + f'{transport_index + 1:03d}' + '.json')
        require(template['matched'] is True and template['messages_or_answers_rewritten_by_host'] is False
                and template['model_generation_requested_by_this_check'] is False
                and template['expected_prompt'] == request['rendered_prompt'], 'plain-template request binding differs')
        for key in raw_totals:
            raw_totals[key] += usage[key]
    require(raw_totals == totals, 'SSE totals disagree with attempt totals')
    require(raw_totals == summary['calibration']['usage'], 'summary usage differs from actual SSE')
    peer = data('review/P7_PEER_REVIEW.json')
    require(peer['source_commit'] == SOURCE and peer['answers_modified'] is False
            and peer['new_model_generations'] == 0 and peer['native_or_repository_code_executed_by_peer'] is False
            and peer['calibration']['correct'] == sum(cell['correct'] for cell in cells)
            and peer['calibration']['requests'] == calibration['requests'],
            'independent peer readback scope differs')
    require(main_exec['returncode'] == 1 and calibration_exec['returncode'] == 0 and main_exec['stage'] == 'main'
            and 'validate_qualification' in text(fresh + 'operations/main.stderr')
            and 'E_TOOLSTUDY_NO_QUALIFIED_MODEL' in text(fresh + 'operations/main.stderr'), 'actual main qualification refusal missing')
    require(not any(name.startswith(PREFIX + fresh + 'main/') for name in expected), 'unexpected main-stage artifacts')
    require(summary['main']['attempted_cells'] == 0 and summary['main']['generation_requests'] == 0
            and summary['main']['startup_refused'] is True and summary['main']['engine_constructed'] is False
            and summary['main']['output_directory_created'] is False, 'main scope was overstated')
    require(summary['historical_results_reused_as_fresh'] is False, 'historical qualification was inherited')
    require(summary['adaptive_same_task_interface_followup'] is True
            and summary['new_independent_task_holdout'] is False, 'adaptive same-task result cannot become independent holdout')
    for phase, execution in (('capacity', capacity_exec), ('calibration', calibration_exec), ('main', main_exec)):
        require(summary['costs']['outer_wall_ns'][phase] == execution['outer_wall_ns'], 'outer cost differs from actual receipt')
    require(summary['costs']['inner_experiment_wall_ns'] == {
                'capacity': capacity['experiment_wall_ns'], 'calibration': calibration['experiment_wall_ns']}
            and summary['costs']['inner_costs_included_in_outer_do_not_add'] is True
            and summary['costs']['full_human_and_agent_development_review_cost'] is None, 'cost overlap/unknown scope differs')
    return {'schema': 'hepta.p7.offline-verification.v1', 'passed': True,
            'archive_sha256': archive_sha, 'manifest_sha256': manifest_sha,
            'members_verified': len(seen), 'uncompressed_bytes_verified': total,
            'source_commit': SOURCE, 'capacity_rows': 19, 'independent_tokenizer_calls': 95,
            'rendered_request_checks': 76, 'fresh_qualification_tasks': len(cells),
            'fresh_qualification_correct': sum(cell['correct'] for cell in cells),
            'generation_requests': calibration['requests'], 'usage_totals_recomputed_from_sse': raw_totals,
            'retained_runtime_payload_pins': 40, 'raw_source_files_each_stage': len(raw_source['files']),
            'public_rust_schema_and_query_bound_outputs': len(usage_names),
            'actual_attempt_statuses': dict(Counter(a['status'] for a in attempts)),
            'main_cells': 0, 'main_startup_refusal_observed': True,
            'verification_wall_ns': time.monotonic_ns() - started,
            'archive_extracted': False, 'archive_code_executed': False, 'network_used': False,
            'scope': 'Integrity and internal consistency of retained evidence; no independent inference/compiler re-execution or cryptographic attestation of past execution.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'refuse to overwrite verification report')
    result = verify(args.archive, args.manifest, args.archive_sha256, args.manifest_sha256)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
