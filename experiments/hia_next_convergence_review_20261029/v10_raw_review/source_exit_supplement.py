#!/usr/bin/env python3
"""Read immutable Git bytes and recorded V10 refusal boundaries only.

This does not import project/evaluator/model code or execute candidate programs.
"""
from pathlib import Path
import collections
import hashlib
import json
import os
import subprocess
import tempfile

RAW = Path('/tmp/hepta-next-agent-v10-qwen4b-01')
OUT = Path(__file__).parent
REPO = Path('/workspace/scratch/220b9d034358/Hepta')
SOURCE = '11d6f78c6c01f66978af7fcf4d40eea7dae5d5f0'
READS = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}


def load(path):
    path = Path(path)
    data = path.read_bytes()
    READS.append({'path': str(path), 'bytes': len(data), 'sha256': sha(data)})
    return json.loads(data)


def git_sources(expected):
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0', GIT_ALLOW_PROTOCOL='file')
    checked = []
    with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as errors:
        for name in sorted(expected):
            assert not Path(name).is_absolute() and '..' not in Path(name).parts
            request.write((SOURCE + ':' + name + '\n').encode())
        request.seek(0)
        process = subprocess.Popen(['git', '-C', str(REPO), 'cat-file', '--batch'],
                                   stdin=request, stdout=subprocess.PIPE, stderr=errors, env=env)
        try:
            for name in sorted(expected):
                header = process.stdout.readline().decode().strip().split()
                assert len(header) == 3 and header[1] == 'blob', name
                length = int(header[2])
                assert 0 <= length <= 64 * 1024 * 1024
                data = process.stdout.read(length)
                assert len(data) == length and process.stdout.read(1) == b'\n', name
                assert sha(data) == expected[name], name
                checked.append({'path': name, 'blob': header[0], 'bytes': length, 'sha256': sha(data)})
            assert process.wait(timeout=30) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return checked


def main():
    review = load(OUT / 'REVIEW.json')
    result = load(RAW / 'RESULT.json')
    assert review['passed_checks'] is True and review['source_commit'] == result['source_commit'] == SOURCE
    assert identity(RAW / 'RESULT.json')['sha256'] == review['result_sha256']
    checked = git_sources(result['source_bindings'])
    assert len(checked) == 185
    exit_path = Path('/tmp/hepta-next-agent-v10-owned-exit.json')
    exited = load(exit_path)
    assert identity(exit_path)['sha256'] == '03ef98d36469e25ba8b97ab8483ee56d4dd4159031b7737182c48d9c6a11ad2a'
    assert exited['all_owned_proc_entries_absent'] is True and len(exited['records']) == 1
    record = exited['records'][0]
    before_path = RAW / 'engine-00/identity.json'
    before = load(before_path)
    assert record['identity_path'] == str(before_path)
    assert record['identity_sha256'] == identity(before_path)['sha256']
    assert record['owned_pid'] == before['pid'] and record['proc_entry_present_at_check'] is False
    assert len(result['engines']) == 1 and result['engines'][0]['exited'] is True

    queries, observations = [], []
    expected_errors = {
        'json_scalar_reasoning': 'E_FACTORIAL_RUST_PROVIDER_CALL_COUNT',
        'two_file_signature_repair': 'E_STRUCTURED_RUST: only disclosed scalar/Vec<u8> types',
        'owner_flow_repair': 'E_STRUCTURED_RUST: trailing tokens outside selected fragment',
    }
    for cell in result['cells']:
        folder = RAW / cell['id']
        query = load(folder / 'CAPTURED_QUERY.json')
        for kind, value in [('outer', query), ('edit', query['edit_query'])]:
            digest = sha(canonical({k: v for k, v in value.items() if k != 'query_sha256'}))
            assert digest == value['query_sha256']
            queries.append({'task': cell['task'], 'query_kind': kind, 'sha256': digest})
        nodes = {node['id']: node for node in query['edit_query']['nodes']}
        for attempt in cell['attempts']:
            index = attempt['index']
            answer = load(folder / ('attempt-' + str(index) + '.response.json'))
            edits = json.loads(answer['text'])['edits']
            evaluation = attempt['evaluation']
            built = evaluation.get('build')
            error = (evaluation.get('error') or (built or {}).get('error'))['message']
            assert error == expected_errors[cell['task']]
            assert evaluation['accepted'] is False and evaluation['hidden_evaluated'] is False
            assert evaluation['failed_transaction_left_source_unchanged'] is True
            assert evaluation['before_revision'] == evaluation['after_revision'] == query['source_revision']
            assert evaluation.get('public') is None
            row = {'task': cell['task'], 'attempt': index, 'observed_error': error,
                   'selected_node_ids': [edit['node'] for edit in edits],
                   'selected_node_categories': [nodes[edit['node']]['category'] for edit in edits],
                   'answer_bytes': len(answer['text'].encode()), 'answer_sha256': sha(answer['text'].encode()),
                   'source_transaction_unchanged': True, 'native_built_or_executed': False,
                   'later_type_functional_resource_result_inferred': False}
            if cell['task'] == 'json_scalar_reasoning':
                external = load(folder / ('candidate-' + str(index)) / 'candidate/BUILD.json')
                assert external == built
                assert built['status'] == 'response_rejected' and built['native_built'] is False
                assert built.get('compile') is None and built.get('compiler') is None
                selected = next(edit for edit in edits if edit['node'] == 'client.rs/entrypoint/n6')
                node, call = nodes[selected['node']], nodes['client.rs/entrypoint/n5']
                assert node['text'] == 'a' and call['text'] == 'api::span(a,b)'
                assert call['start'] <= node['start'] < node['end'] <= call['end']
                start, end = node['start'] - call['start'], node['end'] - call['start']
                assert call['text'][start:end] == node['text']
                # A read-only splice explains the stored edit; no candidate is
                # written, admitted, repaired, compiled or executed.
                enclosing = call['text'][:start] + selected['changes']['text'] + call['text'][end:]
                assert enclosing.count('api::span') == 2
                row.update(retained_BUILD_equals_evaluation=True,
                           actual_compiler_invocation_recorded=False,
                           selected_original_fragment=node['text'],
                           proposed_fragment=selected['changes']['text'],
                           enclosing_call_after_recorded_splice=enclosing,
                           provider_occurrences_in_enclosing_call=2)
            else:
                assert built is None
                row['rejected_before_build_record'] = True
            observations.append(row)

    launch_path = Path('/tmp/hepta-next-agent-v10-capacity-launch-transport.json')
    launch = load(launch_path)
    assert launch['source'] == SOURCE and launch['attempts_before_process'] == 1
    assert launch['model_requests'] == 0 and launch['native_process_started'] is False
    assert launch['output_directory_exists'] is False and launch['log_exists'] is False
    assert launch['elapsed_wall_measured'] is False
    report = {'schema': 'hepta.agent.v10.source-exit-refusal-supplement.v1', 'passed': True,
              'source_commit': SOURCE, 'original_raw_review': identity(OUT / 'REVIEW.json'),
              'git_source_blobs_verified': len(checked), 'source_file_checks': checked,
              'script': identity(__file__), 'exit_receipt': identity(exit_path), 'owned_pid': before['pid'],
              'recorded_exit_identity_and_PID_match': True, 'producer_reported_owned_proc_absent': True,
              'reviewer_independently_observed_historical_process_exit': False,
              'query_digest_checks': queries, 'observed_rejections': observations,
              'new_native_model_tokenizer_compiler_tests_or_network_runs': 0,
              'evaluator_or_gate_rerun': False, 'gates_changed': False,
              'prior_preprocess_transport_failure': {'receipt': identity(launch_path),
                  'attempts': 1, 'recorded_process_started': False, 'model_requests': 0,
                  'exact_orchestration_wall_unknown': True, 'unknown_wall_imputed_as_zero': False,
                  'included_in_three_measured_phase_wall_sum': False},
              'limits': [
                  'Git source bytes are checked directly against the original immutable commit with lazy fetching disabled.',
                  'The process absence and model/runtime hashes remain linked producer observations, not new historical process monitoring or a new weights rehash.',
                  'Read-only fragment splicing describes the submitted scalar edit; no evaluator, compiler, test or candidate code is invoked.',
                  'All rejections precede compiler invocation/native execution. No later correctness, type or resource result is inferred.',
                  'Actual-template rendering and ordering are reviewed separately by the safety reviewer; no tokenizer or template engine is rerun here.',
                  'The recorded pre-process execution-transport failure has unknown orchestration wall. The three measured phases are not total project cost.'
              ], 'read_files': READS}
    (OUT / 'SOURCE_EXIT_SUPPLEMENT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'git_source_blobs_verified': len(checked),
                      'queries_verified': len(queries), 'observed_rejections': len(observations),
                      'new_model_native_compiler_test_runs': 0}, indent=2))


if __name__ == '__main__':
    main()
