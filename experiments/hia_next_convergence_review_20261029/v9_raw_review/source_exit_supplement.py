#!/usr/bin/env python3
"""Read-only V9 Git-byte attribution, refusal and producer exit linkage."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

RAW = Path('/tmp/hepta-next-agent-v9-qwen7b-01')
OUT = Path(__file__).parent
REPO = Path('/workspace/scratch/220b9d034358/Hepta')
GIT_READER = Path('/tmp/hepta-next-convergence-review-20261029/experiments/hia_next_convergence_review_20261029/ci_artifact_7511/review_ci_artifacts.py')
SOURCE = 'ef9fbafabe9db52a5e59220f1738d5842ac164cc'
READS = []


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def load(path):
    record = identity(path)
    READS.append(record)
    return json.loads(Path(path).read_bytes())


def main():
    review = load(OUT / 'REVIEW.json')
    assert review['passed_checks'] is True and review['source_commit'] == SOURCE
    result = load(RAW / 'RESULT.json')
    assert identity(RAW / 'RESULT.json')['sha256'] == review['result_sha256']
    spec = importlib.util.spec_from_file_location('independent_git_blob_reader', GIT_READER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.register_group('V9_frozen_source', result['source_bindings'])
    checked = module.verify_git_sources(REPO, SOURCE)
    assert len(checked) == 172
    exit_path = Path('/tmp/hepta-next-agent-v9-owned-exit.json')
    exited = load(exit_path)
    assert identity(exit_path)['sha256'] == '7dbab8316b27d8f1a182fe11d66120d1a02248adec6517a48340a8932d8de013'
    assert exited['all_owned_proc_entries_absent'] is True and len(exited['records']) == 1
    record = exited['records'][0]
    expected_identity = RAW / 'engine-00/identity.json'
    assert record['identity_path'] == str(expected_identity)
    before = load(expected_identity)
    assert record['identity_sha256'] == identity(expected_identity)['sha256']
    assert record['owned_pid'] == before['pid'] and record['proc_entry_present_at_check'] is False
    assert len(result['engines']) == 1 and result['engines'][0]['exited'] is True
    owner = next(c for c in result['cells'] if c['task'] == 'owner_flow_repair')
    query = load(RAW / owner['id'] / 'CAPTURED_QUERY.json')
    disclosed_nodes = {node['id'] for node in query['edit_query']['nodes']}
    selected = []
    for attempt in owner['attempts']:
        answer = load(RAW / owner['id'] / f"attempt-{attempt['index']}.response.json")
        edit_ids = [edit['node'] for edit in json.loads(answer['text'])['edits']]
        assert edit_ids == ['api.rs/touch/n4', 'api.rs/touch/n21']
        assert 'api.rs/touch/n4' in disclosed_nodes and 'api.rs/touch/n21' not in disclosed_nodes
        assert attempt['evaluation']['error']['message'] == 'E_STRUCTURED_EDIT: duplicate, unknown or unauthorized node'
        assert attempt['evaluation'].get('build') is None and attempt['evaluation'].get('public') is None
        selected.append({'attempt': attempt['index'], 'selected_node_ids': edit_ids,
                         'absent_from_captured_query': sorted(set(edit_ids) - disclosed_nodes),
                         'actual_combined_scope_gate': attempt['evaluation']['error']['message'],
                         'later_syntax_native_resource_error_inferred': False})
    scalar = next(c for c in result['cells'] if c['task'] == 'json_scalar_reasoning')
    compiled = []
    for attempt in scalar['attempts']:
        built = attempt['evaluation']['build']
        external = load(RAW / scalar['id'] / f"candidate-{attempt['index']}/candidate/BUILD.json")
        assert built == external
        assert built['compiler'] == result['tools']['rustc']
        assert built['status'] == 'compile_rejected' and built['native_built'] is False
        assert built['compile']['returncode'] == 1
        codes = sorted(set(re.findall(r'error\[([A-Z][0-9]+)\]', built['compile']['stderr'])))
        assert codes == ['E0277', 'E0308']
        compiled.append({'attempt': attempt['index'], 'returncode': 1, 'error_codes': codes,
                         'retained_BUILD_equals_evaluation': True, 'native_built': False})
    report = {'schema': 'hepta.agent.v9.source-exit-refusal-supplement.v1', 'passed': True,
              'original_raw_review': identity(OUT / 'REVIEW.json'), 'source_commit': SOURCE,
              'git_source_blobs_verified': len(checked), 'source_file_checks': checked,
              'git_reader': identity(GIT_READER), 'script': identity(__file__),
              'exit_receipt': identity(exit_path), 'owned_pid': before['pid'],
              'recorded_exit_identity_and_PID_match': True,
              'producer_reported_owned_proc_absent': True,
              'reviewer_independently_observed_historical_process_exit': False,
              'owner_attempts': selected, 'scalar_compiler_refusals': compiled,
              'new_native_model_tokenizer_compiler_tests_or_network_runs': 0,
              'evaluator_or_gate_rerun': False, 'gates_changed': False,
              'reviewer_development_01': {'source': 'SUPPLEMENT_DEVELOPMENT_01.py',
                  'stderr': 'SUPPLEMENT_DEVELOPMENT_01.stderr.log',
                  'issue': 'The first supplemental audit assumed rejected-before-build records contain explicit null build/public fields; these records legitimately omit those keys. The failed audit and original raw files are retained. Only optional-field reading changed.',
                  'producer_files_changed': False},
              'limitations': ['Exit absence is a linked producer observation, not an independent historical process observation.',
                              'The combined scope rejection is retained verbatim; absent n21 is visible in the original captured query. No later syntax/native/resource result is inferred.',
                              'Git source bytes are compared directly to the immutable measured commit without lazy fetching. Tool/model binary identities remain the original retained records.'],
              'read_files': READS}
    (OUT / 'SOURCE_EXIT_SUPPLEMENT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'git_source_blobs_verified': len(checked),
                     'owned_pid': before['pid'], 'owner_absent_node': 'api.rs/touch/n21',
                     'scalar_compiler_refusals': len(compiled)}, indent=2))


if __name__ == '__main__':
    main()
