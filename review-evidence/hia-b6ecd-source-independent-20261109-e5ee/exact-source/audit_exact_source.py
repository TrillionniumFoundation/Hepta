"""Read-only review of retained CI bytes; never imports or runs project code."""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--workspace-root', required=True, type=Path)
BASE = parser.parse_args().workspace_root.resolve()
OUT = BASE / 'pr817-b6ecd-readonly-review/exact-source'
REPO = BASE / 'hepta-successor-integration-review'
RUNTIME_REPO = BASE / 'runtime-review'
ZIP = BASE / 'evidence/b6ecd-exact-source-original.zip'
HEAD = '6ecd8023615a6e0b2dc269379fb059c656b38b6f'
TREE = '4c51962e030e9ea39c6498224c99eb40fbdd2f35'
RUNTIME = '4cd85c99c5f5a480832c48fbde8561bb365f67a9'
RUNTIME_TREE = '6b78d53b53d51a6c070bb37e8e9f6a15ad26d0e8'
SCOPE = ['subject', 'property', 'profile', 'assumptions', 'checker', 'unproved_obligations']

def sha(data):
    return hashlib.sha256(data).hexdigest()

def blob_id(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def elf_text(data):
    """Read the existing ELF64 section table; no image is loaded or executed."""
    assert data[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, strings = struct.unpack_from('<HHH', data, 58)
    assert size == 64 and strings < count and offset + count * size <= len(data)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    string_header = sections[strings]
    table = data[string_header[4]:string_header[4] + string_header[5]]
    hits = []
    for section in sections:
        start = section[0]
        assert start < len(table)
        end = table.index(0, start)
        if table[start:end] == b'.text':
            at, length = section[4:6]
            assert at + length <= len(data)
            hits.append((data[at:at + length], at, section[3]))
    assert len(hits) == 1
    return hits[0]

def dump(name, value):
    (OUT / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

def git_blob_map(repo, tree, paths):
    """Only Git object reads, with byte hashes checked against object IDs."""
    rows = subprocess.check_output(['git', 'ls-tree', '-rz', tree], cwd=repo)
    index = {}
    for row in rows.split(b'\0'):
        if not row:
            continue
        meta, path = row.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        if kind == 'blob':
            index[path.decode()] = (mode, oid)
    paths = sorted(paths)
    assert all(p in index for p in paths)
    ids = [index[p][1] for p in paths]
    data = subprocess.check_output(['git', 'cat-file', '--batch'],
                                   input=('\n'.join(ids) + '\n').encode(), cwd=repo)
    result = {}
    pos = 0
    for path, oid in zip(paths, ids):
        end = data.index(b'\n', pos)
        actual, kind, size = data[pos:end].decode().split()
        assert kind == 'blob' and actual == oid
        size = int(size)
        raw = data[end + 1:end + 1 + size]
        assert blob_id(raw) == oid and data[end + 1 + size:end + 2 + size] == b'\n'
        result[path] = {'sha256': sha(raw), 'git_blob_sha1': oid,
                        'bytes': size, 'mode': index[path][0], 'raw': raw}
        pos = end + 2 + size
    assert pos == len(data)
    return result

OUT.mkdir(parents=True, exist_ok=True)
artifact_meta = json.loads((OUT / 'metadata/artifact.json').read_text())
run_meta = json.loads((OUT / 'metadata/run.json').read_text())
commit_meta = json.loads((OUT / 'metadata/head-commit.json').read_text())
raw_zip = ZIP.read_bytes()
assert artifact_meta['id'] == 13652892138
assert artifact_meta['workflow_run']['id'] == run_meta['id'] == 42565807355
assert artifact_meta['workflow_run']['head_sha'] == run_meta['head_sha'] == HEAD
assert run_meta['status'] == 'completed' and run_meta['conclusion'] == 'success'
assert run_meta['event'] == 'push' and run_meta['run_attempt'] == 1
assert commit_meta['sha'] == HEAD and commit_meta['tree']['sha'] == TREE
assert len(raw_zip) == artifact_meta['size_in_bytes'] == 36367360
assert 'sha256:' + sha(raw_zip) == artifact_meta['digest']
jobs_meta = json.loads((OUT / 'metadata/jobs.json').read_text())
assert len(jobs_meta['jobs']) == 1
source_job = jobs_meta['jobs'][0]
assert source_job['id'] == 128991941450 and source_job['run_id'] == run_meta['id']
assert source_job['status'] == 'completed' and source_job['conclusion'] == 'success'
current_step = next(s for s in source_job['steps'] if s['name'] ==
                    'Qualify the current checked-in compiler through the borrowed-buffer lifecycle')
assert current_step['status'] == 'completed' and current_step['conclusion'] == 'success'
source_log_path = BASE / 'candidate-6ecd-ci-readback/exact-source-job-128991941450.log'
source_log = source_log_path.read_bytes()
assert len(source_log) == 207431
assert sha(source_log) == 'a0c818d8f7dac1a7ab00983285edb0a1f0c11ffbfa9bace3caf1be3f28cf3d91'
log_lines = source_log.decode().splitlines()
assert any(line.endswith(' ' + HEAD) and '2026-11-09T05:41:59.' in line for line in log_lines)
assert any('agent-buffer-current-compiler' in line and '2026-11-09T05:46:07.' in line for line in log_lines)

with zipfile.ZipFile(ZIP) as z:
    names = z.namelist()
    assert len(names) == len(set(names)) == 28122
    def read_json(name):
        return json.loads(z.read(name))
    lock = read_json('release-lock.json')
    cold = read_json('cold-selfhost')
    nested = read_json('cold-selfhost.cold/qualification.json')
    language = read_json('selfhost-language.json')
    assertions = read_json('selfhost-language.assertions.json')
    fragments = read_json('original-select-fragments/qualification.json')
    replay = read_json('original-select-fragments-replay/replay.json')
    fragment_manifest = read_json('original-select-fragments/artifact-manifest.json')
    leaf = read_json('cmovne-leaf/qualification.json')
    safe = read_json('safe-core/qualification.json')
    strict = read_json('original-select-strict/qualification.json')
    lifecycle = read_json('agent-buffer-continuation/qualification.json')
    current_lifecycle = read_json('agent-buffer-current-compiler/qualification.json')
    assert z.read('source.txt').decode().split() == [HEAD, TREE]
    assert lock['sources']['hepta']['commit'] == HEAD and lock['sources']['hepta']['tree'] == TREE
    assert lock['sources']['runtime']['commit'] == RUNTIME and lock['sources']['runtime']['tree'] == RUNTIME_TREE
    assert lock['qualification']['source_lock_only'] is True
    assert all(v is False for k, v in lock['qualification'].items() if k != 'source_lock_only')
    assert lock['selfhost']['profile'] == 'selfhost-core-linux-x86_64-v16'
    source_groups = {
        'release_lock': lock['files']['hepta'],
        'cold_export': cold['source_manifest'],
        'language': language['source_manifest'],
        'fragment_qualifier': fragments['source_identity'],
        'cmovne_qualifier': leaf['source_identity'],
        'safe_core_qualifier': safe['source_identity'],
        'strict_agent_replay_support': strict['replay_support_sources'],
        'strict_agent_replay_qualifier': {'tools/qualify_hia_agent_original_select_delta.py': strict['replay_source_sha256']},
    }
    all_paths = set().union(*(set(v) for v in source_groups.values()))
    all_paths.update({'tools/qualify_hia_agent_buffer_lifecycle.py', 'tools/hia_selfhost_child.py',
                      'hepta/hia_proof_contract.py', '.github/workflows/hia-sixgap-source.yml'})
    git_files = git_blob_map(REPO, TREE, all_paths)
    source_rows = []
    for group, identities in source_groups.items():
        for path, record in identities.items():
            expected = record['sha256'] if isinstance(record, dict) else record
            got = git_files[path]
            assert got['sha256'] == expected, (group, path)
            if isinstance(record, dict) and 'bytes' in record:
                assert got['bytes'] == record['bytes'], (group, path, 'bytes')
            source_rows.append({'group': group, 'path': path, 'sha256': expected,
                                'git_blob_sha1': got['git_blob_sha1'], 'bytes': got['bytes']})
    runtime_files = git_blob_map(RUNTIME_REPO, RUNTIME_TREE, lock['files']['runtime'])
    for path, expected in lock['files']['runtime'].items():
        assert runtime_files[path]['sha256'] == expected
    assert cold['source_manifest'] == nested['source_manifest'] == language['source_manifest']
    assert len(cold['source_manifest']) == 253
    closure = []
    for path, expected in cold['source_manifest'].items():
        raw = z.read('cold-selfhost.cold/source/' + path)
        assert sha(raw) == expected == lock['files']['hepta'][path]
        assert blob_id(raw) == git_files[path]['git_blob_sha1']
        closure.append({'path': path, 'bytes': len(raw), 'sha256': expected,
                        'git_blob_sha1': blob_id(raw), 'all_bindings_matched': True})
    print('source identities verified', {k: len(v) for k, v in source_groups.items()}, 'runtime', len(runtime_files), flush=True)
    assert cold['status'] == 'COLD_SELFHOST_REPLAY_PASS'
    assert len(cold['checks']) == 11 and all(v is True for v in cold['checks'].values())
    assert [cold['qualification_wall_limit_seconds'], cold['cleanup_wall_limit_seconds']] == [180, 3]
    assert sha(z.read('cold-selfhost.cold/qualification.json')) == cold['nested_report_sha256']
    assert nested['status'] == 'SELF_HOSTED_FIXED_CORE_PASS'
    assert len(nested['checks']) == 1447 and all(v is True for v in nested['checks'].values())
    generations = []
    for row in nested['generations'] + nested['modified_generations']:
        path = 'cold-selfhost.cold/qualification.evidence/' + row['case'] + '.image.bin'
        raw = z.read(path)
        assert len(raw) == row['produced_bytes'] and sha(raw) == row['produced_sha256']
        generations.append({'generation': row['case'], 'bytes': len(raw), 'sha256': sha(raw)})
    assert len({r['sha256'] for r in generations[:3]}) == 1
    assert generations[3]['sha256'] != generations[4]['sha256'] == generations[5]['sha256']
    assert language['status'] == 'SELFHOST_LANGUAGE_COVERAGE_PASS'
    assert len(language['checks']) == 1196 and all(v is True for v in language['checks'].values())
    assert assertions['passed'] and assertions['tests_run'] == 10 and assertions['additional_native_execution'] is False
    assert not any(assertions[k] for k in ['errors', 'failures', 'skipped'])
    assert assertions['report_sha256'] == sha(z.read('selfhost-language.json'))
    assert all(v is False for v in language['claims'].values())
    assert fragments['source_checkout']['commit'] == HEAD and fragments['source_checkout']['tree'] == TREE
    assert fragments['source_checkout']['worktree_clean'] is True
    assert len(fragment_manifest) == replay['retained_artifacts_checked'] == 555
    for path, expected in fragment_manifest.items():
        assert sha(z.read('original-select-fragments/' + path)) == expected, path
    assert sha(z.read('original-select-fragments/artifact-manifest.json')) == replay['manifest_sha256']
    assert fragments['status'] == 'PASS_SCOPED_COPIED_FRAGMENTS' and replay['status'] == 'PASS'
    frozen_paths = {'original': 'original-selfhost.hiaasm', 'candidate': 'candidate-selfhost.hiaasm', 'patch': 'fresh-select.patch'}
    frozen = {}
    for key, path in frozen_paths.items():
        digest = sha(z.read('original-select-inputs/' + path))
        assert digest == fragments['exact_frozen_input_sha256'][key]
        assert digest == strict['frozen_inputs'][key]['sha256']
        frozen[key] = digest
    assert fragments['patch_reconstruction_exact'] is True
    assert fragments['original_agent_four_claim_gate'] == replay['original_agent_four_claim_gate'] == 'HOLD'
    for key in ['adoption_authorized', 'agent_proof_receipt_issued', 'evaluation_performed', 'whole_compiler_or_original_agent_delta_proved', 'original_provider_history_available']:
        assert fragments[key] is False
    assert fragments['provider_fees'] is None and fragments['provider_tokens'] is None
    assert not any(replay[k] for k in ['compiler_execution_performed', 'native_execution_performed', 'new_agent_receipts'])
    proof_rows = []
    query_rows = []
    def proof(v, report_path, query_prefix, byte_paths):
        assert all(k in v for k in SCOPE), report_path
        assert v['ok'] is True and v['status'] == 'smt_validated'
        for mapping in [v['source_identity'], v['checker']['source_identity']]:
            for path, expected in mapping.items():
                assert git_files['hepta/' + path]['sha256'] == expected
        byte_bindings = []
        for field, member in byte_paths.items():
            raw = z.read(member)
            mode = 'archived_bytes'
            bound = raw
            if field == 'core_sha256' and sha(raw) != v['subject'][field]:
                bound = json.dumps(json.loads(raw), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
                mode = 'canonical_Core_JSON_per_exact_checker_source'
            assert sha(bound) == v['subject'][field], (report_path, field)
            byte_bindings.append({'field': field, 'member': member, 'binding_mode': mode,
                                  'archived_sha256': sha(raw), 'bound_sha256': sha(bound)})
        assert len(v['obligations']) == 5
        for obligation in v['obligations']:
            member = query_prefix + '/' + obligation['query_file']
            digest = sha(z.read(member))
            result = read_json(member + '.result.json')
            assert digest == obligation['query_sha256'] == result['query_sha256']
            assert obligation['name'] == result['name']
            assert obligation['result'] == obligation['expected'] == result['result'] == result['expected']
            query_rows.append({'report': report_path, 'name': obligation['name'], 'query_sha256': digest,
                               'expected': obligation['expected'], 'recorded_result': result['result']})
        row = {'report': report_path, 'report_sha256': sha(z.read(report_path)),
               'six_scope_fields_present': True, 'checker_source_count': len(v['checker']['source_identity']),
               'source_identities_matched': True, 'subject_byte_bindings_matched': True,
               'byte_bindings': byte_bindings,
               'subject': v['subject'], 'property': v['property'], 'profile': v['profile'],
               'assumptions': v['assumptions'], 'checker': v['checker'],
               'claims': v['claims'], 'limits': v['limits'], 'unproved_obligations': v['unproved_obligations']}
        proof_rows.append(row)
    fragment_rows = []
    for case in fragments['cases']:
        typ = case['type']
        prefix = 'original-select-fragments/' + typ
        original_path = prefix + '/validation.json'
        replay_path = 'original-select-fragments-replay/' + typ + '-validation.json'
        original = read_json(original_path)
        again = read_json(replay_path)
        assert all(original[k] == again[k] for k in SCOPE)
        paths = {'core_sha256': prefix + '/specification.core.json', 'object_sha256': prefix + '/projection.o',
                 'final_image_sha256': prefix + '/projection.so'}
        proof(original, original_path, prefix + '/queries', paths)
        proof(again, replay_path, 'original-select-fragments-replay/' + typ + '-queries', paths)
        binding = read_json(prefix + '/source-binding.json')
        assert binding == case['source_binding']
        complete = z.read(prefix + '/actual-c1-output.image.bin')
        copied = z.read(prefix + '/copied-fragment.bin')
        assert sha(complete) == binding['compiler_output_sha256'] and len(complete) == binding['compiler_output_bytes']
        assert complete[binding['start']:binding['end']] == copied == bytes.fromhex(binding['fragment_hex'])
        assert sha(copied) == binding['fragment_sha256'] and len(copied) == 35
        assert sha(z.read(prefix + '/actual-c1-output.input.bin')) == binding['source_sha256']
        object_text, _, _ = elf_text(z.read(prefix + '/projection.o'))
        image_text, image_offset, image_address = elf_text(z.read(prefix + '/projection.so'))
        lo = case['projection']['copied_text_start']
        hi = case['projection']['copied_text_end']
        assert object_text[lo:hi] == image_text[lo:hi] == copied and hi - lo == 35
        assert image_offset == original['image_binding']['linked_text_file_offset']
        assert image_address == original['image_binding']['linked_text_vaddr']
        assert sha(image_text) == original['image_binding']['linked_text_sha256']
        assert binding['entire_compiler_output_validated'] is False and binding['fragment_instructions_reemitted'] is False
        assert case['projection']['scaffolding_proves_original_context'] is False
        assert case['projection']['scaffolding_is_new'] is True
        assert sha(z.read(original_path)) == case['validation_sha256']
        native = read_json(prefix + '/native-mathematics.json')
        whole = read_json(prefix + '/whole-output-finite-witnesses.json')
        assert native['finite_witnesses_only'] is True and len(native['results']) == case['native_calls'] == 40
        assert len(whole) == case['whole_generated_program_finite_calls']
        assert all(x['finite_observation_only'] is True for x in whole)
        fragment_rows.append({'type': typ, 'complete_image_sha256': sha(complete), 'copied_fragment_sha256': sha(copied),
                              'copied_bytes': len(copied), 'six_scope_fields_equal_on_recheck': True,
                              'original_input_output_copy_object_and_image_bytes_bound': True,
                              'conditional_projection': case['projection'], 'native_finite_calls': len(native['results']),
                              'whole_program_finite_calls': len(whole)})
    assert len(fragment_rows) == 5
    assert len({x['complete_image_sha256'] for x in fragment_rows}) == 4
    assert len({x['copied_fragment_sha256'] for x in fragment_rows}) == 2
    assert fragments['counts']['smt_obligations'] == 25
    assert sum(x['native_finite_calls'] for x in fragment_rows) == 200
    assert sum(x['whole_program_finite_calls'] for x in fragment_rows) == 64
    assert leaf['status'] == 'PASS' and leaf['counts']['smt_validated'] == 13
    for case in leaf['cases']:
        if case['status'] != 'smt_validated':
            continue
        prefix = 'cmovne-leaf/' + case['id']
        proof(read_json(prefix + '/validation.json'), prefix + '/validation.json', prefix + '/queries',
              {'core_sha256': prefix + '/core.json', 'object_sha256': prefix + '/subject.o',
               'final_image_sha256': prefix + '/subject.so'})
    assert safe['ok'] and safe['git_head'] == HEAD and safe['source_unchanged'] is True
    for case in ['scalar_add', 'guarded_update', 'read_byte']:
        prefix = 'safe-core/' + case
        attempt = read_json(prefix + '/attempt.json')
        proof(attempt['result']['validation'], prefix + '/attempt.json', prefix + '/queries',
              {'core_sha256': prefix + '/core.hia.json', 'object_sha256': prefix + '/candidate.o',
               'final_image_sha256': prefix + '/program.so'})
        prefix += '/independent-check'
        attempt = read_json(prefix + '/attempt.json')
        assert attempt['compiler_invoked'] is False and attempt['linker_invoked'] is False and attempt['adopted'] is False
        proof(attempt['validation'], prefix + '/attempt.json', prefix + '/queries',
              {'core_sha256': prefix + '/core.hia.json', 'object_sha256': prefix + '/candidate.o',
               'final_image_sha256': prefix + '/candidate.so'})
    assert len(proof_rows) == 29 and len(query_rows) == 145
    assert strict['status'] == 'HOLD_REAL_DELTA_STRICT_GATE'
    strict_false = ['adoption_attempted', 'adoption_authorized', 'production_adoption', 'full_cost_complete',
                    'new_fresh_agent_study', 'original_study_rewritten', 'provider_history_available',
                    'remote_mcp_endpoint_qualified', 'same_core_substitution', 'strict_claims_weakened']
    assert all(strict[k] is False for k in strict_false)
    assert strict['provider_fees'] is None and strict['provider_tokens'] is None
    prior_path = BASE / 'evidence/pr819-exact-source.zip'
    assert sha(prior_path.read_bytes()) == '577e5ab4311d6bd6f66a106eb676806277e809225f408b83851c5e2e5b1a5cee'
    with zipfile.ZipFile(prior_path) as prior_zip:
        prior_strict = json.loads(prior_zip.read('original-select-strict/qualification.json'))
    assert all(strict[k] == prior_strict[k] for k in ['frozen_objective', 'frozen_workload', 'frozen_inputs'])
    assert lifecycle['status'] == 'PASS_SCOPED_NONPRODUCTION_LIFECYCLE'
    lifecycle_false = ['universal_compiler_or_machine_refinement_proved', 'production_adoption',
                       'full_cost_complete', 'new_fresh_agent_study', 'full_provider_interaction_available',
                       'remote_mcp_endpoint_qualified', 'original_fresh_agent_study_rewritten']
    assert all(lifecycle[k] is False for k in lifecycle_false)
    assert strict['frozen_objective']['required_claims'] == [
        'core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check']
    assert [(r['claim'], r['status']) for r in strict['verification']['checks']] == [
        ('core_admission', 'proved'), ('behavior_equivalence', 'unknown')]
    assert strict['native_refinement']['checks'][0]['status'] == 'unsupported'
    assert strict['encoding']['checks'][0]['status'] == 'proved'
    assert strict['evaluation_response']['status'] == 'rejected'
    assert strict['evaluation_response']['error']['code'] == 'E_HIA_CLAIM_REQUIRED'

    def wire(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

    strict_scope_rows = []
    for section in ['verification', 'encoding', 'native_refinement']:
        for item in strict[section]['checks']:
            assert all(k in item for k in SCOPE)
            assert item['checker']['installation'] == lock['installation']
            assert item['global_safety_proved'] is False and item['execution_authority_granted'] is False
            evidence_sha = item['evidence_artifact']['sha256']
            evidence_raw = z.read('original-select-strict/state/artifacts/' + evidence_sha)
            assert sha(evidence_raw) == evidence_sha
            evidence = json.loads(evidence_raw)
            auxiliary = item['checker'].get('auxiliary_checker_sha256')
            if auxiliary is not None:
                assert auxiliary == evidence['checker_sha256']
                if item['checker']['method'] == 'independent_safe_core_machine_validation':
                    assert auxiliary == sha(wire(evidence['source_identity']))
                    for path, expected in evidence['source_identity'].items():
                        assert git_files['hepta/' + path]['sha256'] == expected
                else:
                    assert item['checker']['method'] == 'compositional_scalar_effect'
                    # Read the exact function's literal source list; do not call it.
                    optimization_ast = ast.parse(git_files['hepta/hia_optimization.py']['raw'])
                    identity_function = next(n for n in optimization_ast.body
                                             if isinstance(n, ast.FunctionDef) and n.name == 'checker_identity')
                    source_loop = next(n for n in identity_function.body if isinstance(n, ast.For))
                    source_names = ast.literal_eval(source_loop.iter)
                    assert len(source_names) == 9
                    digest = hashlib.sha256()
                    for name in source_names:
                        digest.update(name.encode() + b'\0' + git_files['hepta/' + name]['raw'] + b'\0')
                    assert digest.hexdigest() == auxiliary
            strict_scope_rows.append({'claim': item['claim'], 'status': item['status'],
                'scope': {k: item[k] for k in SCOPE}, 'evidence_artifact_sha256': evidence_sha,
                'six_scope_fields_present': True, 'source_installation_bound': True})

    lifecycle_member_rows = []
    lifecycle_scope_rows = []

    def audit_lifecycle(prefix, q, expected_source_sha256, current_checked_in_source):
        """Read retained protocols and byte bindings, never invoke the service."""
        assert q['status'] == 'PASS_SCOPED_NONPRODUCTION_LIFECYCLE'
        assert all(q[k] is False for k in lifecycle_false)
        assert q['provider_fees'] is None and q['provider_tokens'] is None
        assert q['installation'] == lock['installation']
        assert q['compiler_source_sha256'] == q['source_artifact']['sha256'] == expected_source_sha256
        source_member = prefix + '/state/artifacts/' + expected_source_sha256
        frozen_source = z.read(source_member)
        assert len(frozen_source) == q['compiler_source_bytes'] and sha(frozen_source) == expected_source_sha256
        if current_checked_in_source:
            assert frozen_source == git_files[lock['selfhost']['source']]['raw']
            assert expected_source_sha256 == lock['selfhost']['source_sha256']
        else:
            assert frozen_source == z.read('original-select-inputs/candidate-selfhost.hiaasm')
        artifacts = {}
        members = [name for name in names if name.startswith(prefix + '/')]
        for name in members:
            raw = z.read(name)
            lifecycle_member_rows.append({'member': name, 'bytes': len(raw), 'sha256': sha(raw)})
            if name.startswith(prefix + '/state/artifacts/'):
                digest = name.rsplit('/', 1)[-1]
                assert len(digest) == 64 and digest == sha(raw)
                artifacts[digest] = raw
        references = set()
        def check_artifact_refs(value):
            if isinstance(value, dict):
                if {'id', 'uri', 'sha256'} <= value.keys() and str(value['uri']).startswith('hia://artifacts/'):
                    assert value['sha256'] in artifacts, value
                    references.add(value['sha256'])
                for item in value.values():
                    check_artifact_refs(item)
            elif isinstance(value, list):
                for item in value:
                    check_artifact_refs(item)
        check_artifact_refs(q)
        assert q['baseline']['sha256'] == q['candidate']['sha256']
        assert q['baseline_build']['native_artifact']['sha256'] == q['candidate_build']['native_artifact']['sha256']
        assert q['consumer_invocation']['artifact'] == q['candidate_build']['native_artifact']
        assert q['frozen_objective']['required_claims'] == ['core_admission', 'behavior_equivalence', 'encoding_check']
        assert q['frozen_objective']['allow_unchanged'] is True
        assert q['frozen_objective']['min_improvement_ratio'] == 0
        agent_results = q['verification']['checks'] + q['encoding']['checks'] + q['independent_machine_refinement']['checks']
        assert [(r['claim'], r['status']) for r in agent_results] == [
            ('core_admission', 'proved'), ('behavior_equivalence', 'proved'),
            ('encoding_check', 'proved'), ('lowering_refinement', 'unsupported')]
        for result in agent_results:
            assert all(k in result for k in SCOPE)
            assert result['checker']['installation'] == lock['installation']
            assert result['global_safety_proved'] is False and result['execution_authority_granted'] is False
            evidence = json.loads(artifacts[result['evidence_artifact']['sha256']])
            auxiliary = result['checker'].get('auxiliary_checker_sha256')
            if auxiliary is not None:
                assert auxiliary == evidence['checker_sha256'] == sha(wire(evidence['source_identity']))
                for path, digest in evidence['source_identity'].items():
                    assert git_files['hepta/' + path]['sha256'] == digest
            lifecycle_scope_rows.append({'qualification_member': prefix + '/qualification.json',
                'claim': result['claim'], 'status': result['status'],
                'scope': {k: result[k] for k in SCOPE},
                'source_installation_bound': True, 'evidence_artifact_sha256': result['evidence_artifact']['sha256'],
                'six_scope_fields_present': True})
        for section in ['verification', 'encoding', 'independent_machine_refinement']:
            receipt = json.loads(artifacts[q[section]['verification_receipt']['sha256']])
            assert receipt['checks'] == q[section]['checks']
            assert receipt['installation'] == lock['installation']
        for section, ref in [('measurements', 'measurements'), ('cost_ledger', 'full_cost_ledger')]:
            assert json.loads(artifacts[q['evaluation'][ref]['sha256']]) == q[section]
        assert q['evaluation']['outcome'] == 'unchanged' and q['evaluation']['adopted'] is False
        assert all(q['evaluation'][k] is True for k in ['report_complete', 'planned_workload_complete', 'termination_confirmed'])
        assert all(q['cost_ledger'][k] is False for k in [
            'full_search_cost_complete', 'external_costs_complete', 'net_optimization_benefit_proved', 'entries_truncated'])
        assert q['cost_ledger']['failed_attempts_retained'] is True
        transcript = [json.loads(line) for line in z.read(prefix + '/tool-transcript.jsonl').decode().splitlines()]
        assert q['worker_calls'] == 25 and len(transcript) == 50
        worker_rows = []
        source_imports = []
        for seq in range(1, q['worker_calls'] + 1):
            stem = prefix + '/worker-' + str(seq).zfill(4)
            request = read_json(stem + '.request.json')
            response = read_json(stem + '.stdout.json')
            unsigned = {k: v for k, v in request.items() if k != 'request_sha256'}
            assert request['request_sha256'] == sha(wire(unsigned))
            assert response['schema'] == 'hia-agent-worker-report-v1' and response['complete'] is True
            for key in ['tool', 'request_sha256', 'profile_sha256', 'catalog_sha256']:
                assert response[key] == request[key]
            for key, expected in lock['installation'].items():
                assert response[key] == expected
            intent, result = transcript[2 * (seq - 1):2 * seq]
            assert intent['phase'] == 'intent' and result['phase'] == 'response'
            assert intent['sequence'] == result['sequence'] == seq
            assert intent['tool'] == result['tool'] == request['tool']
            assert intent['arguments'] == result['arguments'] == request['arguments']
            assert result['response'] == response['response']
            if request['tool'] == 'hia_artifact':
                supplied = request['arguments']['source']
                if supplied['kind'] == 'path':
                    assert supplied['expected_sha256'] == expected_source_sha256
                    assert supplied['max_bytes'] == len(frozen_source)
                    source_imports.append(seq)
            worker_rows.append({'sequence': seq, 'tool': request['tool'],
                                'request_sha256': request['request_sha256'], 'correlation_matched': True})
        assert source_imports == [7]
        assert q['consumer_processes'] == 6 and q['consumer_state_reopened_for_every_operation'] is True
        assert q['consumer_authority_database_copied'] is False
        consumer_rows, responses = [], []
        for seq, action in enumerate(['acquire', 'invoke', 'acquire', 'release', 'release', 'invoke'], 1):
            stem = prefix + '/consumer-worker-' + str(seq).zfill(4)
            request = read_json(stem + '.request.json')
            process = read_json(stem + '.process.json')
            response = read_json(stem + '.stdout.json')
            assert request['action'] == response['action'] == action
            digest = sha(wire(request))
            assert process['request_sha256'] == response['request_sha256'] == digest
            assert process['returncode'] == 0 and process['timed_out'] is False
            assert request['installation'] == response['installation'] == lock['installation']
            assert request['worker_sha256'] == response['worker_sha256'] == git_files['tools/qualify_hia_agent_buffer_lifecycle.py']['sha256']
            expected_status = 'rejected' if seq == 6 else 'completed'
            assert response['status'] == expected_status
            responses.append(response['result'])
            consumer_rows.append({'sequence': seq, 'action': action, 'status': response['status'],
                'request_sha256': digest, 'process_returncode': process['returncode'],
                'process_timed_out': process['timed_out'], 'installation_and_worker_source_bound': True})
        assert responses[0]['generation'] == responses[1]['generation'] == '1'
        assert responses[2]['generation'] == '0'
        assert responses[1] == q['consumer_invocation'] and responses[5] == q['released_lease']
        assert q['released_lease'] == {'code': 'E_HIA_LEASE', 'status': 'rejected'}
        assert q['adoption']['current'] == {'epoch': '1', 'generation': '1'}
        assert q['rollback']['current'] == {'epoch': '2', 'generation': '0'}
        assert q['adoption_replay_identical'] is True and q['rollback']['past_effects_reversed'] is False
        emitted = z.read(prefix + '/consumer-program.image.bin')
        assert len(emitted) == q['consumer_image']['byte_length'] == q['consumer_invocation']['values'][0]
        assert sha(emitted) == q['consumer_image']['sha256']
        output_buffer = next(r for r in q['consumer_invocation']['buffers'] if r['argument'] == 1)
        assert artifacts[output_buffer['artifact']['sha256']][:len(emitted)] == emitted
        program_ast = ast.parse(git_files['tools/qualify_hia_agent_buffer_lifecycle.py']['raw'])
        source_program = next(ast.literal_eval(node.value) for node in program_ast.body
                              if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'PROGRAM' for t in node.targets))
        assert source_program == z.read(prefix + '/consumer-program.hiaasm')
        assert len(q['consumer_runs']) == 3
        for row, case, expected in zip(q['consumer_runs'], ['consumer-0', 'consumer-1', 'consumer-255'], [4000000007, 700000001, 700000001]):
            request = read_json(prefix + '/' + case + '.request.json')
            receipt = read_json(prefix + '/' + case + '.receipt.json')
            assert receipt == row and row['case'] == case
            assert row['status'] == 'returned' and row['core_u32'] == expected and row['source_unchanged'] is True
            assert row['image_sha256'] == row['artifact_sha256'] == request['image_sha256'] == sha(emitted)
            assert row['runner_sha256'] == git_files['tools/hia_selfhost_child.py']['sha256']
            raw_input = z.read(prefix + '/' + case + '.input.bin')
            raw_output = z.read(prefix + '/' + case + '.output.bin')
            assert len(raw_input) == len(raw_output) == 1 and raw_input == raw_output
            assert sha(raw_input) == row['input_sha256'] == row['source_sha256'] == request['source_sha256']
            assert sha(raw_output) == row['output_sha256']
        return {'qualification_member': prefix + '/qualification.json', 'status': q['status'],
            'compiler_source_sha256': expected_source_sha256, 'compiler_source_bytes': len(frozen_source),
            'matches_current_checked_in_source': current_checked_in_source,
            'retained_members_hashed': len(members), 'digest_named_artifacts_hashed': len(artifacts),
            'distinct_referenced_artifacts_bound': len(references), 'baseline_and_candidate_same_Core': True,
            'verification_claim_statuses': {r['claim']: r['status'] for r in agent_results},
            'acceptance_scope': q['acceptance_scope'], 'required_claims': q['frozen_objective']['required_claims'],
            'evaluation_outcome': q['evaluation']['outcome'], 'worker_calls': worker_rows,
            'consumer_processes': consumer_rows, 'consumer_authority_database_copied': False,
            'compiled_consumer_image_sha256': sha(emitted), 'compiled_consumer_image_bytes': len(emitted),
            'original_native_finite_observations': 3, 'retained_generation_1_invocation_after_rollback': True,
            'new_acquire_generation_0_and_released_lease_rejection': True,
            'scope_flags': {k: q[k] for k in lifecycle_false}, 'remaining': q['remaining'],
            'not_an_optimization_comparison': True, 'no_local_service_or_native_execution': True}

    lifecycle_reviews = [
        audit_lifecycle('agent-buffer-continuation', lifecycle, frozen['candidate'], False),
        audit_lifecycle('agent-buffer-current-compiler', current_lifecycle, lock['selfhost']['source_sha256'], True),
    ]
    print('both lifecycle source/protocol/consumer bindings verified', [r['retained_members_hashed'] for r in lifecycle_reviews], flush=True)
    support = read_json('cold-selfhost.cold/source/docs/HIA_SELFHOST_CORE_SUPPORT.json')
    areas = {x['area']: x for x in support['support']}
    assert set(areas['scalar_types']['items']) == {'u8', 'u16', 'u32', 'u64', 'usize', 'bool'}
    assert areas['general_core_checker']['status'] == 'not_implemented'
    assert areas['general_object_linking']['status'] == 'not_implemented'
    assert all(value is False for value in support['claims'].values())
    result = {
        'schema': 'hepta.review.exact-source-readonly.v1', 'review_subject': HEAD, 'source_tree': TREE,
        'status': 'PASS_ORIGINAL_CI_IDENTITY_HASH_AND_SCOPE_REVIEW', 'overall_six_item_acceptance': 'HOLD',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'artifact': {'id': artifact_meta['id'], 'run_id': run_meta['id'], 'run_conclusion': run_meta['conclusion'],
                     'run_event': run_meta['event'], 'run_attempt': run_meta['run_attempt'], 'name': artifact_meta['name'], 'bytes': len(raw_zip),
                     'sha256': sha(raw_zip), 'members': len(names), 'official_digest_matches': True},
        'source_identity': {'commit': HEAD, 'tree': TREE, 'runtime_commit': RUNTIME, 'runtime_tree': RUNTIME_TREE,
                            'installation': lock['installation'], 'release_lock_sha256': sha(z.read('release-lock.json')),
                            'compiler_source_sha256': lock['selfhost']['source_sha256'], 'profile': lock['selfhost']['profile'],
                            'qualification_flags': lock['qualification']},
        'source_job': {'id': source_job['id'], 'actual_checkout_commit': HEAD, 'actual_checkout_tree': TREE,
                       'original_log_sha256': sha(source_log), 'original_log_bytes': len(source_log),
                       'current_checked_in_compiler_step': current_step,
                       'later_runtime_dependency_checkout_is_a_separate_repository': True},
        'source_closure': {'cold_export_files': len(closure), 'release_hepta_files': len(lock['files']['hepta']),
                           'release_runtime_files': len(runtime_files), 'fragment_source_identity_files': len(fragments['source_identity']),
                           'all_recorded_source_hashes_match_exact_git_blobs': True, 'unique_hepta_source_paths': len(git_files)},
        'cold': {'status': cold['status'], 'checks': len(cold['checks']), 'nested_status': nested['status'],
                 'nested_checks': len(nested['checks']), 'all_checks_true': True, 'budgets_seconds': [180, 3],
                 'all_six_generation_images_hashed': True, 'B1_B2_B3_identical': True,
                 'M1_differs_M2_equals_M3': True, 'modified_transition': 'Expected predecessor-wrapper transition, not all-three identity.',
                 'generations': generations, 'claims': nested['claims']},
        'language': {'status': language['status'], 'checks': len(language['checks']), 'all_checks_true': True,
                     'counts': language['counts'], 'assertions': assertions, 'claims': language['claims']},
        'fragment': {'status': fragments['status'], 'replay_status': replay['status'], 'artifact_manifest_members': len(fragment_manifest),
                     'all_member_hashes_match': True, 'source_checkout': fragments['source_checkout'], 'frozen_input_sha256': frozen,
                     'counts': fragments['counts'], 'complete_images': 4, 'copied_byte_strings': 2,
                     'original_case_obligation_records': 25, 'replay_case_obligation_records': 25,
                     'case_obligation_pairs': 25, 'replay_is_not_25_additional_obligations': True,
                     'cases': fragment_rows, 'scope': {k: fragments[k] for k in ['subject', 'property', 'profile', 'assumptions', 'checker', 'unproved_obligations']},
                     'flags': {k: fragments[k] for k in ['adoption_authorized', 'agent_proof_receipt_issued', 'evaluation_performed',
                                                       'whole_compiler_or_original_agent_delta_proved', 'original_agent_four_claim_gate',
                                                       'original_provider_history_available', 'provider_fees', 'provider_tokens']}},
        'machine_report_inventory': {'positive_reports_with_six_scope_fields': len(proof_rows),
                                     'safe_core_producer_and_consumer_reports': 6, 'leaf_reports': 13,
                                     'fragment_original_and_recheck_reports': 10, 'recorded_query_rows_checked': len(query_rows),
                                     'query_rows_are_not_counted_as_distinct_theorems': True,
                                     'cmovne_counts': leaf['counts'], 'safe_core_claims': safe['claims']},
        'strict_original_agent': {'status': strict['status'], 'frozen_claims_not_weakened': True,
                                  'frozen_objective_workload_and_inputs_unchanged_from_original_635_artifact': True,
                                  'objective': strict['frozen_objective'],
                                  'scope_flags': {k: strict[k] for k in strict_false}, 'remaining': strict['remaining'],
                                  'claim_statuses': {r['claim']: r['status'] for r in strict_scope_rows},
                                  'evaluation_rejection_code': strict['evaluation_response']['error']['code'],
                                  'counterexample_retained_in_original_artifact': True,
                                  'provider_fees': strict['provider_fees'], 'provider_tokens': strict['provider_tokens']},
        'scoped_buffer_lifecycle': {'status': lifecycle['status'], 'acceptance_scope': lifecycle['acceptance_scope'],
                                    'scope_flags': {k: lifecycle[k] for k in lifecycle_false},
                                    'evaluation_outcome': lifecycle['evaluation']['outcome'],
                                    'remaining': lifecycle['remaining']},
        'two_distinct_compiler_lifecycles': lifecycle_reviews,
        'broader_CI_cohort': {'qualification_inferred_from_this_artifact': False,
                             'original_other_workflow_failures_not_erased': True,
                             'note': 'This review does not qualify the whole cohort. Original guarded/shared failures and any retries require their own retained review.'},
        'general_core_boundary': {'supported_scalar_types': areas['scalar_types']['items'],
                                  'support_claims': support['claims'], 'declared_limits': support['limits'],
                                  'general_core_checker': areas['general_core_checker'],
                                  'general_object_linking': areas['general_object_linking']},
        'method': {'project_modules_imported': 0, 'project_compiler_invocations': 0, 'solver_invocations': 0,
                   'native_image_executions': 0, 'dynamic_project_tests': 0, 'new_malformed_inputs': 0,
                   'online_mutations': 0, 'kind': 'Original CI ZIP/JSON/hash and exact Git blob review; recorded CI outcomes are not locally rerun.'},
        'qualification_transfer': 'None. Applies to this exact head, tree, original run and artifact. No qualification is asserted for a later merge commit, main, public default or online deployment.',
        'does_not_establish': ['complete Core self-hosting', 'whole-compiler correctness', 'complete hardware ISA correctness',
                               'general loader/ABI/resource/FFI correctness', 'context reachability/composition for copied fragments',
                               'original Agent four-claim acceptance or production adoption', 'complete provider interaction or billing',
                               'stable NDU economic benefit', 'qualification of a later source commit'],
    }
    dump('audit.json', result)
    dump('source-closure.json', {'source_commit': HEAD, 'source_tree': TREE, 'files': closure, 'all_matched': True})
    dump('source-identities.json', {'source_commit': HEAD, 'source_tree': TREE, 'groups': {k: len(v) for k, v in source_groups.items()},
                                     'files': source_rows, 'runtime_files': [{k: v for k, v in x.items() if k != 'raw'} | {'path': path}
                                                                          for path, x in runtime_files.items()]})
    dump('proof-scope-inventory.json', {'scope_fields': SCOPE, 'positive_reports': proof_rows,
                                       'query_records': query_rows, 'agent_lifecycle_scope_results': lifecycle_scope_rows,
                                       'strict_agent_scope_results': strict_scope_rows,
                                       'no_local_solver_invocation': True})
    dump('lifecycle-member-hashes.json', {'source_commit': HEAD, 'members': lifecycle_member_rows,
                                         'all_digest_named_artifact_and_reference_bindings_matched': True})
    (OUT / 'release-lock.json').write_bytes(z.read('release-lock.json'))
    (OUT / 'source.txt').write_bytes(z.read('source.txt'))
    (OUT / 'source-job-original.log').write_bytes(source_log)
    print('read-only audit completed', len(proof_rows), 'positive scope reports;', len(query_rows), 'retained query records; overall HOLD', flush=True)
