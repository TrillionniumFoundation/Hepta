"""Independent root review of immutable R16 formal inputs; executes no product."""
from pathlib import Path
import ast
import base64
import copy
import hashlib
import json
import stat
import time

ROOT = Path('/workspace/scratch/dda74a4fae35')
HERE = Path(__file__).resolve().parent
OLD = ROOT / 'v97-union-r14/formal-preparation-r2/harness'
NEW = ROOT / 'v103-union-r16/formal-preparation-r2/harness'
R1 = ROOT / 'v103-union-r16/formal-preparation-r1/harness'
SOURCE = ROOT / 'v103-union-r16/source'
BASE = ROOT / 'v97-source-parser-r14-original/readback-r1/candidate-ci314'

def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def pin(raw):
    return dict(bytes=len(raw), git_blob=blob(raw), sha256=hashlib.sha256(raw).hexdigest())

def read_json(path):
    return json.loads(path.read_bytes())

def check_pin(raw, expected):
    actual = pin(raw)
    assert all(actual[k] == expected[k] for k in actual), (actual, expected)

def tree(rows):
    nested = {}
    for path, row in rows.items():
        current = nested
        parts = path.split('/')
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = (row['mode'], row['git_blob'])
    def walk(node):
        entries = []
        for name, value in node.items():
            is_tree = isinstance(value, dict)
            mode, sha = ('40000', walk(value)) if is_tree else value
            entries.append((name + ('/' if is_tree else ''), mode, name, sha))
        raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
                       for _, mode, name, sha in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return walk(nested)

def replace_once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after)

def main():
    start = time.monotonic()
    intent = read_json(HERE / 'intent.json')
    manifest = read_json(HERE / 'manifest.json')
    assert intent == read_json(NEW.parent / 'HARNESS-PUBLICATION-INTENT.json')
    assert manifest == intent['files']
    assert len(manifest) == 16
    unchanged, changed = [], []
    for name, expected in manifest.items():
        path = NEW / name
        raw = path.read_bytes()
        check_pin(raw, expected)
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        (unchanged if raw == (OLD / name).read_bytes() else changed).append(name)
    assert len(unchanged) == 10 and len(changed) == 6
    assert tree(manifest) == intent['expected_harness_tree'] == '13631b5a2bca668e45fe912b66305b21346a0e1b'
    r2_changed = [n for n in manifest if (NEW / n).read_bytes() != (R1 / n).read_bytes()]
    assert sorted(r2_changed) == sorted(['.github/workflows/hia-combined-source.yml', 'inputs/PARSER-CONTROLS.json', 'tools/run_parser_bounded.py'])
    for remote, name in [('workflow.yml','.github/workflows/hia-combined-source.yml'), ('runner.py','tools/run_parser_bounded.py'), ('controls.json','inputs/PARSER-CONTROLS.json')]:
        assert (HERE / remote).read_bytes() == (NEW / name).read_bytes()
    old_controls = read_json(OLD / 'inputs/PARSER-CONTROLS.json')
    controls = read_json(NEW / 'inputs/PARSER-CONTROLS.json')
    reverted = copy.deepcopy(controls)
    for key in ('expected_ids','materialization_driver','materialization_plan','schema'):
        reverted[key] = old_controls[key]
    for name in ('tools/materialize_candidate.py','tools/run_parser_bounded.py'):
        reverted['harness_files'][name] = old_controls['harness_files'][name]
    assert reverted == old_controls
    assert controls['budgets'] == dict(capacity=1048576, cleanup_seconds=3, compile_seconds=20, qualification_seconds=180, vm_fuel=10000000)
    compiler = bytearray()
    for part in controls['compiler']['parts']:
        encoded = (NEW / part['path']).read_bytes()
        check_pin(encoded, part['encoded'])
        decoded = base64.b64decode(encoded, validate=True)
        check_pin(decoded, part['decoded'])
        compiler.extend(decoded)
    check_pin(compiler, controls['compiler'])
    assert blob(compiler) == '315c6b5f36a1ec679deb68abdca24bd4d1bef9f8'
    driver = (NEW / 'tools/materialize_candidate.py').read_text()
    driver = replace_once(driver, '    representation_name = "HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE"\n', '')
    driver = replace_once(driver, '        representation_name: "@EVIDENCE@/checks/hia-candidate-build-source/representation",\n', '')
    driver = replace_once(driver, '    locations = {candidate_name: evidence, portable_name: portable_evidence, process_name: process_evidence,\n                 representation_name: evidence / "representation"}', '    locations = {candidate_name: evidence, portable_name: portable_evidence, process_name: process_evidence}')
    driver = replace_once(driver, '        "representation_directory_created_by": "new representation Source fixture",\n', '')
    assert driver == (OLD / 'tools/materialize_candidate.py').read_text()
    runner = (NEW / 'tools/run_parser_bounded.py').read_text()
    inverses = [
        ('The original Source runner and Native workflow fragment are unchanged; the fixed materializer adds only the reviewed fourth evidence location.', 'The original materializer, Source runner and product workflow are not modified.'),
        ('len(rows) == 3133', 'len(rows) == 3121'),
        ("result['product_tests_executed'] == 1357", "result['product_tests_executed'] == 1353"),
        ("expected = ids['r16_expected_ordered_ids']", "expected = ids['r14_expected_ordered_ids']"),
        ('len(expected) == 1357', 'len(expected) == 1353'),
        ("(('r15_expected_ordered_ids', 1356), ('r14_expected_ordered_ids', 1353),\n                       ('r13_expected_ordered_ids', 1352), ('r12_expected_ordered_ids', 1342),", "(('r13_expected_ordered_ids', 1352), ('r12_expected_ordered_ids', 1342),"),
        ("'required_original_projection': 1329, 'tests_run': 1357", "'required_original_projection': 1329, 'tests_run': 1353"),
        ('hepta.r16-formal-parser-bounded.v1', 'hepta.r14-formal-parser-bounded.v1'),
    ]
    for new, old in inverses:
        runner = replace_once(runner, new, old)
    assert runner == (OLD / 'tools/run_parser_bounded.py').read_text()
    workflow = (NEW / '.github/workflows/hia-combined-source.yml').read_text()
    for new, old in [
        ('codex/hia-combined-source-parser-v103-r16-20261113-dda7','codex/hia-combined-source-parser-v97-r14-20261113-dda7'),
        ('hia-combined-source-v103-r16','hia-combined-source-v97-r14'),
        ('hia-parser-bounded-v103-r16','hia-parser-bounded-v97-r14'),
        ('cb22fcf729aab99441773428a10e83308380ff33','df4dc7e7b204f280eb5250b91cb4a49c66c1d95a'),
        ('1ce3ab5dc1513f0848de33e2589fef81473c19ef','cfe319279641b124bcd724437857686f36d1aa07'),
        ('7d7c6a92b029d130dc917f59c8e8ca1b68b5a0c1','2ce362fef2a7996ed3b20f5714c264f10eb5b479')]:
        assert new in workflow
        workflow = workflow.replace(new, old)
    assert workflow == (OLD / '.github/workflows/hia-combined-source.yml').read_text()
    old_ids = read_json(OLD / 'inputs/FORMAL-EXPECTED-IDS.json')
    ids = read_json(NEW / 'inputs/FORMAL-EXPECTED-IDS.json')
    for key in old_ids:
        if key not in ('schema', 'selectors'):
            assert ids[key] == old_ids[key], key
    assert ids['selectors'][:-1] == old_ids['selectors'] and len(ids['selectors']) == 232
    expected = ids['r16_expected_ordered_ids']
    assert len(expected) == len(set(expected)) == 1357
    assert ids['bounded_groups'] == old_ids['bounded_groups']
    assert {k:len(v) for k,v in ids['bounded_groups'].items()} == dict(source=10,original43=43,native=9)
    for key, count in intent['explicit_original_ordered_projections'].items():
        prior = ids[key]
        assert len(prior) == len(set(prior)) == count
        assert [item for item in expected if item in set(prior)] == prior
    assert set(expected) - set(ids['r14_expected_ordered_ids']) == set(ids['r15_new_ids'] + ids['r16_new_ids'])
    assert len(ids['r15_new_ids']) == 3 and len(ids['r16_new_ids']) == 1
    old_plan = read_json(OLD / 'inputs/MATERIALIZATION.json')
    plan = read_json(NEW / 'inputs/MATERIALIZATION.json')
    changed_plan = [k for k in sorted(set(plan)|set(old_plan)) if plan.get(k) != old_plan.get(k)]
    assert changed_plan == sorted(['allowed_overrides','expected_authored_files','generators','harness_files','packets','r16_integration','source_contract','source_evidence_capture_r16','source_registration','source_test_environment'])
    assert len(plan['packets']) == 78 and plan['packets'][:75] == old_plan['packets']
    assert len(plan['allowed_overrides']) == 230 and plan['allowed_overrides'][:226] == old_plan['allowed_overrides']
    assert plan['expected_authored_files'] == 481
    assert plan['generators'] == old_plan['generators'] + ['assembly_reparse','core_representation_internal','core_representation_private']
    assert plan['harness_files'][:-1] == old_plan['harness_files']
    old_env = copy.deepcopy(plan['source_test_environment'])
    assert old_env.pop('HEPTA_HIA_REPRESENTATION_SOURCE_EVIDENCE') == '@EVIDENCE@/checks/hia-candidate-build-source/representation'
    assert old_env == old_plan['source_test_environment']
    assert all(v is False for v in plan['constraints'].values())
    assert plan['source_registration']['selectors'] == ids['selectors']
    source_rows = read_json(ROOT / 'v103-union-r16/SOURCE-MANIFEST.json')
    assert len(source_rows) == 3133 and tree(source_rows) == '6272c76d61e55393b665f7091d274720d50451ca'
    for name, identity in source_rows.items():
        path = SOURCE / name
        check_pin(path.read_bytes(), identity)
        assert stat.S_IMODE(path.stat().st_mode) == (0o755 if identity['mode'] == '100755' else 0o644)
    old_test_files = 0
    for path in (BASE / 'tests').rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:
            assert path.read_bytes() == (SOURCE / path.relative_to(BASE)).read_bytes()
            old_test_files += 1
    source_workflow = (SOURCE / '.github/workflows/hia-core.yml').read_text()
    base_workflow = (BASE / '.github/workflows/hia-core.yml').read_text()
    assert source_workflow.split('  native:\n',1)[1] == base_workflow.split('  native:\n',1)[1]
    source_fragment = '  source:\n' + source_workflow.split('  source:\n',1)[1].split('  native:\n',1)[0]
    check_pin(source_fragment.encode(), plan['source_registration']['after_fragment'])
    return dict(schema='hia.root-r16-independent-formal-input-review.v1', status='PASS',
        harness_tree=tree(manifest), harness_files=16, prior_exact_files=unchanged, reviewed_changed_files=changed,
        r2_changed_files=r2_changed, old_test_files_byte_exact=old_test_files,
        original_Native_workflow_fragment_byte_exact=True, original_62_IDs_and_helpers_byte_exact=True,
        original_limits=controls['budgets'], development_B3=pin(compiler),
        source_files=3133, source_tree=tree(source_rows), source_expected=1357,
        generators=134, selectors=232, all_six_original_ordered_projections=True,
        source_driver_only_change='fourth fixed evidence location',
        materialization_plan=pin((NEW/'inputs/MATERIALIZATION.json').read_bytes()),
        expected_ids=pin((NEW/'inputs/FORMAL-EXPECTED-IDS.json').read_bytes()),
        root_independently_fetched_harness_intent='81c6db181ee5a9fe878991ec65853fb404e59f39',
        unique_branch=intent['branch'], sole_parent=intent['sole_parent'],
        product_executions=0, Source_result_inherited=False, Native_result_inherited=False,
        current_source_cold_qualification=False, whole_native=False,
        decision='READY_FOR_ONE_FORMAL_SOURCE_AND_UNCHANGED_62_RUN',elapsed_seconds=time.monotonic()-start)

if __name__ == '__main__':
    result = main()
    with (HERE/'REVIEW-RESULT.json').open('x') as handle:
        json.dump(result,handle,sort_keys=True,indent=2)
        handle.write('\n')
    print(json.dumps(result,sort_keys=True))
