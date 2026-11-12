"""Author a fresh authentic source gate for the observed three-byte EOF repair."""
from pathlib import Path
import ast
import base64
import hashlib
import json
import zlib

ROOT = Path(__file__).resolve().parent
PRIOR = ROOT.parent / 'v78-joint-authentic-generation-r1'
JOINT = ROOT.parent / 'v78-joint-integration-r3'
BRANCH = 'codex/hia-joint-source-generation-v78-r2-20261112-dda7'
OLD_BRANCH = 'codex/hia-joint-source-generation-v78-r1-20261112-dda7'

def sha(b): return hashlib.sha256(b).hexdigest()
def blob(b): return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def save(name, raw):
    p = ROOT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    assert not p.exists(), name
    p.write_bytes(raw)
def replace(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new, 1)

raw = (JOINT / 'source-packet-r3/SOURCE-PACKET.json').read_bytes()
assert sha(raw) == '642264dbd9d8a46520d37791e89fffd6104a554fd3d1458dd5b80e64a1f5771e'
p = json.loads(raw)
assert len(p['files']) == 51 and len(p['final_files']) == 3181
assert p['candidate_tree_by_git_encoding'] == '344f747642bf8b96acbd9788860ac80e45709f1f'
old_driver = (PRIOR / 'tools/hia_source_integration_v78.py').read_text()
driver = replace(old_driver,
    'FROZEN_CANDIDATE_TREE = "a9a2b5ec40d176a7684a03ca2859190abd982db0"',
    'FROZEN_CANDIDATE_TREE = "' + p['candidate_tree_by_git_encoding'] + '"')
assert driver.replace(p['candidate_tree_by_git_encoding'],
    'a9a2b5ec40d176a7684a03ca2859190abd982db0') == old_driver
values = {}
for node in ast.parse(driver).body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        if node.targets[0].id in ('GENERATED_HIA', 'GENERATED_DOCS', 'EXPECTED_GENERATORS',
                                 'EXPECTED_SELECTORS', 'EXPECTED_TESTS'):
            values[node.targets[0].id] = ast.literal_eval(node.value)
assert [values[k] for k in ('EXPECTED_GENERATORS', 'EXPECTED_SELECTORS', 'EXPECTED_TESTS')] == [82, 157, 764]
overlay = {'schema': 'hepta.hia.source-overlay.v1', 'base_commit': p['base_commit'],
    'base_tree': p['base_tree'],
    'files': [{k: row[k] for k in ('path', 'mode', 'bytes', 'sha256', 'blob', 'content')} for row in p['files']],
    'expected_generated_paths': list(values['GENERATED_HIA'] + values['GENERATED_DOCS']), 'extra_controls': []}
overlay_raw = (json.dumps(overlay, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
packed = zlib.compress(overlay_raw, 9)
wrapper = {'schema': 'hia.source-overlay-zlib-wrapper.v1', 'bytes': len(overlay_raw),
    'sha256': sha(overlay_raw), 'compressed_bytes': len(packed), 'compressed_sha256': sha(packed),
    'data': base64.b64encode(packed).decode()}
save('tools/hia_source_integration_v78.py', driver.encode())
save('tools/workflow_process.py', (PRIOR / 'tools/workflow_process.py').read_bytes())
save('overlay/source-overlay.wrapper.json', (json.dumps(wrapper, sort_keys=True, indent=2) + '\n').encode())
save('overlay/expected-source-ids.json', (PRIOR / 'overlay/expected-source-ids.json').read_bytes())
old_workflow = (PRIOR / '.github/workflows/hia-source-generation-v78.yml').read_text()
workflow = replace(old_workflow, OLD_BRANCH, BRANCH)
workflow = replace(workflow, '752fbe9877ba49c6370ee099c19ebcab7d58368274694ae8ad08dd709a3f8ff3', sha(overlay_raw))
workflow = replace(workflow, 'name: HIA v78 authentic joint source generation',
                   'name: HIA v78 authentic joint source generation EOF repair')
save('.github/workflows/hia-source-generation-v78.yml', workflow.encode())
save('R2-TO-R3-PROOF.json', (JOINT / 'R2-TO-R3-PROOF.json').read_bytes())
record = {'schema': 'hia.v78-authentic-joint-source-harness-r2.v1', 'branch': BRANCH,
    'parent_harness': '66c614453a10501d3c7013717636c9ec1fd547d7',
    'parent_product': p['base_commit'], 'base_tree': p['base_tree'],
    'input_joint_source_wrapper_sha1': '8f15bad84ebd1e0b5a5b10d9e9fc6cf1f3258c04',
    'input_joint_source_sha256': sha(raw), 'frozen_tree_before_inventory': p['candidate_tree_by_git_encoding'],
    'overlay_bytes': len(overlay_raw), 'overlay_sha256': sha(overlay_raw),
    'source_child_seconds': 1800, 'base_files': 3153, 'final_source_files': 3181,
    'overlay_paths': 51, 'generators': 82, 'source_selectors': 157, 'source_tests': 764,
    'driver_only_changed_constant': 'FROZEN_CANDIDATE_TREE',
    'original_ids_and_supervisor_byte_identical': True,
    'original_actual_run': 43233467986, 'original_actual_status': 'FAIL',
    'original_actual_passed_source_count': 764,
    'original_actual_failed_check': 'original-diff-check',
    'original_artifact_id': 13953846024,
    'original_artifact_sha256': '206ecd15c3dcd6a4bf52bc2fc2d17b1d3648328e0dfa25773e746e28ceb05ae8',
    'fresh_gate_pending': True, 'current_cold': False, 'whole_native': False,
    'known_shared_lifetime_gap_not_closed': True}
save('AUTHORING.json', (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())
save('README.md', b'# HIA v78 authentic joint source generation: EOF repair\n\n'
    b'The preceding real Python 3.14.4 run 43233467986 passed all 82 generators and all 764 source tests, '
    b'but failed its original staged Git whitespace gate on three newly added final blank lines. '
    b'This fresh run removes exactly those three newline bytes and regenerates only their support digests. '
    b'All three complete Python ASTs, including source positions, remain equal; all other 3177 files and modes remain equal.\n\n'
    b'The driver changes only its expected frozen source tree constant. The same exact 4b Git checkout, '
    b'original 1800-second child supervision, 82 generators, 157 normal selectors, 764 ordered IDs and original Git checks run again. '
    b'The previous failed run and complete raw artifact are retained. No outcomes are transferred to the repaired source.\n\n'
    b'This is an independent minimal harness. It creates no product commit, does not activate a native default, '
    b'and does not qualify a current cold bootstrap or whole-native delivery. The separately discovered shared '
    b'CALL/BoolOp lifetime repair remains in a separate R4 development candidate.\n')
static = {'schema': 'hia.v78-authentic-source-r2-static-review.v1', 'status': 'PASS_STATIC_NOT_EXECUTED',
    'driver_parses': True, 'driver_only_expected_tree_changed': True,
    'supervisor_sha256': sha((ROOT / 'tools/workflow_process.py').read_bytes()),
    'expected_source_ids_sha256': sha((ROOT / 'overlay/expected-source-ids.json').read_bytes()),
    'expected_source_ids_count': len(json.loads((ROOT / 'overlay/expected-source-ids.json').read_bytes())['ordered_ids']),
    'same_original_test_id_order': True, 'all_generators': 82, 'normal_selectors': 157,
    'source_files': 3181, 'eof_only_source_changes': 3, 'support_only_digest_update': True,
    'fresh_actual_gate_pending': True, 'whole_native': False}
save('STATIC-REVIEW.json', (json.dumps(static, sort_keys=True, indent=2) + '\n').encode())
files = []
for name in ('.github/workflows/hia-source-generation-v78.yml', 'tools/hia_source_integration_v78.py',
    'tools/workflow_process.py', 'overlay/source-overlay.wrapper.json', 'overlay/expected-source-ids.json',
    'AUTHORING.json', 'README.md', 'STATIC-REVIEW.json', 'R2-TO-R3-PROOF.json', 'author_harness.py'):
    data = (ROOT / name).read_bytes()
    files.append({'path': name, 'bytes': len(data), 'sha256': sha(data), 'sha': blob(data), 'mode': '100644'})
save('HARNESS-FILES.json', (json.dumps({'files': files}, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps({'status': 'AUTHORED_NOT_EXECUTED', 'branch': BRANCH,
                  'overlay_sha256': sha(overlay_raw), 'files': files}, sort_keys=True))
