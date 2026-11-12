"""Prepare one bounded authoring run from the exact v79 source and five-scan patch."""
from hashlib import sha1, sha256
from pathlib import Path
import difflib
import json
import subprocess
import sys

ROOT = Path('/workspace/scratch/e26ed3e2edcf/compiler-interned-scan-v81-r1')
OUT = Path(__file__).resolve().parent
BASE = 'e7debb7492da1b597cf02f018ee3c64fd157405d'
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

assert git('rev-parse', 'HEAD').decode().strip() == BASE
assert git('rev-parse', 'HEAD^{tree}').decode().strip() == '83a43be6fd510e55c4843cfa8a00aa4889b246cf'
assert git('status', '--porcelain') == b''
generator = ROOT / 'tools/generate_hia_selfhost.py'
baseline = generator.read_bytes()
assert sha256(baseline).hexdigest() == 'd9ede90b8b1d71674bd9f3d7c992f20bd5de7caef39e447bc112eaca7be77f32'
candidate = json.loads((OUT / 'CANDIDATE-GENERATOR.json').read_bytes())['content'].encode()
assert len(candidate) == 82193
assert sha256(candidate).hexdigest() == '9337d6704e47c4257b8b3723c0676809e1ba31914d6cfa6b13e07f2789b03ec2'
assert sha1(f'blob {len(candidate)}\0'.encode() + candidate).hexdigest() == '19876107428018182d8dd0bf99eee65167489ded'
generator.write_bytes(candidate)
contract_source = ROOT / 'tools/hia_selfhost_contract.py'
before = contract_source.read_text()
old_profile = 'selfhost-core-linux-x86_64-v79-native-core-emitter-json-pretty-installed-resources-development'
new_profile = 'selfhost-core-linux-x86_64-v81-native-core-emitter-json-pretty-interned-scans-development'
assert before.count(old_profile) == 1
contract_source.write_text(before.replace(old_profile, new_profile))
control = OUT / 'controls'
control.mkdir(exist_ok=False)
for name, digest in (
        ('guardian.py', 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'),
        ('process_owner_impl.py', '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2')):
    raw = (OUT.parent / 'installed-resource-fix-v79-r1/controls' / name).read_bytes()
    assert sha256(raw).hexdigest() == digest
    with (control / name).open('xb') as stream:
        stream.write(raw)
mutable_output = 'examples/hia_bootstrap/selfhost.hiaasm'
old_output = (ROOT / mutable_output).read_bytes()
metadata = {
    'schema': 'hia.interned-scan-single-source-authoring-intent.v1',
    'status': 'PREEXECUTION_SOURCE_AUTHORING_ONLY', 'base_commit': BASE,
    'base_tree': '83a43be6fd510e55c4843cfa8a00aa4889b246cf',
    'candidate_generator_blob': '19876107428018182d8dd0bf99eee65167489ded',
    'candidate_generator_sha256': sha256(candidate).hexdigest(),
    'generator_proof_commit': 'f1cd72f5a60dde5ac5a9d5edc42bf46c2ee566c8',
    'profile': new_profile, 'runtime': sys.version,
    'mutable_outputs': [mutable_output],
    'old_output': {'bytes': len(old_output), 'sha256': sha256(old_output).hexdigest(),
                   'git_blob': sha1(f'blob {len(old_output)}\0'.encode() + old_output).hexdigest()},
    'qualification_seconds': 180, 'cleanup_seconds': 3,
    'native_compiler_or_cold_or_method_execution': False,
    'existing_contract_is_not_current_candidate_qualification': True,
    'all_original_limits_and_111_current_test_ids_retained': True,
    'unknown_launch_acknowledgement_policy': 'inspect originals; do not repeat this request'}
with (OUT / 'AUTHORING-INTENT.json').open('x') as stream:
    json.dump(metadata, stream, indent=2, sort_keys=True)
    stream.write('\n')
diff = ''.join(difflib.unified_diff(baseline.decode().splitlines(keepends=True),
    candidate.decode().splitlines(keepends=True), fromfile='v79/tools/generate_hia_selfhost.py',
    tofile='v81/tools/generate_hia_selfhost.py'))
(OUT / 'GENERATOR-DIFF.patch').write_text(diff)
contract_path = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
declared = json.loads((ROOT / contract_path).read_bytes())['source_identity']['files']
names = (set(declared) | {contract_path}) - {mutable_output}
identities = {str(ROOT / name): sha256((ROOT / name).read_bytes()).hexdigest()
              for name in sorted(names)}
for path in (OUT / 'AUTHORING-INTENT.json', OUT / 'prepare_authoring.py',
             control / 'guardian.py', control / 'process_owner_impl.py'):
    identities[str(path)] = sha256(path.read_bytes()).hexdigest()
guard = OUT / 'authoring-guard'
guard.mkdir(mode=0o700, exist_ok=False)
request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
           'command': [str(Path(sys.executable).resolve()), '-B', '-m', 'tools.generate_hia_selfhost'],
           'cwd': str(ROOT), 'source_identities': identities}
raw = (json.dumps(request, sort_keys=True, separators=(',', ':')) + '\n').encode()
assert len(raw) <= 262144
(guard / 'request.json').write_bytes(raw)
summary = {'prepared': True, 'source_identities': len(identities),
           'request_sha256': sha256(raw).hexdigest(), 'request_bytes': len(raw),
           'generated_output_excluded_only_as_declared_mutable_output': mutable_output}
with (OUT / 'PREPARATION.json').open('x') as stream:
    json.dump(summary, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(summary))
