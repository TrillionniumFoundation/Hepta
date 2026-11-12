"""Derive source identities and prepare one owned source-only gate test run."""
from hashlib import sha256
from pathlib import Path
import ast
import json
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/e26ed3e2edcf/combined-gates-r2')
OUT = Path(__file__).resolve().parent
CONTROL = Path('/workspace/scratch/e26ed3e2edcf/core/native116-freeze-r1')
PYTHON = str(Path(sys.executable).resolve())

def write(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')

commands = []
for label, args in (
        ('coverage', ['tests/test_hia_selfhost_language_coverage.py', '--generate-inventory']),
        ('support', ['tools/generate_hia_selfhost_contract.py']),
        ('support-check', ['tools/generate_hia_selfhost_contract.py', '--check'])):
    command = [PYTHON, '-I', '-S', '-B', *args]
    started = time.monotonic_ns()
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180)
    (OUT / (label + '.stdout.log')).write_bytes(completed.stdout)
    (OUT / (label + '.stderr.log')).write_bytes(completed.stderr)
    commands.append({'label': label, 'command': command, 'returncode': completed.returncode,
                     'elapsed_ns': time.monotonic_ns() - started,
                     'stdout_sha256': sha256(completed.stdout).hexdigest(),
                     'stderr_sha256': sha256(completed.stderr).hexdigest()})
    if completed.returncode:
        write('DERIVATION-FAIL.json', {'commands': commands, 'product_execution': False})
        raise SystemExit('source derivation failed; originals retained')
sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import PROFILE, CONTRACT_PATH, file_digests
sources = file_digests()
contract = (ROOT / CONTRACT_PATH).read_bytes()
sources[CONTRACT_PATH] = sha256(contract).hexdigest()
write('DERIVATION.json', {
    'schema': 'hia.combined-core-v2-gates-source-derivation.v1',
    'status': 'CURRENT_SOURCE_IDENTITIES_DERIVED_NOT_NATIVE_QUALIFICATION',
    'source_parent_commit': '72510a7accd86e49cc74e0ba8d6b9fbfa135f63a',
    'source_parent_tree': 'e83376343b0c528ae567154938e7dfa0e77f80c0',
    'profile': PROFILE, 'commands': commands, 'runtime': sys.version,
    'source_count_including_contract': len(sources),
    'derived_documents': {name: {'bytes': (ROOT / name).stat().st_size,
                                'sha256': sha256((ROOT / name).read_bytes()).hexdigest()}
                          for name in ('docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json', CONTRACT_PATH)},
    'native_or_cold_qualification_executed': False,
})
expected = []
for module, cls in (
        ('tests.test_hia_compiler_owner_gates', 'CompilerOwnerGateTests'),
        ('tests.test_hia_selfhost_contract', 'SelfhostContractTests')):
    syntax = ast.parse((ROOT / (module.replace('.', '/') + '.py')).read_bytes())
    node = next(n for n in syntax.body if isinstance(n, ast.ClassDef) and n.name == cls)
    expected.extend(module + '.' + cls + '.' + name for name in sorted(
        n.name for n in node.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')))
write('EXPECTED-IDS.json', expected)
identities = {str(ROOT / name): digest for name, digest in sources.items()}
for path in (OUT / 'run_source_tests.py', OUT / 'EXPECTED-IDS.json',
             CONTROL / 'guardian.py', CONTROL / 'process_owner_impl.py'):
    identities[str(path)] = sha256(path.read_bytes()).hexdigest()
guard = OUT / 'guard'
guard.mkdir(exist_ok=False)
request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
           'command': [PYTHON, '-I', '-S', '-B', str(OUT / 'run_source_tests.py')],
           'cwd': str(ROOT), 'source_identities': identities}
raw = (json.dumps(request, sort_keys=True, separators=(',', ':')) + '\n').encode()
(guard / 'request.json').write_bytes(raw)
write('OWNED-TEST-INTENT.json', {
    'request_sha256': sha256(raw).hexdigest(), 'expected_test_count': len(expected),
    'source_identity_count': len(identities), 'controller_seconds': 180,
    'cleanup_seconds': 3, 'product_native_execution': False,
    'guardian_sha256': identities[str(CONTROL / 'guardian.py')],
    'owner_sha256': identities[str(CONTROL / 'process_owner_impl.py')],
})
print(json.dumps({'derived': True, 'expected_tests': len(expected),
                  'source_identities': len(identities), 'request_sha256': sha256(raw).hexdigest()}))
