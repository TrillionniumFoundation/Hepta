"""Regenerate exact source identities and prepare original bounded source controls."""
from hashlib import sha256
from pathlib import Path
import ast
import json
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/e26ed3e2edcf/installed-resource-v79-r1')
OUT = Path(__file__).resolve().parent
CONTROL = OUT / 'controls'
PYTHON = str(Path(sys.executable).resolve())
PARENT = 'd0e110e19f9433baaf202a0f605671c7205b4cff'

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
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=180)
    (OUT / (label + '.stdout.log')).write_bytes(result.stdout)
    (OUT / (label + '.stderr.log')).write_bytes(result.stderr)
    commands.append({'label': label, 'command': command, 'returncode': result.returncode,
                     'elapsed_ns': time.monotonic_ns() - started,
                     'stdout_sha256': sha256(result.stdout).hexdigest(),
                     'stderr_sha256': sha256(result.stderr).hexdigest()})
    if result.returncode:
        write('DERIVATION-FAIL.json', {'commands': commands, 'native_execution': False})
        raise SystemExit('source derivation failed; original logs preserved')

sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import PROFILE, CONTRACT_PATH, file_digests
from hepta.hia_agent_contract import NATIVE_SOURCE_FILES, DISCOVERY_FILES, PUBLICATION_BUILD_FILES
from hepta.hia_core_lowering_selection import ABI_SOURCE, checked_abi, source_names
sources = file_digests()
sources[CONTRACT_PATH] = sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()

def population(raw, module):
    tree = ast.parse(raw)
    return {c.name: [module + '.' + c.name + '.' + n for n in sorted(
        x.name for x in c.body if isinstance(x, ast.FunctionDef) and x.name.startswith('test_'))]
        for c in tree.body if isinstance(c, ast.ClassDef)}

test_path = 'tests/test_hia_agent_installed_resources.py'
before = subprocess.check_output(['git', 'show', PARENT + ':' + test_path], cwd=ROOT)
after = (ROOT / test_path).read_bytes()
assert after.replace(b'index in range(38)', b'index in range(31)').replace(
    b'all 39 source units', b'all 32 source units') == before
old_ids = population(before, 'tests.test_hia_agent_installed_resources')
new_ids = population(after, 'tests.test_hia_agent_installed_resources')
assert old_ids == new_ids and sum(map(len, new_ids.values())) == 21
contract_ids = population((ROOT / 'tests/test_hia_selfhost_contract.py').read_bytes(),
                          'tests.test_hia_selfhost_contract')['SelfhostContractTests']
expected = new_ids['AgentInstalledResourceSourceTests'] + contract_ids
assert len(expected) == 11
write('EXPECTED-IDS.json', expected)
write('ALL-ORIGINAL-INSTALLATION-IDS.json', old_ids)
abi_resources = (ABI_SOURCE, *source_names(checked_abi((ROOT / ABI_SOURCE).read_bytes())))
assert len(abi_resources) == 40
write('DERIVATION.json', {
    'schema': 'hia.installed-resource-source-derivation.v1',
    'status': 'CURRENT_SOURCE_IDENTITIES_DERIVED_NOT_NATIVE_QUALIFICATION',
    'parent_commit': PARENT, 'parent_tree': '6381daf9beb11d873d4608c26facc0b9e5bc747f',
    'profile': PROFILE, 'commands': commands, 'runtime': sys.version,
    'source_count_including_contract': len(sources),
    'core_HIA_units': 39, 'core_resources_including_ABI': len(abi_resources),
    'native_resource_count': len(NATIVE_SOURCE_FILES),
    'all_manifest_resources': len(DISCOVERY_FILES) + len(NATIVE_SOURCE_FILES) + len(PUBLICATION_BUILD_FILES),
    'unchanged_original_installation_methods': 21,
    'source_only_test_methods': len(expected),
    'test_file_inverse_to_original_is_exact': True,
    'native_installation_executed': False, 'cold_qualification_executed': False,
    'derived_documents': {name: {'bytes': (ROOT / name).stat().st_size,
                                'sha256': sha256((ROOT / name).read_bytes()).hexdigest()}
                          for name in ('docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json', CONTRACT_PATH)}})
identities = {str(ROOT / name): digest for name, digest in sources.items()}
for path in (OUT / 'run_source_tests.py', OUT / 'EXPECTED-IDS.json',
             CONTROL / 'guardian.py', CONTROL / 'process_owner_impl.py'):
    identities[str(path)] = sha256(path.read_bytes()).hexdigest()
assert identities[str(CONTROL / 'guardian.py')] == 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
assert identities[str(CONTROL / 'process_owner_impl.py')] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
guard = OUT / 'guard'
guard.mkdir(mode=0o700, exist_ok=False)
request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
           'command': [PYTHON, '-I', '-S', '-B', str(OUT / 'run_source_tests.py')],
           'cwd': str(ROOT), 'source_identities': identities}
raw = (json.dumps(request, sort_keys=True, separators=(',', ':')) + '\n').encode()
(guard / 'request.json').write_bytes(raw)
write('OWNED-TEST-INTENT.json', {'request_sha256': sha256(raw).hexdigest(),
    'expected_test_count': len(expected), 'source_identity_count': len(identities),
    'controller_seconds': 180, 'cleanup_seconds': 3,
    'native_installation_executed': False, 'cold_qualification_executed': False})
print(json.dumps({'prepared': True, 'expected_tests': len(expected),
                  'source_identities': len(identities), 'request_sha256': sha256(raw).hexdigest()}))
