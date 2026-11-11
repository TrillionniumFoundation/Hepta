"""Run unchanged source/cold/native gates with complete per-step evidence."""
import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--full', action='store_true')
a = p.parse_args()
root = a.source.resolve(); out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
os.chdir(root)
sys.path.insert(0, str(root))
from tools.hia_selfhost_contract import validate_contract, CONTRACT_PATH
from workflow_process import run_workflow_step
contract = validate_contract()
sources = {**contract['source_identity']['files'],
           CONTRACT_PATH: sha256((root / CONTRACT_PATH).read_bytes()).hexdigest()}
environment = dict(os.environ)
environment['PYTHONDONTWRITEBYTECODE'] = '1'
environment['PYTHONUNBUFFERED'] = '1'
cold = out / 'cold.json'
for name in ('AGENT_STDIO', 'CORE_MODULE_GRAPH', 'CAPABILITY_RENAMING',
             'FUNCTION_SHAPE', 'PROGRAM_SHAPE', 'INSTRUCTION_POLICY',
             'ARTIFACT_PUBLICATION', 'CORE_ADMISSION', 'CORE_ADMISSION_CLI',
             'CORE_PATCH', 'CORE_PATCH_CLI'):
    environment['HEPTA_HIA_' + name + '_COLD_REPORT'] = str(cold)
steps = []


def run(name, args, *, timeout=1800):
    started = time.monotonic()
    stdout = out / (name + '.stdout.log')
    stderr = out / (name + '.stderr.log')
    result = {'name': name, 'command': [sys.executable, '-B', *args]}
    print(json.dumps({'starting': name}), flush=True)
    step_environment = dict(environment)
    step_environment['HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS'] = str(out / (name + '-module-projects'))
    owner = run_workflow_step(result['command'], cwd=root, env=step_environment,
                      stdout_path=stdout, stderr_path=stderr,
                      receipt_path=out / (name + '.owner.json'),
                      seconds=timeout)
    result['owner'] = owner
    result['returncode'] = owner.get('returncode')
    result['timeout'] = owner.get('timed_out') is not False
    result['seconds'] = time.monotonic() - started
    result['stdout'] = {'path': str(stdout), 'sha256': sha256(stdout.read_bytes()).hexdigest()}
    result['stderr'] = {'path': str(stderr), 'sha256': sha256(stderr.read_bytes()).hexdigest()}
    steps.append(result)
    (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('name', 'returncode', 'timeout', 'seconds')}), flush=True)
    return (result['returncode'] == 0 and not result['timeout']
            and owner.get('status') == 'WORKFLOW_STEP_COMPLETED'
            and owner.get('cleanup', {}).get('complete') is True)


def suite(name, names=None, discover=False):
    result_path = out / (name + '.json')
    source = '''import json,unittest
loader=unittest.defaultTestLoader
suite=loader.discover('tests',top_level_dir='.') if DISCOVER else loader.loadTestsFromNames(NAMES)
r=unittest.TextTestRunner(verbosity=2).run(suite)
value={'tests_run':r.testsRun,'successful':r.wasSuccessful(),
       'errors':[{'test':str(t),'traceback':s} for t,s in r.errors],
       'failures':[{'test':str(t),'traceback':s} for t,s in r.failures],
       'skipped':[{'test':str(t),'reason':s} for t,s in r.skipped],
       'expected_failures':[str(t) for t,s in r.expectedFailures],
       'unexpected_successes':[str(t) for t in r.unexpectedSuccesses]}
open(RESULT,'w').write(json.dumps(value,indent=2)+'\\n')
raise SystemExit(0 if r.wasSuccessful() and not r.skipped and not r.expectedFailures else 1)
'''
    code = 'DISCOVER=' + repr(discover) + '\nNAMES=' + repr(names or []) + '\nRESULT=' + repr(str(result_path)) + '\n' + source
    return run(name, ['-c', code], timeout=5400 if discover else 1800)


workflow = (root / '.github/workflows/hia-core.yml').read_text()
blocks = re.findall(r'          names = \((.*?)\n          \)', workflow, re.S)
assert len(blocks) == 2
named = [re.findall(r"'(tests\.[^']+)'", block) for block in blocks]
generator_match = re.search(r'for component in ([^;]+); do', workflow)
assert generator_match is not None
generators = generator_match.group(1).split()
assert generators and all(re.fullmatch(r'[a-z0-9_]+', name) for name in generators)
reproduction = out / 'source-reproduction'
reproduce_code = '''from pathlib import Path
import json,subprocess,sys
subprocess.run(['git','clone','--quiet','--no-hardlinks',SOURCE,COPY],check=True)
for name in GENERATORS:
    print(json.dumps({'generator':name}),flush=True)
    subprocess.run([sys.executable,'-B','-m','tools.generate_hia_'+name],cwd=COPY,check=True)
subprocess.run([sys.executable,'-B','tests/test_hia_selfhost_language_coverage.py','--generate-inventory'],cwd=COPY,check=True)
status=subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=COPY,text=True)
if status:
    print(status,flush=True)
    subprocess.run(['git','diff','--stat'],cwd=COPY,check=True)
    raise SystemExit('generated source differs from the frozen candidate')
print(json.dumps({'generators':len(GENERATORS),'identical':True}),flush=True)
'''
reproduce_code = ('SOURCE=' + repr(str(root)) + '\nCOPY=' + repr(str(reproduction))
                  + '\nGENERATORS=' + repr(generators) + '\n' + reproduce_code)
ok = run('source-reproduction', ['-c', reproduce_code])
ok = run('source-contract', ['tools/generate_hia_selfhost_contract.py', '--check']) and ok
ok = run('source-scope', ['tools/check_hia_core_only.py']) and ok
ok = suite('source-tests', named[0]) and ok
ok = run('cold', ['tools/replay_hia_selfhost_cold.py', '--output', str(cold)], timeout=240) and ok
if cold.exists():
    record = json.loads(cold.read_text())
    cold_ok = record.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
else:
    cold_ok = False
if cold_ok:
    ok = run('language', ['tests/test_hia_selfhost_language_coverage.py', '--output', str(out / 'language.json')]) and ok
    ok = suite('native-applications', named[1]) and ok
    groups = {
        'module-graph': ['tests.test_hia_core_module_graph_native'],
        'workspace': ['tests.test_hia_core_workspace_json_native', 'tests.test_hia_core_workspace_json_cli', 'tests.test_hia_core_workspace_pipeline'],
        'capability': ['tests.test_hia_capability_renaming_native'],
        'workspace-facts': ['tests.test_hia_core_workspace_facts_native', 'tests.test_hia_core_workspace_materialize_native'],
        'function-shape': ['tests.test_hia_function_shape_native'],
        'program-shape': ['tests.test_hia_program_shape_native'],
        'instruction-policy': ['tests.test_hia_instruction_policy_native'],
        'publication': ['tests.test_hia_artifact_publication_native', 'tests.test_hia_artifact_publication_route', 'tests.test_hia_agent_artifact_store_native'],
        'core-admission': ['tests.test_hia_core_admission_native'],
        'core-cli': ['tests.test_hia_core_admission_cli'],
        'patch': ['tests.test_hia_core_patch_native', 'tests.test_hia_core_patch_cli'],
    }
    for name, names in groups.items():
        ok = suite(name, names) and ok
    if a.full:
        ok = suite('full-retained-regression', discover=True) and ok
preserved = all((root / path).is_file() and sha256((root / path).read_bytes()).hexdigest() == digest
                for path, digest in sources.items())
result = {'schema': 'hepta.hia.native-rewrite-qualification.v1',
          'status': 'PASS' if ok and preserved else 'HOLD', 'source_manifest': sources,
          'source_preserved': preserved, 'steps': steps,
          'whole_native_delivery_qualified': False,
          'full_retained_regression_requested': a.full}
(out / 'QUALIFICATION.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': result['status'], 'steps': len(steps), 'source_preserved': preserved}), flush=True)
raise SystemExit(0 if result['status'] == 'PASS' else 1)
