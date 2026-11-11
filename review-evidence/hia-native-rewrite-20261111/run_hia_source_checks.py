"""Replay the frozen source workflow in a separate checkout, preserving evidence."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = a.source.resolve()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
copy = out / 'source'
subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks', str(root), str(copy)], check=True)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=copy, text=True).strip()
tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=copy, text=True).strip()
sys.path.insert(0, str(copy))
from workflow_process import run_workflow_step
workflow = (copy / '.github/workflows/hia-core.yml').read_text()
components = re.search(r'for component in ([^;]+); do', workflow).group(1).split()
blocks = re.findall(r'          names = \((.*?)\n          \)', workflow, re.S)
names = re.findall(r"'(tests\.[^']+)'", blocks[0])
env = dict(os.environ)
env['PYTHONDONTWRITEBYTECODE'] = '1'
env['PYTHONUNBUFFERED'] = '1'
code = '''import json,subprocess,sys,unittest
for name in COMPONENTS:
 print(json.dumps({'generator':name}),flush=True)
 subprocess.run([sys.executable,'-B','-m','tools.generate_hia_'+name],check=True)
for args in [['tools/check_hia_core_only.py'],['tools/generate_hia_selfhost_contract.py','--check'],['tests/test_hia_selfhost_language_coverage.py','--generate-inventory']]:
 subprocess.run([sys.executable,'-B',*args],check=True)
status=subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],text=True)
if status: raise RuntimeError('generated source changed: '+status)
r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NAMES))
value={'tests':r.testsRun,'failures':[{'test':str(t),'traceback':s} for t,s in r.failures],'errors':[{'test':str(t),'traceback':s} for t,s in r.errors],'skipped':[{'test':str(t),'reason':s} for t,s in r.skipped],'expected_failures':[str(t) for t,s in r.expectedFailures],'unexpected_successes':[str(t) for t in r.unexpectedSuccesses]}
open(RESULT,'w').write(json.dumps(value,indent=2)+'\\n')
raise SystemExit(0 if r.wasSuccessful() and not r.skipped and not r.expectedFailures else 1)
'''
code = 'COMPONENTS=' + repr(components) + '\nNAMES=' + repr(names) + '\nRESULT=' + repr(str(out / 'tests.json')) + '\n' + code
owner = run_workflow_step([sys.executable, '-B', '-c', code], cwd=copy, env=env,
                  stdout_path=out/'stdout.log', stderr_path=out/'stderr.log',
                  receipt_path=out/'owner.json', seconds=1800)
clean = subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=copy,text=True) == ''
passed = owner.get('status') == 'WORKFLOW_STEP_COMPLETED' and owner.get('returncode') == 0 and owner.get('timed_out') is False and owner.get('cleanup',{}).get('complete') is True and clean
result = {'schema':'hepta.hia.source-workflow-replay.v1','status':'PASS' if passed else 'HOLD','commit':head,'tree':tree,'generators':len(components),'source_preserved':clean,'owner':owner,'tests':json.loads((out/'tests.json').read_text()) if (out/'tests.json').exists() else None,'whole_native_delivery_qualified':False,'logs':{name:sha256((out/name).read_bytes()).hexdigest() for name in ['stdout.log','stderr.log']}}
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ['status','commit','generators','source_preserved']}))
raise SystemExit(0 if passed else 1)
