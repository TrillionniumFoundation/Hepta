"""Separate original caller processes with the original workflow supervisor."""
from pathlib import Path
import importlib.util
import json
import os
import sys

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
OUT = ROOT / 'caller-matrix-r1'
OUT.mkdir(exist_ok=False)
spec = importlib.util.spec_from_file_location('original_workflow_process', SOURCE / 'review-evidence/hia-native-rewrite-20261111/workflow_process.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
results = []
for profile, group in (('core', 'program-composite'), ('core', 'assembly'),
                       ('assembly', 'assembly'), ('both', 'all'), ('default', 'all')):
    label = profile + '-' + group
    command = [sys.executable, '-B', str(ROOT / 'run_split_callers_r1.py'),
               '--profile', profile, '--group', group, '--output', str(OUT / label)]
    receipt = module.run_workflow_step(command, cwd=SOURCE,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
        stdout_path=OUT / (label + '.stdout.log'),
        stderr_path=OUT / (label + '.stderr.log'),
        receipt_path=OUT / (label + '.supervisor.json'), seconds=1800)
    report = OUT / label / 'REPORT.json'
    observed = json.loads(report.read_bytes()) if report.exists() else None
    results.append({'profile': profile, 'group': group, 'supervisor': receipt,
                    'report': str(report), 'observed_status': observed and observed['status'],
                    'tests_run': observed and observed['tests_run']})
    print(json.dumps({key: results[-1][key] for key in ('profile', 'group', 'observed_status', 'tests_run')}), flush=True)
passed = all(x['supervisor']['status'] == 'WORKFLOW_STEP_COMPLETED' and x['observed_status'] == 'PASS' for x in results)
(OUT / 'RESULT.json').write_text(json.dumps({'schema': 'hia.front.original-caller-matrix.v81.r1',
    'status': 'PASS' if passed else 'FAIL', 'scope': 'DEVELOPMENT_ONLY',
    'old_thirteen_root_results_inherited': False, 'results': results}, sort_keys=True, indent=2) + '\n')
raise SystemExit(0 if passed else 1)
