"""New-source controls with the unchanged original process-group supervisor."""
from pathlib import Path
import importlib.util
import json
import os
import sys

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
OUT = ROOT / 'controls-r3'
OUT.mkdir(exist_ok=False)
spec = importlib.util.spec_from_file_location('original_workflow_process',
    SOURCE / 'review-evidence/hia-native-rewrite-20261111/workflow_process.py')
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)
build = json.loads((ROOT / 'native-build-r1/RESULT.json').read_bytes())
assembly = build['images']['assembly_front']
image = Path(assembly['manifest_path']).parent / assembly['manifest']['image_path']
steps = [
    ('default-import', [sys.executable, '-B', str(ROOT / 'probe_default_import_r3.py'),
        '--source', str(SOURCE), '--output', str(ROOT / 'default-import-r3')]),
    ('source-core-closure', [sys.executable, '-B', '-m', 'unittest', '-v',
        'tests.test_hia_checker_identity.CheckerDependencyIdentityTests.test_reviewed_inventory_covers_verifier_imports_and_explicit_selectors']),
    ('core-regeneration', [sys.executable, '-B', '-m', 'tools.generate_hia_core_verification', '--check']),
    ('assembly-regeneration', [sys.executable, '-B', '-m', 'tools.generate_hia_assembly_front', '--check']),
    ('callers', [sys.executable, '-B', str(ROOT / 'run_split_matrix_r1.py')]),
    ('capture', [sys.executable, '-B', str(ROOT / 'probe_split_capture_r2.py')]),
    ('transport', [sys.executable, '-B', str(ROOT / 'probe_split_transport_r4.py'),
        '--source', str(SOURCE), '--image', str(image), '--output', str(ROOT / 'transport-controls-r3')]),
    ('admission', [sys.executable, '-B', str(ROOT / 'probe_split_admission_r2.py')]),
]
results = []
for name, command in steps:
    receipt = supervisor.run_workflow_step(command, cwd=SOURCE,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
        stdout_path=OUT / (name + '.stdout.log'),
        stderr_path=OUT / (name + '.stderr.log'),
        receipt_path=OUT / (name + '.supervisor.json'), seconds=1800)
    results.append({'name': name, 'receipt': receipt})
    print(json.dumps({'name': name, 'status': receipt['status'],
                      'seconds': receipt['seconds']}), flush=True)
passed = all(row['receipt']['status'] == 'WORKFLOW_STEP_COMPLETED' for row in results)
(OUT / 'RESULT.json').write_text(json.dumps({'schema': 'hia.front.split.controls.v81.r3',
    'python': sys.version, 'status': 'PASS' if passed else 'FAIL', 'results': results,
    'scope': 'NEW_SOURCE_DEVELOPMENT_ONLY', 'old_results_inherited': False,
    'current_cold': False, 'whole_normalization': False}, sort_keys=True, indent=2) + '\n')
raise SystemExit(0 if passed else 1)
