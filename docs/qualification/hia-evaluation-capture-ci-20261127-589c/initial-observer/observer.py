from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
OUT = Path('/tmp/runtime-evaluation-capture-ci-controls-589c')
BUILD = Path('/tmp/runtime-evaluation-capture-native-build-v2-589c')
OUT.mkdir(mode=0o700, exist_ok=False)
sys.path.insert(0, str(ROOT))

def pin(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

source_names = ('.github/workflows/hia-core.yml', 'tests/test_hia_evaluation_capture.py',
                'hepta/hia_agent_service.py', 'hepta/hia_evaluation_native.py',
                'tools/build_hia_evaluation.py', 'tools/build_hia_native_build_admission.py',
                'tools/build_hia_json_preflight.py')
before = {name: pin(ROOT / name) for name in source_names}
for role in ('evaluation', 'admission'):
    report = json.loads((BUILD / role / 'build.json').read_bytes())
    assert report['scope'] == 'DEVELOPMENT_COMPONENT'
    for name, expected in report['component_inputs'].items():
        assert pin(ROOT / name)['sha256'] == expected, (role, name)

from tests import test_hia_evaluation_capture as controls
clean = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
clean.pop('PYTHONPATH', None)
clean.pop('PYTHONHOME', None)
commands = []
def run(label, selector, environment):
    argv = [sys.executable, '-B', 'tools/run_hia_unittest_gate.py', selector]
    started = time.monotonic()
    with (OUT / (label + '.stdout')).open('wb') as stdout, (OUT / (label + '.stderr')).open('wb') as stderr:
        child = subprocess.run(argv, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr,
                               timeout=180, check=False)
    row = {'label': label, 'argv': argv, 'returncode': child.returncode,
           'elapsed_seconds': time.monotonic() - started,
           'stdout': pin(OUT / (label + '.stdout')), 'stderr': pin(OUT / (label + '.stderr'))}
    commands.append(row)
    assert child.returncode == 0, row

run('source-gate', 'tests.test_hia_evaluation_capture.CaptureSourceTests', clean)
development = dict(clean, **{
    controls.EVALUATION: str(BUILD / 'evaluation/manifest.json'),
    controls.ADMISSION: str(BUILD / 'admission/manifest.json'),
})
run('explicit-development-gate', 'tests.test_hia_evaluation_capture', development)

# A malformed negative fixture is deliberately not a qualification receipt.
# The actual existing admission must reject it before either builder or mkdir.
compiler = Path('/tmp/hia-runtime-589c-language-all-fixtures-20261127-v3/B1.image.bin')
nested = OUT / 'malformed-cold-nested.json'
nested.write_text(json.dumps({'generations': [{'produced_image': str(compiler)}]}) + '\n')
cold = OUT / 'malformed-cold.json'
cold.write_text(json.dumps({'schema': 'malformed-negative-control', 'nested_report': str(nested)}) + '\n')
from tools import build_hia_json_preflight as gate
negative = []
for label, environment in (
    ('empty-cold', {controls.COLD: '', controls.EVIDENCE: str(OUT / 'empty-output')}),
    ('mixed-domains', {controls.COLD: str(cold), controls.EVIDENCE: str(OUT / 'mixed-output'),
                      controls.EVALUATION: str(BUILD / 'evaluation/manifest.json')}),
    ('original-cold-admission', {controls.COLD: str(cold), controls.EVIDENCE: str(OUT / 'refused-output')}),
):
    with patch.dict(os.environ, {**clean, **environment}, clear=True), \
            patch.object(gate, 'admit_cold_build', wraps=gate.admit_cold_build) as admit, \
            patch('tools.build_hia_evaluation.build', side_effect=AssertionError('builder before admission')) as evaluation, \
            patch('tools.build_hia_native_build_admission.build', side_effect=AssertionError('builder before admission')) as admission:
        try:
            controls.EvaluationCaptureTests.setUpClass()
        except ValueError as error:
            negative.append({'label': label, 'exception': type(error).__name__, 'message': str(error),
                             'original_admission_calls': admit.call_count})
        else:
            raise AssertionError('malformed cold mode accepted: ' + label)
        evaluation.assert_not_called()
        admission.assert_not_called()
        assert not Path(environment[controls.EVIDENCE]).exists()
        assert admit.call_count == (1 if label == 'original-cold-admission' else 0)

try:
    gate.current_sources()
except ValueError as error:
    current_cold_domain = {'status': 'HOLD', 'exception': type(error).__name__, 'message': str(error),
                           'admission_not_changed': True}
else:
    raise AssertionError('expected current native-v2 source to remain outside the hosted-cold gate')

workflow = (ROOT / '.github/workflows/hia-core.yml').read_text()
assert "'tests.test_hia_evaluation_capture.CaptureSourceTests'," in workflow
assert 'HEPTA_HIA_EVALUATION_CAPTURE_COLD_REPORT: ${{ runner.temp }}/hia-cold.json' in workflow
assert 'HEPTA_HIA_EVALUATION_CAPTURE_EVIDENCE: ${{ runner.temp }}/hia-evaluation-capture' in workflow
assert 'run: python -B tools/run_hia_unittest_gate.py tests.test_hia_evaluation_capture\n' in workflow
assert 'HEPTA_HIA_EVALUATION_CAPTURE_DEVELOPMENT_MANIFEST' not in workflow
assert '${{ runner.temp }}/hia-evaluation-capture/' in workflow
assert "('hia-evaluation-capture', common_patterns)," in workflow
after = {name: pin(ROOT / name) for name in source_names}
assert before == after
record = {'schema': 'hepta.hia.evaluation-capture-ci-controls.v1',
          'scope': 'source and explicit development component; current cold admission remains HOLD',
          'source_before': before, 'source_after': after, 'source_unchanged': before == after,
          'commands': commands, 'negative_controls': negative, 'current_cold_domain': current_cold_domain,
          'native_manifests': {role: pin(BUILD / role / 'manifest.json') for role in ('evaluation', 'admission')},
          'actual_current_cold_gate_passed': False, 'installed_whole_release_qualified': False,
          'whole_stack_rewritten_in_hia': False}
(OUT / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps(record, sort_keys=True))
