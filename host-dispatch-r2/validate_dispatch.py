from pathlib import Path
from hashlib import sha256
from copy import deepcopy
from unittest.mock import patch
import json
import os
import platform
import sys
import tempfile
import yaml

ROOT = Path(__file__).resolve().parent
before = {name: sha256((ROOT / name).read_bytes()).hexdigest()
          for name in ('original.yml', 'revised.yml', 'HOST-DISPATCH-R2.json')}
old = yaml.load((ROOT / 'original.yml').read_text(), Loader=yaml.BaseLoader)
new = yaml.load((ROOT / 'revised.yml').read_text(), Loader=yaml.BaseLoader)
expected = {'system': 'Linux', 'architecture': 'x86_64',
            'distribution': 'ubuntu', 'version_id': '24.04'}
assert old['jobs']['context-development']['runs-on'] == 'ubuntu-24.04'
assert new['jobs']['context-development']['runs-on'] == 'ubuntu-latest'
assert new['on']['push']['branches'] == ['codex/hia-context-development-v76-r2-20261112-dda7']
projected = deepcopy(new)
projected['name'] = old['name']
projected['on']['push']['branches'] = old['on']['push']['branches']
job = projected['jobs']['context-development']
job['runs-on'] = 'ubuntu-24.04'
guard = job['steps'].pop(0)
assert guard['name'] == 'Verify actual Linux Ubuntu 24.04 x86_64 runner'
assert guard['shell'] == 'bash'
original_path = old['jobs']['context-development']['steps'][-1]['with']['path']
assert job['steps'][-1]['with']['path'] == original_path + 'runner-platform.json\n'
job['steps'][-1]['with']['path'] = original_path
assert projected == old, 'a change outside the declared dispatch projection occurred'
script = guard['run']
assert script.startswith("set -euo pipefail\npython3 - <<'PY'\n") and script.endswith('\nPY\n')
python_source = script[len("set -euo pipefail\npython3 - <<'PY'\n"):-len('PY\n')]
code = compile(python_source, '<exact-workflow-host-guard>', 'exec')
observations = [{'name': 'complete workflow projection', 'status': 'PASS',
                 'unchanged_original_steps': len(job['steps'])}]
for field, replacement in [(None, None), ('system', 'Darwin'), ('architecture', 'aarch64'),
                           ('distribution', 'debian'), ('version_id', '22.04')]:
    actual = dict(expected)
    if field is not None:
        actual[field] = replacement
    with tempfile.TemporaryDirectory(prefix='hia-context-host-guard-') as tmp:
        old_cwd = Path.cwd()
        try:
            os.chdir(tmp)
            caught = None
            with patch.object(platform, 'system', return_value=actual['system']), \
                 patch.object(platform, 'machine', return_value=actual['architecture']), \
                 patch.object(platform, 'freedesktop_os_release', return_value={
                     'ID': actual['distribution'], 'VERSION_ID': actual['version_id']}):
                try:
                    exec(code, {'__name__': '__main__'})
                except RuntimeError as error:
                    caught = str(error)
            assert json.loads(Path('runner-platform.json').read_text()) == actual
            assert (caught is None) == (field is None), (field, caught)
            observations.append({'name': 'actual guard body with controlled ' + str(field),
                                 'status': 'PASS', 'observed': actual, 'refused': caught is not None})
        finally:
            os.chdir(old_cwd)
after = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in before}
assert after == before
report = {'schema': 'hia.context-ci.dispatch-static-controls.v1', 'status': 'PASS',
          'python': sys.version, 'tests': len(observations), 'observations': observations,
          'inputs_before': before, 'inputs_after': after,
          'controlled_guard_inputs_only': True, 'remote_platform_observed': False,
          'native_execution_performed': False, 'qualification_transferred': False}
(ROOT / 'STATIC-RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'status': 'PASS', 'tests': len(observations), 'original_steps_unchanged': len(job['steps'])}))
