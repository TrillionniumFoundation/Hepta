"""One original 180/3 owned source-only execution; all raw outcomes persist."""
from pathlib import Path
from hashlib import sha256
import importlib.util
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
policy = json.loads((ROOT / 'PREEXEC.json').read_bytes())
owner_path = ROOT / 'references/tools/hia_selfhost_process_owner.py'
expected = next(row for row in policy['frozen_files'] if row['path'] == str(owner_path.relative_to(ROOT)))
raw = owner_path.read_bytes()
assert (len(raw), sha256(raw).hexdigest()) == (expected['size'], expected['sha256'])
spec = importlib.util.spec_from_file_location('numeric_comparison_process_owner', owner_path)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
folder = ROOT / 'actual-source-controls-r1'
folder.mkdir(mode=0o700)
environment = {name: os.environ[name] for name in
               ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'TZ') if name in os.environ}
environment['PYTHONDONTWRITEBYTECODE'] = '1'
environment['PYTHONPYCACHEPREFIX'] = str(folder / 'unused-pycache')
command = [sys.executable, '-I', '-S', '-B', str(ROOT / 'controls/run_source_controls.py'),
           '--evidence', str(folder / 'evidence')]
receipt = owner.run_owned(command, cwd=str(ROOT), env=environment,
    stdout_path=folder / 'child.stdout.log', stderr_path=folder / 'child.stderr.log',
    receipt_path=folder / 'lifecycle.json', qualification_seconds=180, cleanup_seconds=3)
with (folder / 'wrapper.json').open('x') as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True); stream.write('\n')
print(json.dumps({'owner_status': receipt['status'], 'returncode': receipt.get('returncode'),
                  'cleanup': receipt.get('cleanup'), 'seconds': receipt.get('elapsed_seconds')}))
raise SystemExit(0 if receipt['status'] == 'OWNED_PROCESS_COMPLETED' else 1)
