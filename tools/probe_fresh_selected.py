from pathlib import Path
import hashlib, json, os, subprocess, sys, time, traceback

from bounded_support import ROOT, SOURCE, snapshot
sys.path.insert(0, str(SOURCE))
label, manifest = sys.argv[1:3]
OUT = ROOT / 'evidence' / label
OUT.mkdir(exist_ok=False)

def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


before = snapshot()
save('SOURCE-BEFORE.json', before)
from tests import test_hia_agent_entry as original
guard = "import argparse\nfrom hepta import cli\ndef reject(*args,**kwargs):raise AssertionError('retained ordinary CLI/parser entered')\ncli._reference_hia_main=reject\nargparse.ArgumentParser=reject\n"
cases = [('lower', '/absent'), ('run', '/absent'),
         ('build', '/absent', '--backend', 'llvm', '-o', '/absent-output'),
         ('build', '/absent', '--kind', 'shared', '-o', '/absent-output'),
         ('verify', '/absent', '--rust-shadow-bin', '/absent')]
records = []
for index, args in enumerate(cases):
    environment = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_') and k != 'PYTHONPATH'}
    environment.update(PATH='', PYTHONDONTWRITEBYTECODE='1', HEPTA_HIA_CLI_MANIFEST=str(Path(manifest).resolve(strict=True)))
    argv = [sys.executable, '-B', '-c', guard + original.CHILD, json.dumps(args), 'agent']
    started = time.monotonic_ns()
    result = subprocess.run(argv, cwd=SOURCE, env=environment, capture_output=True, timeout=30)
    (OUT / f'{index:02d}.stdout').write_bytes(result.stdout)
    (OUT / f'{index:02d}.stderr').write_bytes(result.stderr)
    records.append({'argv': argv, 'returncode': result.returncode, 'wall_ns': time.monotonic_ns() - started,
                    'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                    'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
after = snapshot()
save('SOURCE-AFTER.json', after)
report = {'schema': 'hia-cli-fresh-selected-original-command-observations.v1',
          'scope': 'FORMAL_ACTUAL314_BOUNDED_DEVELOPMENT_NOT_COLD', 'python': sys.version,
          'records': records, 'source_unchanged': before == after,
          'status': 'PASS' if before == after and all(r['returncode'] == 2 for r in records) else 'FAIL'}
save('REPORT.json', report)
print(json.dumps({'status': report['status'], 'returncodes': [r['returncode'] for r in records], 'source_unchanged': before == after}))
raise SystemExit(0 if report['status'] == 'PASS' else 1)
