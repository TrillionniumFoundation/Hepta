"""Real analysis followed by a late lock replacement; no loader mocks."""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
parser = argparse.ArgumentParser()
parser.add_argument('--checkout', required=True)
parser.add_argument('--baseline', action='store_true')
args = parser.parse_args()
sys.path.insert(0, str(Path(args.checkout).resolve()))
from hepta import packages, pipeline
from hepta.ast import HeptaError
if args.baseline:
    from experiments.frontend_cli.cli import evaluate
else:
    from experiments.frontend_lock_revalidation.cli import evaluate
from experiments.policy_failures.owner import Owner

for mutation in ('malformed', 'missing', 'stale'):
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        entry = root / 'main.hepta'
        entry.write_text('fn main()->Unit effects {} {}')
        (root / 'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(root)
        lock = root / 'Hepta.lock'
        real = pipeline.analyze
        def analyze(*args, **kwargs):
            result = real(*args, **kwargs)
            if mutation == 'malformed': lock.write_text('broken')
            elif mutation == 'missing': lock.unlink()
            else:
                value = json.loads(lock.read_text()); value['sha256'] = '0' * 64
                lock.write_text(json.dumps(value))
            return result
        with patch.object(pipeline, 'analyze', analyze):
            response, code = evaluate(['check', '--frontend-only', '--policy', 'loader-experimental-v1', str(entry), '--locked'])
        try:
            Owner().load(entry, locked=True)
        except HeptaError as error:
            fresh_code = error.diagnostic.code
        else:
            fresh_code = 'ACCEPTED'
        if args.baseline:
            assert code == 0 and response['ok'] and response['outcome'] == 'success'
            assert response['report']['project']['locked'] is True
        else:
            assert code == 1 and not response['ok'] and response['outcome'] == 'diagnostic'
            assert response['lock_revalidation'] == 'not_completed'
            assert response['atomic_snapshot'] is False
            assert response['diagnostics'][0]['code'] == fresh_code
        assert fresh_code == {'malformed': 'E_LOCK_INVALID', 'missing': 'E_LOCK_MISSING', 'stale': 'E_LOCK_STALE'}[mutation]
        print(json.dumps({'mutation': mutation, 'cli_exit': code, 'outcome': response['outcome'], 'ok': response['ok'], 'first_failure': response['first_failure'], 'fresh_locked_load': fresh_code}, sort_keys=True))
