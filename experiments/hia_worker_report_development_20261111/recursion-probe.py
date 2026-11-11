"""Preserve the known foreign extension recursion-resource mismatch verbatim."""
from pathlib import Path
from hashlib import sha256
import json
import sys
from tests.test_hia_worker_report_native import Fixture
from hepta.hia_worker_report_native import SOURCE

root = Path('/workspace/scratch/e26ed3e2edcf')
manifest = root / 'worker-report-development-r1/manifest.json'
source_before = sha256(SOURCE.read_bytes()).hexdigest()
results = []
for depth in (128, 500, 700, 749, 750, 900, 999, 1000):
    outcomes = []
    for native in (False, True):
        f = Fixture()
        left = right = 0
        for _ in range(depth):
            left, right = [left], [right]
        f.identities['extension'], f.after['extension'] = left, right
        result, output, errors, events = f.run(manifest if native else None)
        outcomes.append({'result': result, 'stdout_hex': output.hex(), 'stderr': errors, 'events': events})
    results.append({'depth': depth, 'same': outcomes[0] == outcomes[1], 'retained': outcomes[0], 'native': outcomes[1]})
source_after = sha256(SOURCE.read_bytes()).hexdigest()
record = {'schema': 'hia.worker-report-foreign-recursion-observation.v1',
          'status': 'KNOWN_UNCLOSED_EXTENSION_RESOURCE_MISMATCH', 'whole_worker_native': False,
          'scope': 'DEVELOPMENT_ONLY_NOT_ORDINARY_INSTALLATION_MANIFEST_SHAPE',
          'python': sys.version, 'executable': sys.executable, 'recursion_limit': sys.getrecursionlimit(),
          'source_before': source_before, 'source_after': source_after,
          'manifest_sha256': sha256(manifest.read_bytes()).hexdigest(),
          'policy_manifest': json.loads((manifest.parent / 'policy/manifest.json').read_bytes()), 'results': results}
(root / 'worker-report-recursion-r1-full-observations.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
assert source_before == source_after
print(json.dumps({'cases': len(results), 'mismatches': [r['depth'] for r in results if not r['same']],
                  'status': record['status']}))
