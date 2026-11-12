"""Read every existing phase receipt/stdout pair; no project import or execution."""
import hashlib
import io
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / 'full-zip-two-parts-r1/actual-local-readback-r1/artifact-13911977275.original.zip'
SEMANTIC = ROOT / 'semantic-readback-r2/SEMANTIC-READBACK.json'

def sha(value):
    return hashlib.sha256(value).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def difference(left, right):
    return {'extra_stdout_keys': sorted(set(left) - set(right)),
            'extra_receipt_keys': sorted(set(right) - set(left)),
            'different_shared_keys': sorted(k for k in set(left) & set(right)
                                          if canonical(left[k]) != canonical(right[k]))}

source = Path(__file__).read_bytes()
result = {'schema': 'hia.970-all-phase-stdout-receipt-observation.v1',
          'project_imported': False, 'product_execution': False,
          'reader_sha256': sha(source), 'phases': []}
semantic_raw = SEMANTIC.read_bytes()
assert sha(semantic_raw) == '591b896a21ab0be224240c91d0df518ea1cfe8faff65e65c8336ce55a5ae02cb'
with zipfile.ZipFile(ARCHIVE) as outer:
    for phase in json.loads(semantic_raw)['cold']['phases']:
        archive_name = phase['archive']['archive'].removeprefix('/home/runner/work/_temp/')
        raw = outer.read(archive_name)
        assert len(raw) == phase['archive']['packed_bytes'] and sha(raw) == phase['archive']['archive_sha256']
        observations = []
        checked = 0
        with zipfile.ZipFile(io.BytesIO(raw)) as stage:
            manifest_raw = stage.read('HIA_ARCHIVE_MANIFEST.json')
            assert sha(manifest_raw) == phase['archive']['manifest_sha256']
            manifest = json.loads(manifest_raw)
            def read(name):
                data = stage.read(name)
                assert len(data) == manifest['files'][name]['bytes'] and sha(data) == manifest['files'][name]['sha256']
                return data
            for name in sorted(stage.namelist()):
                if not name.endswith('.receipt.json'):
                    continue
                receipt_raw = read(name)
                receipt = json.loads(receipt_raw)
                if 'case' not in receipt or 'input_sha256' not in receipt:
                    continue
                stem = name[:-len('.receipt.json')]
                request_raw = read(stem + '.request.json')
                request = json.loads(request_raw)
                native = 'transport' in request
                if not native and receipt.get('status') != 'returned':
                    continue
                stdout_raw = read(stem + '.stdout.log')
                stdout = json.loads(stdout_raw)
                additions = {'produced_image', 'produced_bytes', 'produced_sha256'}
                if not native:
                    additions |= {'case', 'input_sha256', 'input_bytes', 'artifact_sha256',
                                  'format', 'runner_sha256', 'wall_elapsed_ns'}
                projected = {k: v for k, v in receipt.items() if k not in additions}
                checked += 1
                if canonical(stdout) == canonical(projected):
                    continue
                extra = difference(stdout, projected)
                after_shared = {k: v for k, v in projected.items() if k != 'shared_output_observation'}
                observations.append({'receipt': name, 'case': receipt['case'],
                    'format': request['format'], 'transport': request.get('transport'),
                    'receipt_sha256': sha(receipt_raw), 'request_sha256': sha(request_raw),
                    'stdout_sha256': sha(stdout_raw), **extra,
                    'equal_after_removing_host_shared_output_observation':
                        canonical(stdout) == canonical(after_shared),
                    'shared_output_observation': projected.get('shared_output_observation')})
        result['phases'].append({'family': phase['family'], 'compiler_label': phase['compiler_label'],
            'archive_sha256': sha(raw), 'checked_original_stdout_pairs': checked,
            'differences': observations})
assert Path(__file__).read_bytes() == source and SEMANTIC.read_bytes() == semantic_raw
destination = ROOT / 'all-phase-stdout-difference-r1.original.json'
data = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
with destination.open('xb') as output:
    output.write(data)
    output.flush()
    import os
    os.fsync(output.fileno())
rows = [row for phase in result['phases'] for row in phase['differences']]
print(json.dumps({'phases': len(result['phases']),
    'pairs': sum(p['checked_original_stdout_pairs'] for p in result['phases']),
    'differences': len(rows),
    'unexplained_after_host_shared_output_projection':
        [row for row in rows if not row['equal_after_removing_host_shared_output_observation']],
    'bytes': len(data), 'sha256': sha(data)}))
