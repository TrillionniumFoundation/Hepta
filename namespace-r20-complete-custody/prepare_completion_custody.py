"""Package the existing terminal ZIP and historical author records losslessly."""
from pathlib import Path
import base64
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parent


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def main():
    original_recipe = ROOT / 'prepared-r2/HANDOFF-RECIPE.json'
    original_raw = original_recipe.read_bytes()
    recipe = json.loads(original_raw)
    assert recipe['ids_are_locally_computed_not_remote_ack'] is True
    assert recipe['status'] == 'FROZEN_LOCALLY_NOT_PUBLISHED_NOT_EXECUTED'
    assert len(recipe['entries']) == 21
    for row in recipe['entries']:
        path = Path(row['path'])
        assert identity(path.read_bytes()) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
        assert stat.S_IMODE(path.stat().st_mode) == row['mode']
    original_zip = ROOT / 'actual/namespace-r20-expired-sections.zip'
    zip_raw = original_zip.read_bytes()
    pin = identity(zip_raw)
    assert pin == {'bytes': 2684449,
                   'sha256': '5e2d6406cb907d20f0f0b73229d42159bc01bd8199767ffc89da9313a269204c',
                   'git_blob': 'feaf4ae35985e6b408ea610d21722ec2cb9d7e68'}
    output = ROOT / 'complete-custody-r1'
    output.mkdir(exist_ok=False)
    chunks, restored = [], []
    for index, offset in enumerate(range(0, len(zip_raw), 384 * 1024)):
        raw = zip_raw[offset:offset + 384 * 1024]
        value = {'schema': 'hepta.exact-binary-span-utf8.v1', 'index': index,
                 'offset': offset, 'decoded': identity(raw),
                 'payload_base64': base64.b64encode(raw).decode('ascii')}
        text = encode(value)
        path = output / ('zip-part-%02d.json' % index)
        with path.open('xb') as stream:
            stream.write(text)
        decoded = base64.b64decode(json.loads(path.read_bytes())['payload_base64'], validate=True)
        assert decoded == raw
        restored.append(decoded)
        chunks.append({'path': str(path), **identity(text), 'mode': 0o644,
                       'index': index, 'offset': offset, 'decoded': identity(raw)})
    assert b''.join(restored) == zip_raw and identity(original_zip.read_bytes()) == pin
    selected = [
        'actual/ACTUAL-READBACK.json',
        'actual/raw/Hepta/Hepta/evidence/REPORT.json',
        'actual/raw/Hepta/Hepta/evidence/case-0/observations/REPORT.json',
        'actual/raw/Hepta/Hepta/evidence/case-0/observations/ORIGINAL-TEST.log',
        'actual/FULL-JOB.log',
        'actual/TRANSFER-INTENT.json', 'actual/TRANSFER.json',
        'actual/ZIP-CENTRAL.json', 'actual/ZIP-MEMBERS.json', 'actual/CUSTODY-READBACK.json',
        'actual/READBACK-R1-FAILURE.json', 'actual/READBACK-R2.stdout',
        'actual/READBACK-R2.stderr', 'actual/READBACK-R2-PROCESS.json',
        'download_exact.py', 'verify_artifact.py', 'summarize_actual.py',
        'analyze_repair_scope.py', 'analysis-r1/REPAIR-SCOPE.json',
        'prepare_completion_custody.py', 'prepared-r2/HANDOFF-RECIPE.json',
    ]
    leaves = []
    for row in recipe['entries']:
        leaves.append({**row, 'role': 'historical_author_leaf'})
    for name in selected:
        path = ROOT / name
        raw = path.read_bytes()
        raw.decode('utf-8', 'strict')
        leaves.append({'path': str(path), **identity(raw), 'mode': stat.S_IMODE(path.stat().st_mode),
                       'role': 'terminal_or_readback_record'})
    leaves.extend({**row, 'role': 'exact_original_zip_transport_span'} for row in chunks)
    harness = json.loads((ROOT / 'prepared-r2/HARNESS-MANIFEST.json').read_bytes())
    inherited = []
    for i, row in enumerate(harness):
        receipt = ROOT / 'publication-r1' / ('leaf-%02d-%s.VERIFIED.json' % (i, row['sha']))
        r = json.loads(receipt.read_bytes())
        assert r['pin'] == {'bytes': row['bytes'], 'sha256': row['sha256'], 'git_blob': row['sha']}
        assert r['status'] == 'FULL_REMOTE_BYTES_EQUAL_FROZEN_HARNESS'
        inherited.append({'path': row['path'], 'git_blob': row['sha'], 'bytes': row['bytes'],
                          'sha256': row['sha256'], 'mode': row['mode'],
                          'existing_full_get_receipt': str(receipt),
                          'receipt_identity': identity(receipt.read_bytes())})
    assert len(inherited) == 16
    result = {'schema': 'hepta.namespace-terminal-complete-custody-plan.v1',
              'status': 'LOCAL_PACKAGE_EXACT_REMOTE_COMPLETION_PENDING',
              'historical_author_recipe': {'path': str(original_recipe), **identity(original_raw)},
              'historical_recipe_bytes_unchanged': original_recipe.read_bytes() == original_raw,
              'original_zip': {'path': str(original_zip), **pin,
                               'mode': stat.S_IMODE(original_zip.stat().st_mode)},
              'zip_transport': chunks, 'leaves_to_reuse_or_publish': leaves,
              'harness_16_already_full_get': inherited,
              'product_runs': 0, 'refs_changed': False,
              'restoration': 'Strict-base64 decode each JSON payload, verify decoded pins, concatenate by offset, verify complete original ZIP identity, then use the preserved safe ZIP verifier. No original directory modes are invented.'}
    raw = encode(result)
    with (output / 'PLAN.json').open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'plan': str(output / 'PLAN.json'), **identity(raw),
                      'leaves': len(leaves), 'zip_parts': len(chunks),
                      'inherited_harness': len(inherited), 'product_runs': 0}))


if __name__ == '__main__':
    main()
