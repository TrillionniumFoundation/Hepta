"""Close already observed raw custody. No product execution or ref mutation."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'handoff'
KEYS = ('bytes', 'sha256', 'git_blob')


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def record(path, name=None):
    raw = path.read_bytes()
    return {'path': name or path.name, 'local_path': str(path), **identity(raw)}


def load(name):
    return json.loads((OUT / name).read_text())


def write(name, value):
    p = OUT / name
    assert not p.exists(), name
    p.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n')
    return record(p)


def check(entry, receipt):
    assert identity(Path(entry['local_path']).read_bytes()) == {k: entry[k] for k in KEYS}, entry['path']
    assert all(receipt[k] == entry[k] for k in ('path', *KEYS)), entry['path']
    assert receipt['create_ack']['sha'] == entry['git_blob'], entry['path']
    assert receipt['readback_complete'] is True and receipt['readback_equal'] is True, entry['path']


def base_entries():
    return load('SOURCE-UPLOAD-PLAN.json')['entries'] + load('RAW-UPLOAD-PLAN.json')['entries']


def prepare():
    source = load('SOURCE-UPLOAD-PLAN.json')['entries']
    raw = load('RAW-UPLOAD-PLAN.json')['entries']
    receipts = []
    for e in source:
        name = 'SOURCE-ACK.json' if e['path'] == 'SOURCE-PACKET.zlib.json' else 'ACK-' + e['path'].replace('/', '_') + '.json'
        r = load(name)
        check(e, r)
        receipts.append(r)
    for e in raw:
        r = load('remote-receipts/' + e['path'])
        check(e, r)
        receipts.append(r)
    assert len(receipts) == 144 and len({r['path'] for r in receipts}) == 144
    write('ACK-RECEIPTS.json', {
        'schema': 'hia.full-blob-custody-receipts.v1',
        'repository': 'TrillionniumFoundation/Hepta',
        'all_create_ack_and_full_readback': True, 'receipts': receipts,
        'raw_binary_tar_uploaded_as_blob': False,
        'raw_archive_recoverable_from_full_utf8_chunks': True,
        'refs_modified': False, 'matching_cold': False, 'whole': False,
    })
    entries = [record(OUT / name) for name in (
        'SOURCE-UPLOAD-PLAN.json', 'RAW-UPLOAD-PLAN.json', 'ACK-RECEIPTS.json',
        'SEAL-LOCAL.stdout', 'SEAL-LOCAL.stderr')]
    entries.append(record(Path(__file__), 'CUSTODY-FINALIZER.py'))
    return write('FINAL-METADATA-UPLOAD-PLAN.json', {
        'repository': 'TrillionniumFoundation/Hepta', 'entries': entries,
        'matching_cold': False, 'refs_modified': False,
    })


def index():
    original = base_entries()
    extra = load('FINAL-METADATA-UPLOAD-PLAN.json')['entries']
    for e in extra:
        check(e, load('metadata-receipts/' + e['path'] + '.json'))
    report = load('REPORT.json')
    plan = load('RAW-UPLOAD-PLAN.json')
    assert len(original + extra) == 150
    facts = []
    for r in report['real_results']:
        facts.append({k: v for k, v in r.items() if k != 'loaded_ids'})
    return write('INDEX.json', {
        'schema': 'hia.linux-stdio-current-cold.custody-index.v1',
        'status': report['status'],
        'base_tree': report['base_tree'], 'final_tree': report['final_tree'],
        'source_files': report['source_files'], 'changed_paths': report['changed_paths'],
        'source': original[0], 'report': original[1], 'registration_spec': original[2],
        'entries': original + extra,
        'complete_raw_originals_retained': True,
        'archive': plan['archive'], 'logical_files': plan['logical_files'],
        'logical_bytes': plan['logical_bytes'], 'unique_objects': plan['unique_objects'],
        'unique_bytes': plan['unique_bytes'], 'raw_parts': 136,
        'all_create_ack_and_full_readback': True,
        'facts': facts, 'preserved_failures': report['failure_custody'],
        'limitations': report['limitations'],
        'native_calls_this_revision': 0, 'cold_qualifier69_executed': False,
        'matching_cold': False, 'whole': False, 'refs_modified': False,
        'predecessor_recipes': ['2533da06411d2de6e95f74f5de0dcb9c615cbb71'],
    })


def recipe():
    index_entry = record(OUT / 'INDEX.json')
    check(index_entry, load('INDEX-ACK.json'))
    index_data = load('INDEX.json')
    entries = index_data['entries'] + [index_entry]
    assert len(entries) == 151 and len({e['path'] for e in entries}) == 151
    return write('AUDIT-TREE-ENTRIES.json', {
        'schema': 'hia.audit-tree-recipe.v1',
        'repository': 'TrillionniumFoundation/Hepta',
        'index': index_entry['git_blob'], 'source_packet': index_data['source']['git_blob'],
        'report': index_data['report']['git_blob'],
        'all_blobs_acknowledged_and_full_readback': True,
        'refs_modified': False, 'matching_cold': False, 'whole': False,
        'entries': [{'path': 'linux-stdio-current-cold-r1/' + e['path'],
                     'mode': '100644', 'type': 'blob', 'sha': e['git_blob']}
                    for e in entries],
        'predecessor_recipes': index_data['predecessor_recipes'],
    })


if __name__ == '__main__':
    action, = sys.argv[1:]
    print(json.dumps({'prepare': prepare, 'index': index, 'recipe': recipe}[action](), indent=2))
