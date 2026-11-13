from pathlib import Path
import base64
import hashlib
import json
import zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'handoff-r3'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def checked(raw, record):
    actual = identity(raw)
    assert all(record[key] == value for key, value in actual.items()), (actual, record)
    return actual


def tree(flat):
    root = {}
    for path, item in flat.items():
        cursor = root
        parts = path.split('/')
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        assert parts[-1] not in cursor
        cursor[parts[-1]] = (item['mode'], item['git_blob'])
    def visit(node):
        body = b''
        for name, item in sorted(node.items(), key=lambda kv: (kv[0] + ('/' if isinstance(kv[1], dict) else '')).encode()):
            mode, digest = ('40000', visit(item)) if isinstance(item, dict) else item
            body += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
        return hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    return visit(root)


def decode(name):
    wrapper = json.loads((OUT / name).read_bytes())
    compressed = base64.b64decode(wrapper['payload'], validate=True)
    raw = zlib.decompress(compressed)
    checked(raw, wrapper['decoded'])
    return json.loads(raw)


def main():
    plan = json.loads((OUT / 'PUBLICATION-PLAN.json').read_bytes())
    receipts = []
    for item in plan['entries']:
        checked((OUT / item['path']).read_bytes(), item)
        receipt = json.loads((OUT / ('ACK-' + item['path'])).read_bytes())
        assert receipt['create_sha'] == item['git_blob'] and receipt['full_GET_bytes_equal'] is True
        receipts.append(receipt)
    source = decode('SOURCE-PACKET.zlib.json')
    for label in ('base', 'prior', 'current'):
        assert tree(source[label + '_manifest']) == source[label + '_tree']
    for name, item in source['files'].items():
        checked(item['text'].encode(), item)
        assert (ROOT / 'source' / name).read_bytes() == item['text'].encode()
        for before in ('before', 'v1_before'):
            if item[before] is not None:
                checked(item[before]['text'].encode(), item[before])
    original = decode('MINIMUM-ORIGINAL-EVIDENCE.zlib.json')
    assert len(original['members']) == original['count'] == 1159
    for item in original['members'].values():
        checked(item['text'].encode(), item)
    checked(original['external_retained_VM_template']['text'].encode(), original['external_retained_VM_template'])
    first = decode('KERNEL-R1-SOURCE-CHECKPOINT.zlib.json')
    assert tree(first['base_manifest']) == first['base_tree']
    assert tree(first['source_manifest']) == first['source_tree']
    for item in first['files'].values():
        checked(item['text'].encode(), item)
        if item['before'] is not None:
            checked(item['before']['text'].encode(), item['before'])
    report = {'schema': 'hia.file-render-v2.full-handoff-readback.v1', 'status': 'PASS',
              'source_tree': source['current_tree'], 'source_files': len(source['current_manifest']),
              'source_delta': len(source['files']), 'small_originals': len(original['members']),
              'earlier_49_source_tree': first['source_tree'],
              'all_publication_leaves_full_GET': True, 'all_capsules_fully_decoded': True,
              'all_text_members_bytes_sha256_git_and_source_preimages_checked': True,
              'five_full_manifest_trees_independently_computed': True,
              'no_product_execution': True, 'all_large_raw_Git_persisted': False,
              'matching_current_cold': False, 'whole': False}
    for name, value in [('FINAL-READBACK.json', report), ('GIT-RECEIPTS.json', receipts)]:
        raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
        with (OUT / name).open('xb') as stream:
            stream.write(raw)
        assert (OUT / name).read_bytes() == raw
        print(json.dumps({'path': name, **identity(raw)}))


if __name__ == '__main__':
    main()
