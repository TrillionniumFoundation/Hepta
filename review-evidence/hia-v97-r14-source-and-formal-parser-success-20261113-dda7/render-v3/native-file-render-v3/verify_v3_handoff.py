"""Independent byte/hash/tree readback of the frozen v3 handoff, no product calls."""
from pathlib import Path
import base64
import hashlib
import json
import zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'handoff-r1'
PRIOR = Path('/workspace/scratch/dda74a4fae35/v95-native-file-render-r2')


def meta(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def check(raw, expected):
    actual = meta(raw)
    assert all(actual[key] == expected[key] for key in actual)


def tree(items):
    groups = {}
    for path, value in items.items():
        components = path.split('/')
        node = groups
        for part in components[:-1]:
            node = node.setdefault(part, {})
        node[components[-1]] = (value['mode'], value['git_blob'])
    def pack(node):
        rows = []
        for name, value in node.items():
            is_tree = type(value) is dict
            mode, digest = ('40000', pack(value)) if is_tree else value
            rows.append(((name + ('/' if is_tree else '')).encode(),
                         mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)))
        body = b''.join(raw for _, raw in sorted(rows))
        return hashlib.sha1(b'tree ' + str(len(body)).encode() + b'\0' + body).hexdigest()
    return pack(groups)


def main():
    plan = json.loads((OUT / 'PUBLICATION-PLAN.json').read_bytes())
    for entry in plan['entries']:
        raw = (OUT / entry['path']).read_bytes()
        check(raw, entry)
        assert len(raw) <= 384 * 1024 and raw.decode().encode() == raw
    records = {}
    for label, index in plan['capsules'].items():
        raw = bytearray()
        for part in index['parts']:
            assert part['offset'] == len(raw)
            data = (OUT / part['path']).read_bytes()
            check(data, part)
            raw.extend(data)
        raw = bytes(raw)
        check(raw, index['complete'])
        wrapped = json.loads(raw)
        if label == 'manifest':
            records[label] = wrapped
        else:
            decoded = zlib.decompress(base64.b64decode(wrapped['payload'], validate=True))
            if 'decoded' in wrapped:
                check(decoded, wrapped['decoded'])
            else:
                assert len(decoded) == wrapped['decoded_bytes']
                assert hashlib.sha256(decoded).hexdigest() == wrapped['decoded_sha256']
            records[label] = json.loads(decoded)
    packet = records['source']
    assert packet['current_manifest'] == records['manifest']
    assert tree(packet['prior_manifest']) == packet['prior_tree'] == 'cee29d828985f1c43b39eb11d68d931b0f7001f7'
    assert tree(packet['current_manifest']) == packet['current_tree'] == plan['source_tree']
    assert len(packet['files']) == 11
    for path, value in packet['files'].items():
        after = value['text'].encode()
        before = value['before']['text'].encode()
        check(after, value)
        check(before, value['before'])
        assert after == (ROOT / 'source' / path).read_bytes()
        assert before == (PRIOR / 'source' / path).read_bytes()
        assert packet['current_manifest'][path] == {k: value[k] for k in ('bytes', 'sha256', 'git_blob', 'mode')}
    for path, value in records['evidence']['members'].items():
        raw = value['text'].encode()
        check(raw, value)
        assert raw == (ROOT / path).read_bytes()
    for path, value in records['first122']['files'].items():
        assert hashlib.sha256(value['before']['text'].encode()).hexdigest() == value['before']['sha256']
        assert hashlib.sha256(value['after']['text'].encode()).hexdigest() == value['after']['sha256']
    # The original seven assertions remain literally the old fixture, with
    # only its explicit new scope label and build-readback module adapted.
    original_vm = (PRIOR / 'authoring/run_semantic_vm.py').read_bytes()
    expected_vm = original_vm.replace(b"'hia.file-render-semantic-vm.v1'", b"'hia.file-render-semantic-vm.v3'")
    expected_vm = expected_vm.replace(b'from admit_semantic_build import admitted_actual_build',
                                       b'from admit_semantic_build_r2 import admitted_actual_build')
    actual_vm = (ROOT / 'authoring/run_semantic_vm_original7.py').read_bytes()
    assert expected_vm == actual_vm
    report = {'schema': 'hia.file-render-v3.independent-handoff-readback.v1', 'status': 'PASS',
        'prior_tree': packet['prior_tree'], 'current_tree': packet['current_tree'],
        'source_files': len(packet['current_manifest']), 'delta_paths': len(packet['files']),
        'all39_transport_leaves_size_SHA_Git_readback': True,
        'all_capsules_losslessly_decoded': True,
        'all11_before_after_texts_match_actual_frozen_sources': True,
        'small_originals': len(records['evidence']['members']),
        'original_VM7_assertions_byteexact_after_only_two_scope_adaptations': True,
        'actual_original7_result': '6PASS1FAIL, not inherited as PASS',
        'all_large_raw_Git_persisted': False, 'product_or_test_executions': 0}
    path = OUT / 'FINAL-READBACK.json'
    with path.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
