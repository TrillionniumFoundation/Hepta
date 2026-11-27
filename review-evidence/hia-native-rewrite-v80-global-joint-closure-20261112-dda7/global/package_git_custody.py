"""Split the frozen complete evidence wrapper without altering its contents."""
from pathlib import Path
from hashlib import sha1, sha256
import base64
import json
import zlib

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'git-custody-r1'


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')) + '\n').encode()


def main():
    OUT.mkdir(exist_ok=False)
    original = (ROOT / 'COMPLETE-LOCAL-EVIDENCE.zlib.json').read_bytes()
    identities = json.loads((ROOT / 'CHECKPOINT-IDENTITIES.json').read_bytes())
    expected = next(p for p in identities['packets'] if p['path'] == 'COMPLETE-LOCAL-EVIDENCE.zlib.json')
    assert identity(original) == {k: expected[k] for k in ('bytes', 'sha256', 'blob')}
    wrapper = json.loads(original)
    compressed = base64.b64decode(wrapper['payload'], validate=True)
    assert identity(compressed) == wrapper['compressed']
    raw = zlib.decompress(compressed)
    assert identity(raw) == wrapper['raw']
    evidence = json.loads(raw)
    assert len(evidence['members']) == evidence['member_count'] == 142
    for name, member in evidence['members'].items():
        data = (member['content'].encode('utf-8') if member['encoding'] == 'utf-8'
                else base64.b64decode(member['content'], validate=True))
        assert identity(data) == {k: member[k] for k in ('bytes', 'sha256', 'blob')}, name
        assert member['mode'] in ('100644', '100755'), name
    parts, reconstructed = [], bytearray()
    for ordinal, start in enumerate(range(0, len(original), 300000), 1):
        fragment = original[start:start + 300000]
        part = {'schema': 'hia.global-import.original-evidence-fragment.v80.r2',
                'ordinal': ordinal, 'offset': start, 'original': identity(original),
                'fragment': identity(fragment), 'payload': base64.b64encode(fragment).decode('ascii')}
        packet = encoded(part)
        path = OUT / ('EVIDENCE-%03d.json' % ordinal)
        path.write_bytes(packet)
        recovered = base64.b64decode(json.loads(path.read_bytes())['payload'], validate=True)
        assert recovered == fragment
        reconstructed.extend(recovered)
        parts.append({'path': path.name, **identity(packet), 'offset': start,
                      'fragment': identity(fragment)})
    assert reconstructed == original
    members = {name: {k: member[k] for k in ('bytes', 'sha256', 'blob', 'mode', 'encoding')}
               for name, member in evidence['members'].items()}
    index = {'schema': 'hia.global-import.complete-local-custody.v80.r2',
             'status': 'PACKAGED_AWAITING_REMOTE_ACK', 'source': identities['packets'][0],
             'source_tree': identities['source_tree'], 'source_files': identities['source_files'],
             'original_evidence': expected, 'member_count': len(members), 'members': members,
             'parts': parts, 'added_tests_run': identities['added_tests_run'],
             'actual_native_returns': identities['actual_native_returns'],
             'current_source_cold': False, 'whole_native': False}
    packet = encoded(index)
    (OUT / 'INDEX.json').write_bytes(packet)
    print(json.dumps({'index': identity(packet), 'parts': len(parts),
                      'members': len(members), 'original_evidence': identity(original)}, sort_keys=True))


if __name__ == '__main__':
    main()
