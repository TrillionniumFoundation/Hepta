"""Static exact-source recovery addendum. No source generation or imports."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import stat

HERE = Path(__file__).absolute().parent
AUTHORITY = Path('/tmp/hia-op13-execution-author-r1-dda7')


def pin(raw):
    return {'bytes': len(raw), 'mode': '100644',
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'sha256': hashlib.sha256(raw).hexdigest()}


def identity(s):
    return [s.st_dev, s.st_ino, s.st_nlink, s.st_mode, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns]


def read(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o644
    raw = path.read_bytes()
    assert identity(s) == identity(path.lstat())
    return raw, identity(s)


def main():
    packet_path = AUTHORITY / 'R20-PREPARED-PACKET.json'
    packet_raw, packet_stat = read(packet_path)
    assert pin(packet_raw) == {
        'bytes': 628381, 'mode': '100644',
        'git_blob': '5ad99d545a3902f84744f783c5d65a5990fb67a7',
        'sha256': '8f19c1bbed3bdd75830e8009ae275aa83a041571b067ab8d58dcd658da5cb6c1'}
    packet = json.loads(packet_raw)
    target = [row for row in packet['files'] if row['path'] == 'hepta/hia_checker_identity.py']
    assert len(target) == 1
    after = target[0]['after']
    assert set(after) == {'bytes', 'mode', 'git_blob', 'sha256', 'text'}
    captured = after['text'].encode('utf-8')
    assert pin(captured) == {key: value for key, value in after.items() if key != 'text'}
    source_path = AUTHORITY / 'recovered-source/hepta/hia_checker_identity.py'
    source_raw, source_stat = read(source_path)
    assert source_raw == captured
    assert pin(source_raw) == {
        'bytes': 345093, 'mode': '100644',
        'git_blob': '231701aa72ecb5a5109b0e7dc8094bb079682e5a',
        'sha256': 'a2d6b832a80421422f59b945eb6ddc8aea67854f9392a63329d61b6d76505b65'}
    route_raw = (HERE / 'CURRENT-PREDECESSOR-PLAN.json').read_bytes()
    assert pin(route_raw)['git_blob'] == '571039f75a9569e65d1463afdc991b6a7f671d14'
    report = {
        'schema': 'hepta.cli-inspect-r6.source-recovery-addendum.v1',
        'status': 'EXACT_CHECKER_SOURCE_BYTES_RECOVERED_STATIC_ONLY',
        'frozen_route_not_modified': pin(route_raw),
        'authority_packet': {'path': str(packet_path), 'pin': pin(packet_raw),
                             'observed_new_stat': packet_stat},
        'actual_complete_after_text_matches_local_source': True,
        'source': {'path': str(source_path), 'pin': pin(source_raw),
                   'observed_new_stat': source_stat},
        'boundary': [
            'The earlier route recorded this exact body as missing at its authoring time.',
            'The later complete original packet supplies the exact source bytes; no source text was guessed.',
            'This addendum does not claim old file or filesystem identity recovery.',
            'The complete current source views and runtime/materialization bindings still require review.',
            'The old 64615 historical-payload gate remains unchanged and blocked.',
            'No future generation, Source18, Native17, VM12, current raw custody or R6 result is supplied.',
        ],
        'prepared_packet_not_actual314_product_tree': True,
        'before_text_not_claimed': True,
        'project_imports': 0, 'source_generation': 0, 'products': 0, 'binders': 0, 'CI': 0,
        'script': pin(Path(__file__).read_bytes()),
    }
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    path = HERE / 'SOURCE-RECOVERY-ADDENDUM.json'
    with path.open('xb') as handle:
        assert handle.write(raw) == len(raw)
    path.chmod(0o644)
    assert path.read_bytes() == raw
    print(json.dumps({'status': report['status'], 'report': pin(raw), 'products': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
