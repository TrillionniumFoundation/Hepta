"""Retain all root integration attempts and original Source buffers losslessly."""
from __future__ import annotations
import base64
import importlib.util
import json
import os
from pathlib import Path
import stat
import zlib

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
spec = importlib.util.spec_from_file_location('h', WORK / 'v94-union-r12/prepare_plan_r12.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(raw)
    path.chmod(0o644)


def main():
    r15 = WORK / 'v102-union-r15'
    r16 = WORK / 'v103-union-r16'
    baseline = json.loads((r15 / 'BASELINE-MANIFEST.json').read_bytes())
    current15 = json.loads((r15 / 'SOURCE-MANIFEST-R3.json').read_bytes())
    before = h.read_exact(WORK / 'v97-source-parser-r14-original/readback-r1/candidate-ci314', baseline)
    after15 = h.read_exact(r15 / 'source-r3', current15)
    current16 = json.loads((r16 / 'SOURCE-MANIFEST.json').read_bytes())
    h.read_exact(r16 / 'source', current16)
    changed15 = sorted(n for n in after15 if n not in before or after15[n] != before[n])
    assert len(changed15) == 14 and len(after15) == 3131
    terminal = json.loads((r15 / 'new-source-controls-r3/OUTER.json').read_bytes())
    assert terminal['status'] == 'PASS' and terminal['source_unchanged'] is True
    final15 = {'schema': 'hia.r15.final-three-source-controls-overlay.v1',
        'base_manifest': baseline, 'current_manifest': current15,
        'base_tree': h.tree_hash(baseline), 'source_tree': h.tree_hash(current15),
        'new_Source3_actual_terminal': terminal,
        'complete_Source1356_executed': False, 'all133_generators_twice_executed': False,
        'files': {n: {'before': None if n not in before else dict(h.identity(before[n]), text=before[n].decode()),
                      'after': dict(current15[n], text=after15[n].decode())} for n in changed15},
        'earlier_fixture_failures_preserved': True, 'matching_cold': False, 'whole_native': False}
    decoded = h.encode(final15)
    final15_raw = h.encode({'schema': 'hia.lossless.zlib-json.v1', 'decoded': h.identity(decoded),
        'payload': base64.b64encode(zlib.compress(decoded, 9)).decode()})
    put(ROOT / 'SOURCE-R15-R3.zlib.json', final15_raw)

    selected = {}
    def add(name, path):
        assert name not in selected and path.is_file() and not path.is_symlink()
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        selected[name] = (path, path.read_bytes())
    for label, folder in [('r15', r15), ('r16', r16)]:
        for path in sorted(folder.iterdir()):
            if path.is_file():
                add(label + '/' + path.name, path)
        for folder2 in sorted(folder.glob('new-source-controls-*')):
            for path in sorted(folder2.rglob('*')):
                if path.is_file():
                    add(label + '/' + path.relative_to(folder).as_posix(), path)
    for round_ in (1, 2, 3):
        folder = r15 / ('source' if round_ == 1 else 'source-r' + str(round_))
        add('r15/test-originals/r' + str(round_) + '.py', folder / 'tests/test_hia_core_representation_source.py')
    add('r15/SOURCE-R15-R3.zlib.json', ROOT / 'SOURCE-R15-R3.zlib.json')
    audit = WORK / 'v95-audit-mount-r1'
    for folder, pattern in [('v101-r14-formal', '**/*'), ('root', 'v101-*'),
                            ('trees', 'v101-*'), ('publication', 'v101-*')]:
        for path in sorted((audit / folder).glob(pattern)):
            if path.is_file():
                add('r14-publication/' + path.relative_to(audit).as_posix(), path)
    add('capture.py', Path(__file__))
    rows = {n: dict(h.identity(raw), content_base64=base64.b64encode(raw).decode())
            for n, (_, raw) in sorted(selected.items())}
    capsule = {'schema': 'hia.lossless-root-integration-originals.v1', 'files': rows,
        'all_R15_R1_R2_failures_preserved': True, 'R15_Source3_R3_status': 'PASS',
        'R16_status': 'PREPARED_NOT_GENERATED_NOT_TESTED', 'new_product_execution': 0, 'whole_native': False}
    logical = h.encode(capsule)
    packed = h.encode({'schema': 'hia.lossless.zlib-json.v1', 'decoded': h.identity(logical),
        'payload': base64.b64encode(zlib.compress(logical, 9)).decode()})
    put(ROOT / 'ORIGINALS.zlib.json', packed)
    decoded = zlib.decompress(base64.b64decode(json.loads(packed)['payload'], validate=True))
    assert decoded == logical
    restored = json.loads(decoded)
    assert set(restored['files']) == set(selected)
    for name, item in restored['files'].items():
        raw = base64.b64decode(item['content_base64'], validate=True)
        assert h.identity(raw) == {k: v for k, v in item.items() if k != 'content_base64'}
        assert raw == selected[name][1] == selected[name][0].read_bytes()
        target = ROOT / 'restored' / name
        put(target, raw)
        assert target.read_bytes() == raw and stat.S_IMODE(target.stat().st_mode) == 0o644
    proof = {'schema': 'hia.root-integration-lossless-readback.v1', 'status': 'PASS',
        'files': len(rows), 'logical_original_bytes': sum(v['bytes'] for v in rows.values()),
        'archive': h.identity(packed), 'decoded': h.identity(logical),
        'all_bytes_git_SHA256_and_modes_verified': True,
        'all_original_files_unchanged': True, 'new_product_execution': 0,
        'R15_final_source_tree': h.tree_hash(current15), 'R16_prepared_tree': h.tree_hash(current16),
        'R15_new_Source3_only': terminal, 'R16_tests_executed': 0,
        'matching_cold': False, 'whole_native': False}
    put(ROOT / 'READBACK.json', h.encode(proof))
    index = {'schema': 'hia.root-integration-archive-index.v1', 'files': {n: {k: v for k, v in r.items() if k != 'content_base64'} for n, r in rows.items()},
        'archive': h.identity(packed), 'readback': h.identity(h.encode(proof)), 'whole_native': False}
    put(ROOT / 'INDEX.json', h.encode(index))
    pins = []
    for name in ('ORIGINALS.zlib.json', 'READBACK.json', 'INDEX.json', 'SOURCE-R15-R3.zlib.json', 'capture.py'):
        path = ROOT / name
        pins.append(dict(h.identity(path.read_bytes()), path=name, local_path=str(path)))
    put(ROOT / 'PUBLICATION-INTENT.json', h.encode({'files': pins}))
    print(json.dumps({k: proof[k] for k in ('status', 'files', 'logical_original_bytes', 'archive', 'R15_final_source_tree', 'R16_prepared_tree', 'whole_native')}))


if __name__ == '__main__':
    main()
