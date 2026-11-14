"""Freeze Root's exact failed and successful work without duplicating fixed source trees."""
from pathlib import Path, PurePosixPath
import base64
import gzip
from hashlib import sha1, sha256
import io
import json
import os
import stat
import tarfile
import zlib

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def identity(raw):
    return dict(bytes=len(raw), sha256=sha256(raw).hexdigest(),
                git_blob=sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def put(name, raw):
    path = ROOT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        assert stream.write(raw) == len(raw)


def main():
    assert not (ROOT / 'ROOT-WORK.tar.gz').exists()
    r17 = WORK / 'v109-union-r17'
    base = json.loads((r17 / 'SOURCE-MANIFEST.json').read_bytes())
    current = json.loads((r17 / 'SOURCE-MANIFEST-R2.json').read_bytes())
    assert set(base) == set(current) and len(base) == 3152
    names = [name for name in base if base[name] != current[name]]
    assert set(names) == {'tests/test_hia_verified_report_source.py', 'tests/test_hia_linux_file_roundtrip_source.py'}
    delta = {}
    for name in names:
        old = (r17 / 'source' / name).read_bytes()
        new = (r17 / 'source-r2' / name).read_bytes()
        assert identity(old) == {k: base[name][k] for k in identity(old)}
        assert identity(new) == {k: current[name][k] for k in identity(new)}
        delta[name] = dict(before=dict(base[name], text=old.decode()), after=dict(current[name], text=new.decode()))
    overlay = encode(dict(schema='hia.r17.test-only-successor.exact-source-overlay.v1',
                          base_manifest=base, current_manifest=current, files=delta,
                          first_group_outcome='FAIL', successor_group_outcome='6_NEW_SOURCE_PASS',
                          qualification_not_inherited=True, whole_native=False))
    wrapper = encode(dict(schema='hia.lossless.zlib-json.v1', decoded=identity(overlay),
                          payload=base64.b64encode(zlib.compress(overlay, 1)).decode()))
    put('R17-R2-SOURCE-PACKET.zlib.json', wrapper)

    selected = {}

    def add(path):
        state = path.lstat()
        assert stat.S_ISREG(state.st_mode)
        name = path.relative_to(WORK).as_posix()
        assert name not in selected
        raw = path.read_bytes()
        selected[name] = dict(identity(raw), mode=stat.S_IMODE(state.st_mode),
                              git_mode='100755' if state.st_mode & 0o111 else '100644')

    for dirname, excluded in (
        ('v109-union-r17', {'source', 'source-r2', '__pycache__'}),
        ('v111-union-r18', {'source', '__pycache__'}),
        ('v108-source-protocol-unroll-r1', {'__pycache__'}),
    ):
        directory = WORK / dirname
        for parent, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in excluded)
            for leaf in sorted(files):
                path = Path(parent) / leaf
                if path.suffix not in ('.pyc', '.pyo'):
                    add(path)
    for name in ('v108-r16-formal-repair', 'v110-component-custody'):
        directory = WORK / 'v95-audit-mount-r1' / name
        for path in sorted(directory.iterdir()):
            if path.is_file():
                add(path)
    add(Path(__file__).resolve())
    add(ROOT / 'R17-R2-SOURCE-PACKET.zlib.json')
    manifest = dict(schema='hia.root.work-checkpoint.manifest.v1', files=selected,
                    logical_files=len(selected), logical_bytes=sum(r['bytes'] for r in selected.values()),
                    source_copy_exclusions={
                        'R16': 'Existing fixed Git source packet and full authoring transport mounted at V107',
                        'R17_r1': 'Full before/after source overlay retained inside this checkpoint',
                        'R17_r2': 'Two exact before/after tests plus both complete manifests retained',
                        'R18': 'Complete source overlay plus exact base/current manifests retained',
                    },
                    important_boundaries=[
                        'R16 first formal run failed before generation/tests; exact alias successor kept separately.',
                        'R16 successor full Source actual1357:1353PASS,3FAIL,1ERROR; original62 skipped.',
                        'R17 first new Source group failed; all10 new default generator commands passed.',
                        'R17 test-only successor six new Source passed; no full139 generation or Source1363 qualification.',
                        'R18 portable integration prepared with known fixed-resource profile conflict; no product execution.',
                        'Guard unroll prototype NOT_ADOPTED; no budget or freshness guarantee weakened.',
                        'Component source, raw custody, selected restores and whole qualification remain distinct.',
                    ], new_qualification=False, whole_native=False)
    manifest_raw = encode(manifest)
    put('MANIFEST.json', manifest_raw)
    archive_path = ROOT / 'ROOT-WORK.tar.gz'
    with archive_path.open('xb') as target:
        with gzip.GzipFile(filename='', fileobj=target, mode='wb', compresslevel=1, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, raw, mode in [('MANIFEST.json', manifest_raw, 0o644)] + [
                        (name, (WORK / name).read_bytes(), pin['mode']) for name, pin in selected.items()]:
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    info.mode = mode
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    archive.addfile(info, io.BytesIO(raw))
    seen = set()
    with gzip.open(archive_path, 'rb') as stream:
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for member in archive:
                assert member.name not in seen and member.isreg()
                seen.add(member.name)
                raw = archive.extractfile(member).read()
                if member.name == 'MANIFEST.json':
                    assert raw == manifest_raw and member.mode == 0o644
                else:
                    expected = selected[member.name]
                    assert identity(raw) == {k: expected[k] for k in identity(raw)}
                    assert member.mode == expected['mode']
                    path = WORK / member.name
                    assert path.read_bytes() == raw and stat.S_IMODE(path.stat().st_mode) == member.mode
        while True:
            tail = stream.read(1 << 20)
            if not tail:
                break
            assert not any(tail)
    assert seen == set(selected) | {'MANIFEST.json'}
    raw = archive_path.read_bytes()
    parts = []
    for number, offset in enumerate(range(0, len(raw), 393216)):
        payload = raw[offset:offset + 393216]
        path = f'parts/{number:03}.json'
        wrapped = encode(dict(schema='hia.root.work-checkpoint.archive-part.v1', number=number,
                              offset=offset, encoding='base64', decoded=identity(payload),
                              payload=base64.b64encode(payload).decode()))
        put(path, wrapped)
        parts.append(dict(identity(wrapped), path=path, mode='100644', offset=offset, decoded=identity(payload)))
    index = dict(schema='hia.root.work-checkpoint.transport.v1', archive=identity(raw),
                 manifest=identity(manifest_raw), parts=parts, source_manifests_and_overlay_complete=True,
                 logical_files=len(selected), logical_bytes=manifest['logical_bytes'],
                 archive_full_readback=True, all_original_paths_unchanged=True,
                 source_copies_are_reconstructed_from_fixed_base_and_full_overlays=True,
                 selected_component_custody_recipes_are_separate_leaves=True,
                 new_product_executions=0, whole_native=False)
    put('TRANSPORT.json', encode(index))
    entries = [dict(path='root-work-checkpoint/' + row['path'], local_path=str(ROOT / row['path']),
                    bytes=row['bytes'], git_blob=row['git_blob'], sha256=row['sha256'], mode='100644') for row in parts]
    for name in ('TRANSPORT.json', 'MANIFEST.json', 'capture_checkpoint.py', 'R17-R2-SOURCE-PACKET.zlib.json'):
        path = ROOT / name
        entries.append(dict(path='root-work-checkpoint/' + name, local_path=str(path), mode='100644', **identity(path.read_bytes())))
    put('PUBLICATION-INTENT.json', encode(dict(schema='hia.root.checkpoint-publication-intent.v1',
                                             entries=entries, source_mutations=0, ref_mutations=0)))
    print(json.dumps({k: index[k] for k in ('archive', 'logical_files', 'logical_bytes', 'archive_full_readback', 'whole_native')} |
                     dict(parts=len(parts), publication_objects=len(entries)), sort_keys=True))


if __name__ == '__main__':
    main()
