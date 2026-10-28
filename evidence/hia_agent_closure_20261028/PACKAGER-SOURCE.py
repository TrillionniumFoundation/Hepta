#!/usr/bin/env python3
"""Package already-recorded HIA evidence; never compile or execute the project."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from urllib.parse import parse_qs, urlsplit
import zipfile

ROOT = Path(__file__).resolve().parent
DEST = ROOT / 'hepta-round4-evidence/evidence/hia_agent_closure_20261028'
SOURCE = 'fc5c155c47a7920519ed79a9953f8e415b0a7863'
CI_DIRS = (
    'round4-c-ci-c9f1915', 'round4-c-ci-fc5c155',
    'round4-cpp-ci-c9f1915', 'round4-cpp-ci-801cf02', 'round4-cpp-ci-fc5c155',
    'round4-verified-ci-c9f1915', 'round4-verified-ci-fc5c155',
    'round4-full-ci-c9f1915', 'round4-full-ci-fc5c155',
)
ROOT_OMIT = {
    'round4-evidence-README-draft.md', 'round4-build-evidence.py',
    'round4-evidence-selection.json', 'round4-evidence-build.log',
    'round4-evidence-publication.json', 'round4-evidence-publication-receipt.json',
    'round4-evidence-final-pr.md', 'round4-evidence-restore-verification.json',
    'round4-evidence-source-check.json', 'round4-evidence-direct-review.json',
}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def write(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def relative(path):
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    p = p.absolute()
    r = p.relative_to(ROOT).as_posix()
    if '..' in PurePosixPath(r).parts or '\\' in r:
        raise ValueError(f'unsafe path: {r}')
    return p, r


def signed_url_paths(paths):
    failures = []
    for p in paths:
        if p.suffix.lower() not in {'.json', '.log', '.py', '.sh', '.md', '.stdout', '.stderr', '.diff', '.txt'}:
            continue
        raw = p.read_bytes()
        if b'\0' in raw:
            continue
        for match in re.finditer(rb'https?://[^\s<>"\x27]+', raw):
            url = match.group().decode('utf-8', 'replace')
            try:
                query = {k.lower() for k in parse_qs(urlsplit(url).query)}
            except ValueError:
                continue
            if query & {'sig', 'signature', 'x-amz-signature', 'x-goog-signature', 'jwt', 'access_token'}:
                failures.append(p.relative_to(ROOT).as_posix())
                break
    return sorted(set(failures))


def select(allow_pending=False):
    selected = {}
    checked = []

    def add(path, group, expected=None):
        p, r = relative(path)
        if p.is_symlink() or not p.is_file():
            raise ValueError(f'not a retained regular file: {r}')
        row = selected.get(r)
        if row is None:
            row = {'path': r, 'bytes': p.stat().st_size, 'sha256': digest(p),
                   'mode': stat.S_IMODE(p.stat().st_mode) & 0o777, 'groups': []}
            selected[r] = row
        if group not in row['groups']:
            row['groups'].append(group)
        if expected:
            if row['bytes'] != expected['bytes'] or row['sha256'] != expected['sha256']:
                raise ValueError(f'frozen-file mismatch: {r}')
        return row

    def tree(path, group, skip_parts=()):
        base = ROOT / path
        if not base.is_dir():
            if allow_pending:
                return
            raise FileNotFoundError(base)
        for p in sorted(base.rglob('*')):
            rp = p.relative_to(base)
            if any(part in skip_parts for part in rp.parts):
                continue
            if p.is_file() or p.is_symlink():
                add(p, group)

    def frozen(name, base=''):
        p = ROOT / name
        if not p.exists() and allow_pending:
            return
        d = load(p)
        add(p, 'freeze-manifests')
        rows = d['files']
        if isinstance(rows, dict):
            rows = [dict(v, path=v.get('path', k)) for k, v in rows.items()]
        for row in rows:
            q = Path(row['path'])
            add(q if q.is_absolute() else Path(base) / q, name, row)
        checked.append({'path': name, 'listed_files_verified': len(rows)})

    for p in sorted(ROOT.glob('round4-*')):
        if p.is_file() and p.name not in ROOT_OMIT and not p.name.startswith('round4-evidence-'):
            add(p, 'root-history-and-readers')

    frozen('round4-resource-final-archive-FREEZE-fc5c155.json')
    frozen('round4-integrated-fc5c155-FREEZE.json')
    frozen('round4-integrated-c9f1915-FREEZE.json')
    frozen('round4-ndu-reuse-study-FREEZE.json', 'round4-ndu-reuse-study')
    for mode in ('adaptive', 'stateful', 'background'):
        frozen(f'round4-final-native-{mode}-fc5c155/FREEZE.json',
               f'round4-final-native-{mode}-fc5c155')

    for dirname in CI_DIRS:
        if dirname.startswith('round4-full-ci-'):
            # The explicit collector freeze excludes unrelated transfer
            # temporaries. Its superseded v1 manifest is retained as text only.
            frozen(dirname + '/FREEZE-v2.json', dirname)
        else:
            tree(dirname, 'original-ci-zips-and-collection-records', ('extracted',))
    for p in sorted(ROOT.glob('round4-cpp-host-*')):
        if p.is_dir():
            tree(p.name, 'cpp-author-qualifications')
    for dirname in ('round4-ndu-finite-build', 'round4-ndu-finite-build-attempt2',
                    'round4-ndu-recursive-build'):
        tree(dirname, 'native-bridge-builds')
    tree('round4-ndu-ranking-build', 'ranking-build-inputs', ('target',))
    add('round4-ndu-ranking-build/target/debug/hia-ndu-bridge', 'executed-ranking-bridge')
    for dirname in ('round4-initial-untracked-preserved', 'round4-migration-checkout-residue'):
        tree(dirname, 'preserved-checkout-state')
    for dirname in ('toolchains/qemu-round4', 'toolchains/gdb-round4'):
        for p in sorted((ROOT / dirname).glob('*.json')):
            add(p, 'tool-bootstrap-receipts')
        tree(dirname + '/logs', 'tool-bootstrap-raw-streams')
        tree(dirname + '/isa-smoke', 'original-tool-smoke-artifacts')
        signatures = load(ROOT / dirname / 'logs/signature-checks.json')
        for row in signatures['rows'] if isinstance(signatures, dict) else signatures:
            add(row['path'] if 'path' in row else row['argv'][-1],
                'original-signed-package-indices')
    for name in ('audit_collected_cpp.py', 'download_originals.py'):
        add('round4-ci-transfer-cpp/' + name, 'ci-collection-readers')

    whitelist = ROOT / 'round4-migration-archive-whitelist.json'
    if whitelist.exists():
        d = load(whitelist)
        rows = d.get('files', d.get('selected_files', []))
        if isinstance(rows, dict):
            rows = [dict(v, path=k) for k, v in rows.items()]
        for row in rows:
            add(row['path'], 'independent-migration-whitelist', row)

    problems = signed_url_paths([ROOT / p for p in selected])
    if problems:
        raise ValueError('signed URLs require exclusion: ' + ', '.join(problems))

    zips = []
    for r, row in sorted(selected.items()):
        p = Path(r)
        if p.suffix != '.zip' or p.parts[0] not in CI_DIRS:
            continue
        if p.name == 'original.zip':
            destination = p.parent / 'extracted'
        elif p.parent.name == 'archives':
            destination = p.parent.parent / 'extracted' / p.stem
        else:
            raise ValueError(f'unknown CI ZIP layout: {r}')
        members = []
        seen = set()
        with zipfile.ZipFile(ROOT / r) as z:
            for i in z.infolist():
                n = PurePosixPath(i.filename)
                if n.is_absolute() or '..' in n.parts or '\\' in i.filename or ':' in n.parts[0]:
                    raise ValueError(f'unsafe ZIP member in {r}')
                if i.is_dir():
                    continue
                if i.filename in seen or stat.S_ISLNK(i.external_attr >> 16):
                    raise ValueError(f'duplicate/symlink ZIP member in {r}')
                seen.add(i.filename)
                actual = ROOT / destination / i.filename
                if not actual.is_file() or actual.is_symlink():
                    raise ValueError(f'missing extracted original: {actual}')
                h = hashlib.sha256()
                size = 0
                with z.open(i) as f:
                    for b in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(b)
                        size += len(b)
                if size != i.file_size or size != actual.stat().st_size or h.hexdigest() != digest(actual):
                    raise ValueError(f'ZIP/extraction mismatch in {r}: {i.filename}')
                members.append({'path': i.filename, 'bytes': size, 'sha256': h.hexdigest(),
                                'mode': (i.external_attr >> 16) & 0o777})
        zips.append({'archive': r, 'destination': destination.as_posix(),
                     'members': members, 'member_count': len(members),
                     'member_bytes': sum(x['bytes'] for x in members)})

    files = sorted(selected.values(), key=lambda x: x['path'])
    return {
        'schema': 'hepta.hia-agent-closure.raw-index.v1', 'source_commit': SOURCE,
        'files': files, 'file_count': len(files), 'bytes': sum(x['bytes'] for x in files),
        'zip_expansions': zips, 'verified_freezes': checked,
        'archive_scope': 'Original observations, binaries, complete original CI ZIPs, collectors and independent readers. Local build caches and SDK payloads are omitted; cache members uploaded inside original CI ZIPs remain intact.',
        'ci_extracted_trees': 'Omitted only because all original ZIP bytes are retained; listed expansions reconstruct and hash-check every extracted file.',
        'signed_url_scan': {'passed': True, 'matching_paths': []},
        'excluded': ['Unreferenced local Cargo/rust-target caches (original CI ZIP members remain intact)', 'local toolchain SDK payloads and package archives',
                     'temporary signed-download URL request files', 'duplicate CI extracted trees'],
    }


def pack(index):
    DEST.mkdir(parents=True, exist_ok=True)
    output = DEST / 'raw-evidence.tar.xz'
    retained = ROOT / 'round4-evidence-raw.tar.xz'
    outputs = (output, retained, DEST / 'RAW-INDEX.json', DEST / 'ARCHIVE.json')
    if any(p.exists() or p.is_symlink() for p in outputs) or list(DEST.glob('raw-evidence.tar.xz.part-*')):
        raise FileExistsError('refusing to overwrite existing archive/index/manifest output')
    write(DEST / 'RAW-INDEX.json', index)
    # A wide dictionary preserves shared Rust debug information across retained
    # original binaries. Deterministic metadata does not modify file payloads.
    with lzma.open(output, 'wb', format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64,
                   filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6, 'dict_size': 512 * 1024 * 1024}]) as xz:
        with tarfile.open(fileobj=xz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for row in index['files']:
                p = ROOT / row['path']
                if p.stat().st_size != row['bytes'] or digest(p) != row['sha256']:
                    raise ValueError('changed after selection: ' + row['path'])
                t = tarfile.TarInfo(row['path'])
                t.size, t.mode, t.mtime = row['bytes'], row['mode'], 0
                t.uid = t.gid = 0
                t.uname = t.gname = ''
                with p.open('rb') as f:
                    tar.addfile(t, f)
    parts = []
    with output.open('rb') as f:
        for number in range(10000):
            raw = f.read(6 * 1024 * 1024)
            if not raw:
                break
            part = DEST / f'raw-evidence.tar.xz.part-{number:04d}'
            part.write_bytes(raw)
            parts.append({'path': part.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    archive = {'schema': 'hepta.hia-agent-closure.archive.v1', 'source_commit': SOURCE,
               'format': 'tar.xz', 'bytes': output.stat().st_size, 'sha256': digest(output),
               'part_size': 6 * 1024 * 1024, 'parts': parts,
               'index': {'path': 'RAW-INDEX.json', 'bytes': (DEST / 'RAW-INDEX.json').stat().st_size,
                         'sha256': digest(DEST / 'RAW-INDEX.json')},
               'compression': 'LZMA2 preset 6, 512 MiB dictionary, XZ CRC64',
               'file_count': index['file_count'], 'uncompressed_file_bytes': index['bytes']}
    write(DEST / 'ARCHIVE.json', archive)
    # The unsplit local file is a temporary packaging product, not a second
    # repository artifact. Retain it outside the evidence prefix for review.
    os.link(output, retained)
    output.unlink()
    print(json.dumps({k: v for k, v in archive.items() if k != 'parts'}, sort_keys=True), flush=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--select-only', action='store_true')
    ap.add_argument('--allow-pending', action='store_true')
    args = ap.parse_args()
    selected = select(args.allow_pending)
    if args.select_only:
        write(ROOT / 'round4-evidence-selection.json', selected)
        print(json.dumps({'file_count': selected['file_count'], 'bytes': selected['bytes'],
                          'ci_zip_count': len(selected['zip_expansions'])}), flush=True)
    else:
        if args.allow_pending:
            raise ValueError('--allow-pending is permitted only for selection previews')
        pack(selected)
