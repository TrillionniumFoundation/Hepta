"""Preserve closed historical19 originals and exact external fixtures named by the actual records."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

CONTROL = Path(__file__).resolve().parent
OLD = CONTROL / 'custody19-controls-r1'
PACKAGE = CONTROL / 'old19-actual-package-r1'
PREFIX = 'experiments/hia_native_source_merge_20261112/combined-v88-original19-actual-r1'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid]

validation = json.loads((OLD / 'VALIDATION.json').read_bytes())
if not (validation['status'] == 'ORIGINAL19_SOURCE_CONTROLS_PASS_NOT_PRODUCT_QUALIFICATION'
        and validation['expected_loaded_executed'] == 19 and validation['owner_natural_and_ECHILD_closed'] is True):
    raise ValueError('closed original19 pass required')
regular, typed = [], []
def collect(path, name):
    info = path.lstat()
    row = {'path': name, 'original_path': str(path), 'identity': identity(info), 'mode': stat.S_IMODE(info.st_mode)}
    if stat.S_ISLNK(info.st_mode):
        row.update(type='symlink', target=os.readlink(path), followed=False)
    elif stat.S_ISDIR(info.st_mode):
        row['type'] = 'directory'
        typed.append(row)
        for child in sorted(path.iterdir()):
            collect(child, name + '/' + child.name)
        return
    elif stat.S_ISREG(info.st_mode):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(path, flags)
        try:
            if identity(os.fstat(fd)) != row['identity']:
                raise ValueError('regular evidence descriptor changed')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read()
            if identity(os.fstat(fd)) != row['identity'] or identity(path.lstat()) != row['identity'] or len(raw) != info.st_size:
                raise ValueError('regular evidence changed while read')
        finally:
            os.close(fd)
        row.update(type='regular', bytes=len(raw), sha256=sha(raw))
        regular.append((path, row))
    elif stat.S_ISFIFO(info.st_mode):
        row.update(type='fifo', opened=False)
    else:
        raise ValueError('unexpected special object in retained controls')
    typed.append(row)

collect(OLD, 'custody19-controls-r1')
collect(CONTROL / 'pack_old19_actual.py', 'pack_old19_actual.py')
external = {}
for path, row in list(regular):
    if not path.is_relative_to(OLD / 'actual'):
        continue
    if path.name == 'RUN.json':
        value = json.loads(path.read_bytes())
        for fixture in value.get('fixtures', []):
            external.setdefault(fixture['path'], []).append({'record': str(path), 'fixture': fixture})
    elif path.name == 'replaced-root-locations.json':
        value = json.loads(path.read_bytes())
        for key in ['recorded', 'original_preserved']:
            external.setdefault(value[key], []).append({'record': str(path), 'field': key,
                'explicitly_preserved_synthetic_replacement': key == 'recorded'})
for index, (value, origins) in enumerate(sorted(external.items())):
    path = Path(value)
    if path.parent != Path('/tmp') or not path.name.startswith(('publication-retained-', 'publication-custody-original-fs-')):
        raise ValueError('actual fixture path outside declared original prefixes')
    collect(path, 'external-fixture-%03d' % index)
PACKAGE.mkdir(mode=0o700)
archive = PACKAGE / 'original19-complete-originals.tar.gz'
with archive.open('xb') as stream:
    with gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for path, row in regular:
                raw = path.read_bytes()
                if identity(path.lstat()) != row['identity'] or len(raw) != row['bytes'] or sha(raw) != row['sha256']:
                    raise ValueError('actual original changed during custody')
                item = tarfile.TarInfo(row['path'])
                item.size, item.mode = len(raw), row['mode']
                item.uid = item.gid = item.mtime = 0
                tar.addfile(item, io.BytesIO(raw))
restored = []
with tarfile.open(archive, 'r:gz') as tar:
    for item in tar:
        if not item.isfile():
            raise ValueError('archive unexpectedly contains active links or FIFO')
        raw = tar.extractfile(item).read()
        restored.append((item.name, len(raw), sha(raw), item.mode))
if restored != [(row['path'], row['bytes'], row['sha256'], row['mode']) for _, row in regular]:
    raise ValueError('full actual19 archive readback differs')
raw = archive.read_bytes()
files, parts = [], []
for index, offset in enumerate(range(0, len(raw), 393216)):
    chunk = raw[offset:offset + 393216]
    text = base64.b64encode(chunk).decode() + '\n'
    name = 'archive/part-%04d.b64' % index
    files.append({'path': PREFIX + '/' + name, 'text': text})
    parts.append({'path': name, 'bytes': len(text), 'sha256': sha(text.encode()),
                  'decoded_bytes': len(chunk), 'decoded_offset': offset, 'decoded_sha256': sha(chunk)})
manifest = {'schema': 'hia.v88.original19-complete-custody.v1',
            'status': 'ORIGINAL19_SOURCE_CONTROLS_PASS', 'validation': validation,
            'regular_files': len(regular), 'regular_bytes': sum(r['bytes'] for _, r in regular),
            'typed_objects': len(typed), 'typed_inventory': typed,
            'external_fixtures_from_actual_records': external,
            'source_symlink_followed': False, 'fifo_or_symlink_opened': False,
            'hardlinked_regular_paths_retained_as_separate_full_bytes': True,
            'archive_bytes': len(raw), 'archive_sha256': sha(raw), 'parts': parts,
            'full_archive_restore_verified': True,
            'synthetic_expected_HOLD_or_UNKNOWN_records_reclassified': False,
            'original39_or_native_or_matching_cold_or_installed_executed': False}
manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
(PACKAGE / 'MANIFEST.json').write_text(manifest_text)
files.append({'path': PREFIX + '/MANIFEST.json', 'text': manifest_text})
for name, path in [('VALIDATION.json', OLD / 'VALIDATION.json'), ('REPORT.json', OLD / 'actual/REPORT.json'),
                   ('pack_old19_actual.py', CONTROL / 'pack_old19_actual.py')]:
    files.append({'path': PREFIX + '/' + name, 'text': path.read_text()})
body = (json.dumps({'files': files, 'manifest': manifest}, ensure_ascii=True, separators=(',', ':')) + '\n').encode()
(PACKAGE / 'BUNDLE.json').write_bytes(body)
summary = {'path': str(PACKAGE / 'BUNDLE.json'), 'bytes': len(body), 'sha256': sha(body),
           'git_files': len(files), 'regular_files': len(regular), 'regular_bytes': manifest['regular_bytes'],
           'typed_objects': len(typed), 'external_roots': len(external),
           'archive_bytes': len(raw), 'archive_sha256': sha(raw), 'full_restore_verified': True}
(PACKAGE / 'SUMMARY.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
