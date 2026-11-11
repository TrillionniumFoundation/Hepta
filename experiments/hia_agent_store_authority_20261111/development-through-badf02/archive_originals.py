from pathlib import Path
from hashlib import sha256
import io, json, os, stat, tarfile, time

root = Path('/tmp/hia-e26e-agent-store-authority-r1')
output = Path(__file__).resolve().parent
archive = output / 'raw-development-originals.tar.xz'
if archive.exists(): raise FileExistsError(archive)

def digest_file(path):
    h = sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(1 << 20): h.update(chunk)
    return h.hexdigest()

def enumerate_path(path):
    info = path.lstat()
    row = {'path': path.relative_to(root).as_posix(), 'mode': stat.S_IMODE(info.st_mode),
           'uid': info.st_uid, 'gid': info.st_gid, 'mtime_ns': info.st_mtime_ns}
    if stat.S_ISDIR(info.st_mode):
        row.update(type='directory', size=0)
        yield row
        for child in sorted(path.iterdir()): yield from enumerate_path(child)
    elif stat.S_ISREG(info.st_mode):
        row.update(type='file', size=info.st_size, sha256=digest_file(path)); yield row
    elif stat.S_ISLNK(info.st_mode):
        row.update(type='symlink', size=0, target=os.readlink(path)); yield row
    else: raise ValueError('unarchived special file: ' + str(path))

started = time.monotonic()
rows = [row for child in sorted(root.iterdir()) if child.name not in {'source', 'venv'}
        for row in enumerate_path(child)]
names = [row['path'] for row in rows]
assert len(names) == len(set(names))
inventory = {'schema': 'hia.agent-store-authority-original-evidence-inventory.v1',
    'scope': 'DEVELOPMENT_ONLY_ALL_PRIOR_FAILURES_AND_NEW_FINITE_SUCCESSES',
    'original_root': str(root),
    'source_commit': 'badf02d42a5d563540e9ea2e5d0b2490fcf724bd',
    'source_tree': '2b9adaa05e2cf8af6cff0ed333557afcd26539d8',
    'excluded': {
        'source': 'Current partial checkout is represented by canonical Git sources, complete declared SHA maps and frozen-source-r5 delta bytes.',
        'venv': 'Reproducible private dependency installation; original pip report/stdout/stderr and live interpreter/Z3 library identities are included.'},
    'entries': rows}
raw_inventory = (json.dumps(inventory, indent=2, sort_keys=True) + '\n').encode()
(output / 'originals-manifest.json').write_bytes(raw_inventory)
with tarfile.open(archive, mode='w:xz', format=tarfile.PAX_FORMAT, preset=3) as tar:
    for row in rows:
        path = root / row['path']
        info = tarfile.TarInfo(row['path'])
        info.mode, info.uid, info.gid = row['mode'], row['uid'], row['gid']
        seconds, nanos = divmod(row['mtime_ns'], 1_000_000_000)
        info.mtime = seconds; info.pax_headers = {'mtime': f'{seconds}.{nanos:09d}'}
        if row['type'] == 'directory':
            info.type = tarfile.DIRTYPE; tar.addfile(info)
        elif row['type'] == 'symlink':
            info.type = tarfile.SYMTYPE; info.linkname = row['target']; tar.addfile(info)
        else:
            info.type = tarfile.REGTYPE; info.size = row['size']
            with path.open('rb') as handle: tar.addfile(info, handle)
            if digest_file(path) != row['sha256']: raise ValueError('input changed: ' + row['path'])
    info = tarfile.TarInfo('ORIGINALS_MANIFEST.json'); info.mode = 0o600; info.size = len(raw_inventory)
    tar.addfile(info, io.BytesIO(raw_inventory))

by_name = {row['path']: row for row in rows}
verified = []
with tarfile.open(archive, mode='r:xz') as tar:
    members = tar.getmembers()
    if len(members) != len(rows) + 1 or len({m.name for m in members}) != len(members):
        raise ValueError('archive membership differs')
    for member in members:
        if member.name == 'ORIGINALS_MANIFEST.json':
            assert tar.extractfile(member).read() == raw_inventory
            continue
        row = by_name[member.name]
        assert (member.mode, member.uid, member.gid, member.size) == (row['mode'], row['uid'], row['gid'], row['size'])
        if row['type'] == 'file':
            assert member.isfile()
            h = sha256()
            with tar.extractfile(member) as handle:
                while chunk := handle.read(1 << 20): h.update(chunk)
            assert h.hexdigest() == row['sha256']
        elif row['type'] == 'directory': assert member.isdir()
        else: assert member.issym() and member.linkname == row['target']
        verified.append(member.name)
assert set(verified) == set(by_name)
parts_dir = output / 'parts'; parts_dir.mkdir(mode=0o700)
parts = []
with archive.open('rb') as handle:
    while chunk := handle.read(524286):
        name = f'raw-development-originals.tar.xz.part-{len(parts):03d}'
        (parts_dir / name).write_bytes(chunk)
        parts.append({'path': 'parts/' + name, 'size': len(chunk), 'sha256': sha256(chunk).hexdigest()})
combined = sha256()
for part in parts:
    raw = (output / part['path']).read_bytes()
    assert sha256(raw).hexdigest() == part['sha256']
    combined.update(raw)
archive_sha = digest_file(archive)
assert combined.hexdigest() == archive_sha
receipt = {'schema': 'hia.agent-store-authority-original-evidence-archive.v1', 'status': 'PASS',
    'archive': {'path': archive.name, 'size': archive.stat().st_size, 'sha256': archive_sha},
    'inventory': {'path': 'originals-manifest.json', 'size': len(raw_inventory), 'sha256': sha256(raw_inventory).hexdigest()},
    'original_entries': len(rows), 'original_regular_files': sum(row['type'] == 'file' for row in rows),
    'original_regular_bytes': sum(row['size'] for row in rows if row['type'] == 'file'),
    'archive_members': len(rows) + 1, 'all_original_bytes_modes_uid_gid_independently_read_back': True,
    'all_members_unique': True, 'parts': parts, 'parts_concatenation_matches_archive': True,
    'originals_deleted': False, 'wall_seconds': time.monotonic() - started}
(output / 'ARCHIVE.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
print(json.dumps({k:v for k,v in receipt.items() if k!='parts'}, indent=2, sort_keys=True))
