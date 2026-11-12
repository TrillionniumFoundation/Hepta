"""Stream all outer ZIP bodies and every selected typed original, without extraction.

Only small control, request, receipt and diagnostic originals are saved. Source,
package, wheel and toolchain payloads are hashed in bounded chunks, never unpacked.
The original full32 failure and its explicit two custody gaps remain failures.
"""
from pathlib import Path, PurePosixPath
from collections import Counter
import gzip
import hashlib
import json
import os
import stat
import tarfile
import time
import traceback
import zipfile

ROOT = Path('/workspace/scratch/e26ed3e2edcf/core-full32-failed-parts-recovery-r1')
ORIGINAL = Path('/tmp/hia-full32-failed-original-recovery-r1-20261112-e26e/artifact-13974465966.original.zip')
SIZE = 818594350
SHA = '9da285831263db03d5e24e26e427f867763f39d1d607ccf34f21ef519163785d'
TAR = 'hia-v87-full-public/full-retained-originals.tar.gz'
CAT = 'hia-v87-full-public/ORIGINAL-CATALOG.json'
MANIFEST = '.FULL-RETAINED-TYPED-MANIFEST.json'
checks = 0


def require(value, label):
    global checks
    if not value:
        raise AssertionError(label)
    checks += 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o400)


class DigestReader:
    def __init__(self, source):
        self.source = source
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        block = self.source.read(size)
        self.count += len(block)
        self.digest.update(block)
        return block


def stream_digest(stream, maximum, selected=None):
    digest = hashlib.sha256()
    size = 0
    capture = bytearray() if selected else None
    while block := stream.read(1 << 20):
        size += len(block)
        if size > maximum:
            raise AssertionError('stream exceeds frozen declared size')
        digest.update(block)
        if capture is not None:
            capture.extend(block)
    require(size == maximum, 'stream complete size')
    return size, digest.hexdigest(), bytes(capture) if capture is not None else None


def wanted(name, row):
    return row['kind'] == 'regular' and row['bytes'] <= 4 << 20 and (
        name == 'RUN-INTENT.json' or name == 'supply/SUPPLY.json' or
        name.startswith(('control/', 'checkpoints/', 'preparation-logs/', 'guard/',
                         'supply/logs/', 'supply/requests/', 'supply/reports/')))


def main():
    started = time.monotonic_ns()
    recover = json.loads((ROOT / 'RECONSTRUCTION-AUDIT.json').read_bytes())
    require(recover['status'] == 'COMPLETE_ORIGINAL_FAILED_ZIP_RECONSTRUCTED_AND_BOUND' and
            recover['original_bytes'] == SIZE and recover['original_sha256'] == SHA and
            recover['bound_owner_900_cleanup3_natural0_ECHILD'] is True,
            'independently closed exact receiver/reconstruction prerequisite')
    fd = os.open(ORIGINAL, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    outer = []
    member_inventory = []
    selected = []
    with os.fdopen(fd, 'rb') as file:
        before = identity(os.fstat(file.fileno()))
        require(before == recover['original_local_identity'] and before[6] == SIZE,
                'exact reconstructed input identity')
        require(hashlib.file_digest(file, 'sha256').hexdigest() == SHA,
                'complete official original ZIP raw SHA at audit entry')
        file.seek(0)
        with zipfile.ZipFile(file) as archive:
            infos = archive.infolist()
            require(len(infos) == 48 and len({x.filename for x in infos}) == 48,
                    'exact 48 unique original outer entries')
            small = {}
            for item in infos:
                require(not item.filename.startswith('/') and
                        '..' not in PurePosixPath(item.filename).parts and not item.is_dir() and
                        not stat.S_ISLNK(item.external_attr >> 16), 'safe outer regular member')
                if item.filename == TAR:
                    continue
                keep = '/wheels/' not in item.filename
                if keep:
                    require(item.file_size <= 4 << 20, 'bounded outer diagnostic original')
                with archive.open(item) as body:
                    n, digest, raw = stream_digest(body, item.file_size, selected=keep)
                outer.append({'path': item.filename, 'bytes': n, 'sha256': digest,
                              'crc32': '%08x' % item.CRC, 'saved_as_small_original': keep})
                if keep:
                    small[item.filename] = raw
                    save(ROOT / 'original-outer' / item.filename, raw)
            catalog_raw = small[CAT]
            catalog = json.loads(catalog_raw)
            custody = json.loads(small['hia-v87-full-public/CUSTODY.json'])
            final = json.loads(small['hia-v87-full-public/FINAL.json'])
            rows = catalog['originals']
            require(len(rows) == custody['original_members'] == 4798 and
                    len({x['path'] for x in rows}) == 4798, 'complete original catalog unique count')
            require(custody['catalog']['bytes'] == len(catalog_raw) and
                    custody['catalog']['sha256'] == sha(catalog_raw), 'full catalog raw custody pin')
            require(custody['status'] == 'PARTIAL_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN' and
                    custody['all_regular_bytes_read_back'] is False and
                    custody['all_selected_regular_bytes_read_back'] is True and
                    custody['full_namespace_observed'] is False and
                    custody['permissions_or_ownership_changed'] is False and
                    custody['product_execution_performed'] is False and
                    final['status'] == 'HOLD' and final['complete_custody'] is False and
                    final['whole_native_delivery_qualified'] is False,
                    'original HOLD and incomplete namespace retained explicitly')
            unread = [x for x in rows if 'read_error' in x]
            unlisted = [x for x in rows if 'traversal_error' in x]
            require([x['path'] for x in unread] == custody['unreadable_regular_paths'] ==
                    final['unreadable_regular_paths'] == ['supply/apt-cache/lock'] and
                    [x['path'] for x in unlisted] == custody['unlisted_directory_paths'] ==
                    final['unlisted_directory_paths'] == ['supply/apt-cache/partial'],
                    'two exact observed custody gaps, no invented bodies')
            for row in unread + unlisted:
                error = row.get('read_error', row.get('traversal_error'))
                require(error['type'] == 'PermissionError' and error['errno'] in [1, 13],
                        'actual denied custody entry metadata')
            expected = {x['path']: x for x in rows if x['path'] != '.' and
                        x['kind'] != 'special' and 'read_error' not in x}
            require(len(expected) + 1 == custody['archive_members'] == 4797,
                    'exact archived selected population plus manifest')
            info = archive.getinfo(TAR)
            require(info.file_size == custody['archive']['bytes'] == 785234691,
                    'exact inner archive directory size')
            seen = set()
            total_regular = 0
            with archive.open(info) as compressed:
                counted = DigestReader(compressed)
                with gzip.GzipFile(fileobj=counted, mode='rb') as decoded:
                    with tarfile.open(fileobj=decoded, mode='r|') as tar:
                        for member in tar:
                            name = member.name
                            require(name not in seen and not name.startswith('/') and
                                    '..' not in PurePosixPath(name).parts, 'unique safe typed member')
                            seen.add(name)
                            if name == MANIFEST:
                                require(member.isfile() and member.size == len(catalog_raw) and
                                        tar.extractfile(member).read() == catalog_raw,
                                        'entire embedded catalog raw equals outer catalog')
                                member_inventory.append({'path': name, 'kind': 'catalog',
                                                         'bytes': len(catalog_raw), 'sha256': sha(catalog_raw)})
                                continue
                            require(name in expected, 'typed member was actually selected')
                            row = expected[name]
                            old = row['identity']
                            require(member.mode == stat.S_IMODE(old[2]) and member.uid == old[3] and
                                    member.gid == old[4] and member.mtime == old[7] // 10**9,
                                    'typed original mode/uid/gid/whole-second mtime preserved')
                            out = {'path': name, 'kind': row['kind'], 'mode': member.mode,
                                   'uid': member.uid, 'gid': member.gid, 'mtime': member.mtime}
                            if row['kind'] == 'regular':
                                require(member.isfile() and member.size == row['bytes'],
                                        'actual regular typed member size/type')
                                stream = tar.extractfile(member)
                                size, digest, captured = stream_digest(stream, row['bytes'], selected=wanted(name, row))
                                require(digest == row['sha256'], 'complete typed original SHA')
                                out.update(bytes=size, sha256=digest)
                                total_regular += size
                                if captured is not None:
                                    save(ROOT / 'original-inner-selected' / name, captured)
                                    selected.append({'path': name, 'bytes': size, 'sha256': digest})
                                    if name == 'supply/SUPPLY.json':
                                        value = json.loads(captured)
                                        print(json.dumps({'observed_supply_status': value.get('status'),
                                            'errors': value.get('errors'), 'error': value.get('error'),
                                            'source': name, 'sha256': digest}, sort_keys=True), flush=True)
                                    if name == 'supply/logs/009-apt-install.stderr':
                                        print(json.dumps({'actual_009_stderr': captured.decode('utf-8', 'replace'),
                                                          'sha256': digest}), flush=True)
                            elif row['kind'] == 'directory':
                                require(member.isdir() and member.size == 0, 'actual typed directory')
                                if 'traversal_error' in row:
                                    out['children_not_observed'] = True
                            else:
                                raise AssertionError('unexpected original typed kind in this exact archive')
                            member_inventory.append(out)
                    # Consume the gzip trailer and the complete ZIP member, including padding.
                    tail = 0
                    while block := decoded.read(1 << 20):
                        tail += len(block)
                        require(not block.strip(b'\0'), 'only zero tar trailing padding')
                while counted.read(1 << 20):
                    pass
                require(counted.count == info.file_size and
                        counted.digest.hexdigest() == custody['archive']['sha256'],
                        'entire inner archive compressed bytes/SHA/ZIP CRC read')
                outer.append({'path': TAR, 'bytes': counted.count,
                              'sha256': counted.digest.hexdigest(), 'crc32': '%08x' % info.CRC,
                              'saved_as_small_original': False})
            require(seen == set(expected) | {MANIFEST} and len(seen) == 4797 and
                    total_regular == custody['regular_bytes'] == 863570811,
                    'all exact selected typed original members and regular bytes')
            require(len(outer) == 48 and sum(x['bytes'] for x in outer) == 818584840,
                    'all outer 48 bodies complete CRC/SHA, no bulk extraction')
        require(before == identity(os.fstat(file.fileno())) == identity(ORIGINAL.lstat()),
                'original artifact identity stable over full physical audit')
    save(ROOT / 'ORIGINAL-OUTER-INVENTORY.json', wire({'schema': 'hepta.complete-outer-zip-bodies.v1',
         'artifact_id': 13974465966, 'files': sorted(outer, key=lambda x: x['path'])}))
    save(ROOT / 'ORIGINAL-INNER-INVENTORY.json', wire({'schema': 'hepta.complete-selected-typed-original-bodies.v1',
         'archive_sha256': custody['archive']['sha256'], 'members': member_inventory,
         'unreadable_original_metadata': unread, 'unlisted_directory_metadata': unlisted}))
    report = {'schema': 'hepta.failed-full32-complete-physical-custody-readback.v1',
              'status': 'ALL_AVAILABLE_ORIGINAL_BODIES_VERIFIED_ORIGINAL_HOLD_PRESERVED',
              'original_artifact_id': 13974465966, 'original_run': 43283027193,
              'original_bytes': SIZE, 'original_sha256': SHA, 'original_path': str(ORIGINAL),
              'outer_members': len(outer), 'outer_expanded_bytes': sum(x['bytes'] for x in outer),
              'catalog_originals': len(rows), 'inner_archive_members': len(member_inventory),
              'inner_original_regular_bytes': total_regular,
              'inner_archive': custody['archive'], 'typed_kinds': dict(Counter(x['kind'] for x in rows)),
              'selected_small_originals': selected, 'checks': checks,
              'original_final_status': final['status'], 'original_complete_custody': False,
              'unreadable_regular_paths': custody['unreadable_regular_paths'],
              'unlisted_directory_paths': custody['unlisted_directory_paths'],
              'new_supplier_or_product_or_native_execution': False,
              'full_namespace_or_whole_qualification_claimed': False,
              'elapsed_ns': time.monotonic_ns() - started}
    save(ROOT / 'ORIGINAL-PHYSICAL-AUDIT.json', wire(report))
    print(json.dumps({k: report[k] for k in ['status', 'outer_members', 'outer_expanded_bytes',
          'inner_archive_members', 'inner_original_regular_bytes', 'checks', 'elapsed_ns']}, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        failure = {'status': 'HOLD', 'error_type': type(error).__name__, 'error': str(error),
                   'traceback': traceback.format_exc(), 'checks_completed': checks,
                   'partial_readback_preserved': True, 'product_executed': False}
        target = ROOT / 'ORIGINAL-PHYSICAL-r1-ERROR.json'
        if not target.exists():
            save(target, wire(failure))
        raise
