"""Fetch exactly two public canonical files into a new private staging root.

This is input transport only. It does not prepare source, run Git, run tests,
retry HTTP, or commit/abort the older unresolved binary-upload session.
"""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import time
import urllib.request

ROOT = Path('/home/qian-qi/he26v66devr2-ingress-r1')
INPUTS = ROOT / 'inputs'
BASE = ('https://raw.githubusercontent.com/TrillionniumFoundation/Hepta/'
        'fdb40f161907d0c4722ea14ca933945d33ec4990/'
        'experiments/hia_v66_desktop_development_20261111/source-package-r2/')
FILES = [
    {'name': 'e09-program-and-declared-source.tar.xz', 'size': 5829996,
     'sha256': 'f0f0a0fd570fa2d260d95f25193b1d9571d9614bbc7ab1c22607f23112ae5428',
     'git_blob_sha1': 'ff3ff3b9fe91d76952d2a4e84e0f33c5a09a1ede'},
    {'name': 'canonical-e09-development-package.json', 'size': 473051,
     'sha256': '7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af',
     'git_blob_sha1': 'c3faf7709057a6024decfc0aa2c0e001565511ba'},
]
os.umask(0o077)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def save(report):
    path = ROOT/'ingress.next.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(wire(report))
        f.flush()
        os.fsync(f.fileno())
    os.replace(path, ROOT/'ingress.json')
    sync_dir(ROOT)


def validate_data(raw, expected):
    require(len(raw) == expected['size'] and sha256(raw).hexdigest() == expected['sha256']
            and sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == expected['git_blob_sha1'],
            'canonical file bytes differ: '+expected['name'])


def readback(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400,
                'published staging file is not private and read-only')
        raw = f.read(expected['size']+1)
        after = os.fstat(f.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            'staging file changed while reading')
    bound = path.lstat()
    require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            == (bound.st_dev, bound.st_ino, bound.st_size, bound.st_mtime_ns, bound.st_ctime_ns),
            'staging file binding changed')
    validate_data(raw, expected)
    return {'path': str(path), **expected, 'mode': oct(before.st_mode),
            'uid': before.st_uid, 'nlink': before.st_nlink, 'readback_verified': True}


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise RuntimeError('public canonical source redirect refused')


def fetch_one(expected, report):
    url = BASE + expected['name']
    target = INPUTS / expected['name']
    partial = INPUTS / (expected['name']+'.partial')
    require(not os.path.lexists(target) and not os.path.lexists(partial), 'create-only input already exists')
    started = time.monotonic_ns()
    deadline = started + 240_000_000_000
    report['get_attempts'].append({'url': url, 'method': 'GET', 'started_ns': started,
                                   'socket_timeout_seconds': 30, 'checked_transfer_seconds': 240})
    save(report)
    print(json.dumps({'stage': 'CANONICAL_PUBLIC_GET', 'name': expected['name'],
                      'expected_bytes': expected['size']}), flush=True)
    opener = urllib.request.build_opener(RefuseRedirects())
    request = urllib.request.Request(url, method='GET',
                                    headers={'User-Agent': 'HIA-source-package-ingress/1',
                                             'Accept-Encoding': 'identity'})
    received = 0
    digest = sha256()
    git_digest = sha1(b'blob '+str(expected['size']).encode()+b'\0')
    # There is exactly one open() attempt for this fixed URL. The external
    # original guardian supplies the absolute ownership/deadline bound.
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url,
                'canonical source response is not exact HTTP 200')
        encoding = response.headers.get('Content-Encoding')
        require(encoding is None or encoding.lower() == 'identity', 'encoded source response refused')
        length = response.headers.get('Content-Length')
        require(length is None or int(length) == expected['size'], 'source Content-Length differs')
        fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'w+b') as f:
            while True:
                require(time.monotonic_ns() < deadline, 'source transfer exceeded checked deadline')
                data = response.read1(min(65536, expected['size'] + 1 - received))
                require(time.monotonic_ns() < deadline, 'source transfer exceeded checked deadline')
                if not data:
                    break
                received += len(data)
                require(received <= expected['size'], 'source response exceeds exact size')
                f.write(data)
                digest.update(data)
                git_digest.update(data)
            require(received == expected['size'] and digest.hexdigest() == expected['sha256']
                    and git_digest.hexdigest() == expected['git_blob_sha1'],
                    'downloaded canonical source identity differs')
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)
            validate_data(f.read(expected['size']+1), expected)
            os.fchmod(f.fileno(), 0o400)
            os.fsync(f.fileno())
    # link() is no-replace. Both names are in this new private same-filesystem
    # directory. Removing the temporary name restores the required nlink==1.
    os.link(partial, target, follow_symlinks=False)
    os.unlink(partial)
    sync_dir(INPUTS)
    facts = readback(target, expected)
    facts.update(http_status=200, final_url=url, elapsed_ns=time.monotonic_ns()-started)
    report['files'].append(facts)
    save(report)
    print(json.dumps({'stage': 'CANONICAL_FILE_VERIFIED', 'name': expected['name'],
                      'bytes': received, 'sha256': expected['sha256']}), flush=True)


def main():
    report = {'schema': 'hia.fixed-public-source-package-ingress.v1', 'status': 'INGRESS_HOLD',
              'root': str(ROOT), 'source_package_commit': 'fdb40f161907d0c4722ea14ca933945d33ec4990',
              'get_attempts': [], 'files': [], 'maximum_get_attempts': 2,
              'redirects_allowed': False, 'http_retries': 0,
              'source_preparation_started': False, 'git_or_product_tests_requested': False,
              'complete_git_object_closure': False, 'whole_native_delivery_qualified': False,
              'outer_guardian_acceptance_required': True,
              'older_upload': {'upload_id': 'hia-e26e-e09-devr2-source-package-r1',
                               'last_acknowledged_offset': 1179648,
                               'unresolved_chunk_offset': 1179648,
                               'commit_or_abort_requested': False, 'touched_by_this_program': False}}
    try:
        save(report)
        for expected in FILES:
            fetch_one(expected, report)
        report['final_readbacks'] = [readback(INPUTS/f['name'], f) for f in FILES]
        require(len(report['get_attempts']) == len(report['files']) == 2, 'ingress population differs')
        report['status'] = 'PUBLIC_SOURCE_INGRESS_READY_PENDING_OUTER_GUARDIAN'
        save(report)
        print(json.dumps({'status': report['status'], 'inputs': str(INPUTS)}), flush=True)
        return 0
    except BaseException as error:
        report.update(status='INGRESS_HOLD', error_type=type(error).__name__, error=str(error))
        try:
            save(report)
        except BaseException:
            pass
        raise


if __name__ == '__main__':
    raise SystemExit(main())
