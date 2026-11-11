"""Retain one exact official Actions ZIP under an unchanged external guardian.

Only input transport and streaming verification occur here. No package member
is extracted or executed. The signed transport URL is read from a private
request and is never printed into a public receipt or error message.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import time
import urllib.parse
import urllib.request
import zipfile


ROOT = Path('/home/qian-qi/he26v67-source-original-r1')
KEY = 'hia-e26e-desktop-v67-source-13870963554-original-ingress-r1'
PIN_SHA = 'ed40b484eeee3d87d376c72e6cec62a35d837dd89c8e2059f7a49d19f671e05c'
HOST = 'sdmntprwestcentralus.oaiusercontent.com'
ARCHIVE_NAME = 'hia-source-custody-608157e5-original.zip'
ARCHIVE_BYTES = 300074958
ARCHIVE_SHA = '837e8fecfa42012d0749ef7464a083e8a46743e49915ee0b99ebb6bf00df45c2'
CHECKED_TRANSFER_SECONDS = 720
SOCKET_TIMEOUT_SECONDS = 30


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save(report):
    # Replace only this operation's progress record, inside its new private
    # root. Every terminal and original input pathname remains create-only.
    pending = ROOT / 'ingress.next.json'
    create(pending, wire(report), 0o600)
    os.replace(pending, ROOT / 'ingress.json')
    sync_dir(ROOT)


def read_small(path, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= 1 << 20,
                'private small input is invalid')
        raw = stream.read((1 << 20) + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'small input changed')
    if expected is not None:
        require(sha256(raw).hexdigest() == expected, 'small input SHA differs')
    return raw


def stream_archive_hash(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    digest, count = sha256(), 0
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size == ARCHIVE_BYTES
                and stat.S_IMODE(before.st_mode) == 0o400,
                'retained original is not an independent owned read-only regular file')
        while True:
            part = stream.read(1 << 20)
            if not part:
                break
            count += len(part)
            require(count <= ARCHIVE_BYTES, 'retained ZIP grew')
            digest.update(part)
        require(identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'retained ZIP identity changed')
    require(count == ARCHIVE_BYTES and digest.hexdigest() == ARCHIVE_SHA, 'retained ZIP SHA differs')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
            'device': before.st_dev, 'inode': before.st_ino, 'mode': stat.S_IMODE(before.st_mode),
            'uid': before.st_uid, 'gid': before.st_gid, 'nlink': before.st_nlink,
            'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns,
            'actual_bytes_independently_read': count}


def inspect_members(path, pins):
    expected = {'package/' + name: value for name, value in pins['artifact']['package_files'].items()}
    expected.update(pins['artifact']['receipt_files'])
    require(len(expected) == 8, 'external eight-member inventory differs')
    observations = []
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(before.st_size == ARCHIVE_BYTES and before.st_nlink == 1, 'original ZIP stat differs')
        with zipfile.ZipFile(stream, 'r') as archive:
            seen = set()
            directories = []
            for info in archive.infolist():
                require(info.filename not in seen, 'duplicate ZIP member')
                seen.add(info.filename)
                require(not info.flag_bits & 1, 'encrypted ZIP member refused')
                mode = info.external_attr >> 16
                if info.is_dir():
                    require(info.filename == 'package/' and stat.S_ISDIR(mode), 'unexpected ZIP directory')
                    directories.append(info.filename)
                    continue
                require(info.filename in expected and stat.S_ISREG(mode)
                        and stat.S_IMODE(mode) == 0o644, 'ZIP member path/type/mode differs')
                target = expected[info.filename]
                require(info.file_size == target['bytes'], 'ZIP member size differs')
                digest, count = sha256(), 0
                with archive.open(info, 'r') as member:
                    while True:
                        part = member.read(1 << 20)
                        if not part:
                            break
                        count += len(part)
                        require(count <= target['bytes'], 'ZIP member expanded past its exact size')
                        digest.update(part)
                # ZipExtFile has consumed every byte and checked original CRC.
                require(count == target['bytes'] and digest.hexdigest() == target['sha256'],
                        'complete ZIP member digest differs')
                observations.append({'name': info.filename, 'bytes': count, 'sha256': digest.hexdigest(),
                                     'posix_mode': mode, 'crc32': info.CRC,
                                     'compressed_bytes': info.compress_size,
                                     'compression_type': info.compress_type,
                                     'actual_entire_member_read': True, 'crc_verified_by_zipfile': True})
            require({x['name'] for x in observations} == set(expected), 'ZIP member population differs')
        require(identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'ZIP changed during member verification')
    return {'members': observations, 'directories': directories,
            'regular_member_count': len(observations),
            'actual_member_bytes_read': sum(x['bytes'] for x in observations),
            'source_package_extracted': False, 'source_package_executed': False}


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise RuntimeError('official transport redirect refused')


def download(request, report):
    url = request['transport_url']
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname == HOST and parsed.port in (None, 443)
            and not parsed.username and not parsed.password and not parsed.fragment,
            'official transport endpoint differs')
    require(request['transport_host'] == HOST and sha256(url.encode()).hexdigest() == request['transport_url_sha256'],
            'private transport URL binding differs')
    output = ROOT / 'original' / ARCHIVE_NAME
    partial = output.with_name(output.name + '.partial')
    require(not os.path.lexists(output) and not os.path.lexists(partial), 'create-only original already exists')
    started = time.monotonic_ns()
    deadline = started + CHECKED_TRANSFER_SECONDS * 1_000_000_000
    report['get_attempt'] = {'attempt': 1, 'method': 'GET', 'transport_host': HOST,
                             'url_sha256': request['transport_url_sha256'], 'started_ns': started,
                             'socket_timeout_seconds': SOCKET_TIMEOUT_SECONDS,
                             'checked_transfer_seconds': CHECKED_TRANSFER_SECONDS}
    save(report)
    print(json.dumps({'stage': 'ORIGINAL_ARTIFACT_GET', 'artifact_id': 13870963554,
                      'expected_bytes': ARCHIVE_BYTES, 'http_attempt': 1}), flush=True)
    opener = urllib.request.build_opener(RefuseRedirects())
    http_request = urllib.request.Request(url, method='GET', headers={
        'User-Agent': 'HIA-official-source-original-ingress/1', 'Accept-Encoding': 'identity'})
    digest, received = sha256(), 0
    with opener.open(http_request, timeout=SOCKET_TIMEOUT_SECONDS) as response:
        require(response.status == 200 and response.geturl() == url, 'official response is not exact HTTP 200')
        encoding = response.headers.get('Content-Encoding')
        require(encoding is None or encoding.lower() == 'identity', 'encoded transport refused')
        declared_length = response.headers.get('Content-Length')
        require(declared_length is None or int(declared_length) == ARCHIVE_BYTES, 'HTTP Content-Length differs')
        report['http_response'] = {'status': response.status, 'content_length': declared_length,
                                   'content_encoding': encoding}
        fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'w+b') as stream:
            while True:
                require(time.monotonic_ns() < deadline, 'original transfer exceeded checked deadline')
                part = response.read1(min(1 << 20, ARCHIVE_BYTES + 1 - received))
                require(time.monotonic_ns() < deadline, 'original transfer exceeded checked deadline')
                if not part:
                    break
                received += len(part)
                require(received <= ARCHIVE_BYTES, 'HTTP payload exceeds exact original size')
                stream.write(part)
                digest.update(part)
            require(received == ARCHIVE_BYTES and digest.hexdigest() == ARCHIVE_SHA,
                    'original downloaded payload differs')
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
    # The new private directory prevents untrusted replacement; link is
    # create-only, and removal of the temporary name restores nlink==1.
    os.link(partial, output, follow_symlinks=False)
    os.unlink(partial)
    sync_dir(output.parent)
    report['download'] = {'bytes': received, 'sha256': digest.hexdigest(),
                          'elapsed_ns': time.monotonic_ns() - started,
                          'path': str(output), 'http_attempts': 1, 'redirects': 0, 'retries': 0}
    save(report)
    return output


def main():
    os.umask(0o077)
    started = time.monotonic_ns()
    report = {'schema': 'hia.v67.official-source-original-ingress.v1', 'status': 'INGRESS_HOLD',
              'stable_key': KEY, 'root': str(ROOT), 'artifact_id': 13870963554,
              'workflow_run_id': 43055736977, 'run_attempt': 1,
              'source_commit': '608157e52b0b94e0d294f6b99c4e809869f183aa',
              'source_tree': 'e7c29a60796a1a78946a2c667aa80df86529e532',
              'artifact_pins_sha256': PIN_SHA, 'maximum_get_attempts': 1,
              'source_materialization_requested': False, 'clone_requested': False,
              'prerequisite_preparation_requested': False, 'product_tests_requested': False,
              'whole_native_delivery_qualified': False,
              'natural_outer_guardian_acceptance_required': True}
    stage = 'INPUT_VALIDATION'
    try:
        pins = json.loads(read_small(ROOT / 'control/artifact-pins.json', PIN_SHA))
        request_raw = read_small(ROOT / 'control/request.private.json')
        request = json.loads(request_raw)
        require(request.get('schema') == 'hia.v67.official-source-original-private-request.v1'
                and request.get('stable_key') == KEY and request.get('artifact_pins_sha256') == PIN_SHA,
                'private ingress request differs')
        require(pins['artifact']['archive_bytes'] == ARCHIVE_BYTES
                and pins['artifact']['archive_sha256'] == ARCHIVE_SHA, 'original ZIP pins differ')
        report['private_request_sha256'] = sha256(request_raw).hexdigest()
        report['official_download_response_sha256'] = request['official_download_response_sha256']
        save(report)
        stage = 'GET'
        output = download(request, report)
        stage = 'FIRST_INDEPENDENT_ZIP_READ'
        report['zip_readback_before_members'] = stream_archive_hash(output)
        stage = 'ALL_EIGHT_MEMBERS'
        report['member_verification'] = inspect_members(output, pins)
        stage = 'SECOND_INDEPENDENT_ZIP_READ'
        report['zip_readback_after_members'] = stream_archive_hash(output)
        require(report['zip_readback_before_members'] == report['zip_readback_after_members'],
                'original ZIP changed across member verification')
        require(report['member_verification']['regular_member_count'] == 8
                and report['member_verification']['actual_member_bytes_read'] == 300073828,
                'member verification denominator differs')
        report.update(status='ORIGINAL_BYTES_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started)
        create(ROOT / 'ingress-terminal.json', wire(report))
        save(report)
        print(json.dumps({'status': report['status'], 'archive': str(output),
                          'bytes': ARCHIVE_BYTES, 'sha256': ARCHIVE_SHA,
                          'regular_members_fully_read': 8}), flush=True)
        return 0
    except BaseException as error:
        # Full URL-bearing exception representations must remain private; the
        # type, errno, HTTP code and failed phase preserve bounded diagnosis.
        report.update(status='INGRESS_HOLD', failed_stage=stage,
                      error_type=type(error).__name__, errno=getattr(error, 'errno', None),
                      http_status=getattr(error, 'code', None), elapsed_ns=time.monotonic_ns() - started)
        try:
            if not os.path.lexists(ROOT / 'ingress-terminal.json'):
                create(ROOT / 'ingress-terminal.json', wire(report))
            save(report)
        except BaseException:
            pass
        print(json.dumps({'status': 'INGRESS_HOLD', 'failed_stage': stage,
                          'error_type': type(error).__name__}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
