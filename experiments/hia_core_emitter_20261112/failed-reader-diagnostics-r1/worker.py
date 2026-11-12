"""Inspect one exact failed reader artifact; frame only fixed small diagnostics."""
from __future__ import annotations

from hashlib import sha1, sha256
from contextlib import contextmanager
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import re
import zipfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = 'TrillionniumFoundation/Hepta'
TOKEN_VARIABLE = 'HIA_CUSTODY_GITHUB_TOKEN'
API_VERSION = '2026-03-10'
CHUNK = 1 << 20


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def blob(raw):
    return sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

class OriginalTooLarge(RuntimeError):
    def __init__(self, path, size):
        super().__init__('unbounded original: ' + str(path))
        self.size = size

@contextmanager
def parent_descriptor(path):
    """Keep a no-follow descriptor spine for the entire fixed path operation."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) > 1,
            'noncanonical absolute original path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def directory_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    def stable():
        for parent, name, child, wanted in links:
            require(directory_identity(os.fstat(child)) == wanted
                    and directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == wanted,
                    'original directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            observed = os.fstat(child)
            require(stat.S_ISDIR(observed.st_mode), 'original ancestor is not a directory')
            links.append((parent, name, child, directory_identity(observed)))
        stable()
        yield descriptors[-1], path.parts[-1]
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def inspect_file(path, maximum=1 << 30, *, system_binary=False, retain=False, reserve=None):
    path = Path(path)
    with parent_descriptor(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), 'nonregular original: ' + str(path))
        require(before.st_size >= 0, 'invalid original size')
        if before.st_size > maximum:
            raise OriginalTooLarge(path, before.st_size)
        if system_binary:
            require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                    and not stat.S_IMODE(before.st_mode) & 0o022, 'mutable runtime binary')
        else:
            require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                    'owned single-link original required: ' + str(path))
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        chunks, count = ([] if retain else None), 0
        digest = sha256()
        git_digest = sha1(b'blob ' + str(before.st_size).encode() + b'\0')
        try:
            require(identity(os.fstat(fd)) == identity(before), 'original changed before descriptor read')
            if reserve is not None:
                reserve(before.st_size)
            while count < before.st_size:
                block = os.read(fd, min(1 << 20, before.st_size - count))
                if not block:
                    break
                count += len(block)
                digest.update(block)
                git_digest.update(block)
                if retain:
                    chunks.append(block)
            require(count == before.st_size and identity(os.fstat(fd)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    'original changed during descriptor read')
        finally:
            os.close(fd)
        pin = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
               'git_blob_sha1': git_digest.hexdigest(), 'posix_mode': stat.S_IMODE(before.st_mode),
               'identity': list(identity(before))}
        return (b''.join(chunks) if retain else None), pin

def descriptor_read(path, maximum=32 << 20, *, system_binary=False, reserve=None):
    return inspect_file(path, maximum, system_binary=system_binary, retain=True, reserve=reserve)

def descriptor_create(path, raw):
    path = Path(path)
    with parent_descriptor(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o400, dir_fd=parent)
        try:
            os.fchmod(fd, 0o400)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                require(written > 0, 'short create-only original write')
                offset += written
            os.fsync(fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o400
                    and before.st_size == len(raw), 'created original identity differs')
            os.lseek(fd, 0, os.SEEK_SET)
            chunks, count = [], 0
            while count < len(raw):
                part = os.read(fd, min(1 << 20, len(raw) - count))
                if not part:
                    break
                chunks.append(part)
                count += len(part)
            observed = b''.join(chunks)
            require(observed == raw and count == len(raw)
                    and identity(os.fstat(fd)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    'create-only original descriptor readback differs')
            pin = {'path': str(path), 'bytes': count, 'sha256': sha256(observed).hexdigest(),
                   'git_blob_sha1': blob(observed), 'posix_mode': stat.S_IMODE(before.st_mode),
                   'identity': list(identity(before))}
        finally:
            os.close(fd)
        return pin


def read(path, maximum=8 << 20, expected=None):
    raw, _ = descriptor_read(Path(path), maximum)
    require(expected is None or sha256(raw).hexdigest() == expected, 'input SHA differs')
    return raw

def file_record(path, maximum=64 << 20, *, system_binary=False):
    _, pin = inspect_file(Path(path), maximum, system_binary=system_binary)
    return {key: pin[key] for key in ('path', 'bytes', 'sha256', 'identity')}

def create(path, raw, mode=0o400):
    require(mode == 0o400, 'fixed immutable create mode required')
    return descriptor_create(Path(path), raw)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def new_client():
    # Each caller gets an independent client: there is no cookie jar, global
    # authentication handler, ambient proxy, or automatically followed redirect.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def deadline_check(deadline):
    require(time.monotonic_ns() < deadline, 'combined original transfer deadline exceeded')


def api_request(token, path):
    require(path.startswith('/repos/' + REPO + '/actions/artifacts/')
            and '\n' not in token and '\r' not in token, 'fixed API credential boundary differs')
    return urllib.request.Request('https://api.github.com' + path, method='GET', headers={
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': API_VERSION,
        'Accept-Encoding': 'identity',
        'User-Agent': 'HIA-original-artifact-custody/1',
    })


def bounded_response(response, maximum, deadline):
    count, chunks = 0, []
    while True:
        deadline_check(deadline)
        block = response.read1(min(CHUNK, maximum + 1 - count))
        deadline_check(deadline)
        if not block:
            break
        count += len(block)
        require(count <= maximum, 'API metadata exceeds bound')
        chunks.append(block)
    return b''.join(chunks)


def metadata(token, pin, root, deadline, report, helper):
    path = '/repos/' + REPO + '/actions/artifacts/%d' % pin['id']
    attempt = {'artifact_id': pin['id'], 'role': 'official_metadata',
               'method': 'GET', 'host': 'api.github.com', 'path': path,
               'attempt': 1, 'retries': 0, 'credential_sent_only_to_official_API': True}
    report['API_attempts'].append(attempt)
    helper.checkpoint(report)
    deadline_check(deadline)
    request = api_request(token, path)
    with new_client().open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == request.full_url,
                'exact metadata HTTP200 required')
        require(response.headers.get('Content-Encoding', 'identity').lower() == 'identity',
                'encoded API metadata refused')
        raw = bounded_response(response, 1 << 20, deadline)
    value = json.loads(raw)
    require(type(value) is dict and value.get('id') == pin['id']
            and value.get('size_in_bytes') == pin['bytes']
            and value.get('digest') == 'sha256:' + pin['sha256']
            and value.get('expired') is False
            and value.get('workflow_run', {}).get('id') == pin['run_id']
            and value.get('workflow_run', {}).get('head_sha') == pin['head_sha']
            and value.get('name') == pin['name']
            and value.get('archive_download_url') == 'https://api.github.com' + path + '/zip',
            'official artifact identity differs from external pins')
    output = root / 'api' / ('artifact-%d.metadata.original.json' % pin['id'])
    create(output, raw)
    require(read(output, 1 << 20) == raw, 'metadata independent readback differs')
    record = {'path': str(output), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
              'artifact_id': pin['id'], 'run_id': pin['run_id'],
              'provider_head_sha_observed': value.get('workflow_run', {}).get('head_sha')}
    attempt.update(status=200, original_metadata=record)
    helper.checkpoint(report)
    return record


def official_location(token, pin, deadline, report, helper):
    path = '/repos/' + REPO + '/actions/artifacts/%d/zip' % pin['id']
    attempt = {'artifact_id': pin['id'], 'role': 'official_download_redirect',
               'method': 'GET', 'host': 'api.github.com', 'path': path,
               'attempt': 1, 'retries': 0, 'automatic_redirects': 0,
               'credential_sent_only_to_official_API': True}
    report['API_attempts'].append(attempt)
    helper.checkpoint(report)
    deadline_check(deadline)
    request = api_request(token, path)
    try:
        response = new_client().open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    try:
        require(response.code == 302 and response.geturl() == request.full_url,
                'official archive endpoint must return exactly302')
        locations = response.headers.get_all('Location', [])
        require(len(locations) == 1, 'one signed location required')
        url = locations[0]
        require(type(url) is str and 0 < len(url) <= 16384
                and not any(ord(c) < 32 or ord(c) == 127 for c in url),
                'bounded signed location required')
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname
                and parsed.hostname.endswith(('.blob.core.windows.net', '.actions.githubusercontent.com'))
                and parsed.port in (None, 443) and not parsed.username
                and not parsed.password and not parsed.fragment,
                'official signed storage endpoint refused')
    finally:
        response.close()
    deadline_check(deadline)
    attempt.update(status=302, storage_host=parsed.hostname,
                   location_sha256=sha256(url.encode()).hexdigest(),
                   signed_Location_recorded=False, authorization_forwarded=False)
    helper.checkpoint(report)
    return url


def storage_download(url, pin, root, deadline, report, helper):
    # This completely new request/client carries no Authorization or Cookie.
    # The signed Location is never serialized, printed, or passed as argv.
    parsed = urllib.parse.urlsplit(url)
    path = root / 'original' / ('artifact-%d.zip' % pin['id'])
    partial = path.with_name(path.name + '.partial')
    require(not os.path.lexists(path) and not os.path.lexists(partial), 'original archive already exists')
    attempt = {'artifact_id': pin['id'], 'method': 'GET', 'attempt': 1,
               'host': parsed.hostname, 'url_sha256': sha256(url.encode()).hexdigest(),
               'started_ns': time.monotonic_ns(), 'socket_seconds': 30,
               'redirects': 0, 'retries': 0, 'authorization_sent': False, 'cookies_sent': False}
    report['GET_attempts'].append(attempt)
    helper.checkpoint(report)
    request = urllib.request.Request(url, method='GET', headers={
        'User-Agent': 'HIA-original-artifact-custody/1', 'Accept-Encoding': 'identity'})
    require(not request.has_header('Authorization') and not request.has_header('Cookie'),
            'storage credential boundary differs')
    count, digest = 0, sha256()
    deadline_check(deadline)
    with new_client().open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, 'exact storage HTTP200 required')
        require(response.headers.get('Content-Encoding', 'identity').lower() == 'identity',
                'encoded original body refused')
        length = response.headers.get('Content-Length')
        require(length is None or int(length) == pin['bytes'], 'original HTTP size differs')
        fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'w+b') as target:
            while True:
                deadline_check(deadline)
                block = response.read1(min(CHUNK, pin['bytes'] + 1 - count))
                deadline_check(deadline)
                if not block:
                    break
                count += len(block)
                require(count <= pin['bytes'], 'original HTTP body exceeded fixed size')
                target.write(block)
                digest.update(block)
            require(count == pin['bytes'] and digest.hexdigest() == pin['sha256'],
                    'downloaded original ZIP differs from external seal')
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o400)
            os.fsync(target.fileno())
    os.link(partial, path, follow_symlinks=False)
    os.unlink(partial)
    helper.sync_dir(path.parent)
    attempt.update(bytes=count, sha256=digest.hexdigest(),
                   finished_ns=time.monotonic_ns(), output=str(path))
    helper.checkpoint(report)
    return path


def load_helper(control, policy, root):
    expected = policy['control_files']['original_receiver.py']
    path = control / 'original_receiver.py'
    raw = read(path, 1 << 20, expected['sha256'])
    require(len(raw) == expected['bytes'], 'fixed original helper size differs')
    spec = importlib.util.spec_from_file_location('fixed_original_ci_custody', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # This is a fixed evidence-only control module, never project/product code.
    # Only its destination path is re-rooted. The complete historical module is
    # preserved. This reader calls only checkpoint/create/read_file_hash/sync_dir;
    # its old download and CI-specific selection routines are not invoked.
    module.ROOT = root
    return module


FRAME_RAW_LIMIT = 512 << 10
ARCHIVE_RAW_LIMIT = 41 << 20
MAX_ARCHIVE_FILES = 116

def load_pins(control, policy):
    pin = policy['control_files']['asset-pins.json']
    raw = read(control / 'asset-pins.json', 1 << 20, pin['sha256'])
    require(len(raw) == pin['bytes'], 'fixed diagnostic pins size differs')
    value = json.loads(raw)
    rows = value.get('historical_targets')
    require(value.get('schema') == 'hia.core-failed-reader-diagnostic-pins.v1'
            and value.get('artifact') == policy['source_artifact']
            and type(rows) is list and len(rows) == 54
            and len({row['logical_path'] for row in rows}) == 54
            and sum(row['bytes'] for row in rows) == 7251108
            and sum(row['role'] == 'assembly' for row in rows) == 39
            and sum(row['role'] == 'original' for row in rows) == 14
            and value.get('assembly_output') is False
            and value.get('original_failure_reclassified') is False,
            'fixed failed-reader inventory differs')
    for index, row in enumerate(rows):
        require(row['archive_aliases'] ==
                    ['%03d.original' % index, 'partial/%03d.original' % (index + 2)]
                and type(row['bytes']) is int and 0 <= row['bytes'] <= 2 << 20
                and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
                and re.fullmatch(r'[0-9a-f]{40}', row['git_blob_sha1']) is not None,
                'historical pin or fixed alias differs')
    require([x['logical_path'] for x in value['reader_targets']] == [
                'failed-reader/guard/guardian.json',
                'failed-reader/guard/child.stdout.log',
                'failed-reader/guard/child.stderr.log',
                'failed-reader/recovery-terminal.json', 'failed-reader/setup.json'],
            'fixed five prior reader diagnostics differ')
    return value

def zip_inventory(path, pins):
    allowed = {'RESULT.json'}
    allowed.update('%03d.original' % i for i in range(59))
    allowed.update('partial/%03d.original' % i for i in range(56))
    optional_root = 'hia-core-emitter-generated-asset-receipts-r2/'
    inventory, total, names, prefix_mode = [], 0, set(), None
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(len(infos) <= MAX_ARCHIVE_FILES + 2, 'failed artifact entry denominator exceeded')
        for info in infos:
            raw_name = info.filename
            require(type(raw_name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', raw_name)
                    and not raw_name.startswith('/') and '\\' not in raw_name
                    and all(p not in ('.', '..') for p in raw_name.split('/')),
                    'unsafe failed artifact member name')
            rooted = raw_name.startswith(optional_root)
            name = raw_name[len(optional_root):] if rooted else raw_name
            if raw_name == optional_root and info.is_dir():
                require(info.file_size == 0, 'nonempty root directory member')
                continue
            if prefix_mode is None:
                prefix_mode = rooted
            require(prefix_mode == rooted, 'mixed failed artifact root prefixes')
            require(name not in names, 'duplicate failed artifact member')
            names.add(name)
            require(not info.flag_bits & 1
                    and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    'encrypted or unsupported failed artifact member')
            if info.is_dir():
                require(name == 'partial/' and info.file_size == 0,
                        'unexpected failed artifact directory')
                continue
            mode = info.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG) and name in allowed,
                    'nonregular or nonfixed failed artifact member: ' + name)
            require(type(info.file_size) is int and 0 <= info.file_size <= 32 << 20,
                    'failed artifact member exceeds bound')
            total += info.file_size
            require(total <= ARCHIVE_RAW_LIMIT, 'failed artifact inflated extent exceeds bound')
            count, digest = 0, sha256()
            git = sha1(b'blob ' + str(info.file_size).encode() + b'\0')
            with archive.open(info, 'r') as source:
                while True:
                    part = source.read(min(CHUNK, info.file_size + 1 - count))
                    if not part:
                        break
                    count += len(part)
                    require(count <= info.file_size, 'failed member expanded beyond metadata')
                    digest.update(part)
                    git.update(part)
            require(count == info.file_size, 'failed member byte count differs')
            inventory.append({'archive_path': raw_name, 'normalized_path': name,
                'bytes': count, 'sha256': digest.hexdigest(), 'git_blob_sha1': git.hexdigest(),
                'zip_crc32': info.CRC, 'full_member_CRC_read': True})
    require(len(inventory) <= MAX_ARCHIVE_FILES, 'failed artifact file denominator exceeded')
    return inventory, total

def member_bytes(archive, row, maximum):
    require(row['bytes'] <= maximum, 'fixed diagnostic original exceeds raw limit')
    info = archive.getinfo(row['archive_path'])
    raw = archive.read(info)
    require(len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
            and blob(raw) == row['git_blob_sha1'], 'diagnostic member changed after inventory')
    return raw

def old_context(value, pins):
    old = pins['original_failed_reader']
    require(type(value) is dict
            and value.get('schema') == old['schema_context']
            and value.get('repository') == REPO and value.get('event') == 'create'
            and value.get('run_attempt') == 1 and value.get('run_id') == old['run_id']
            and value.get('actual_control_checkout') == old['control_commit']
            and value.get('actual_workflow_commit') == old['workflow_commit']
            and value.get('policy_sha256') == old['policy_sha256']
            and type(value.get('root')) is str and len(value['root']) <= 4096
            and Path(value['root']).is_absolute() and '..' not in Path(value['root']).parts
            and Path(value['root']).name == old['work_root_name']
            and type(value.get('public_root')) is str
            and Path(value['public_root']).is_absolute()
            and '..' not in Path(value['public_root']).parts
            and Path(value['public_root']).parent == Path(value['root']).parent
            and Path(value['public_root']).name == old['public_root_name']
            and value.get('token_or_signed_URL_in_context') is False
            and value.get('qualification_executed') is False,
            'diagnostic JSON belongs to another reader operation')
    return value

def select_diagnostics(path, policy, root, helper, report):
    pins = load_pins(root / 'control', policy)
    before = helper.read_file_hash(path, expected_size=policy['source_artifact']['bytes'],
                                   expected_sha=policy['source_artifact']['sha256'])
    inventory, total = zip_inventory(path, pins)
    by_name = {row['normalized_path']: row for row in inventory}
    report.update(archive_inventory=inventory, archive_member_count=len(inventory),
                  archive_uncompressed_bytes=total, all_members_fully_read_and_CRC_verified=True,
                  original_failed_run=pins['original_failed_reader'],
                  original_run_conclusion='failure', original_failure_reclassified=False)
    observations, chosen = [], {}
    for target in pins['historical_targets']:
        existing = [by_name[name] for name in target['archive_aliases'] if name in by_name]
        matches = [row for row in existing if all(row[key] == target[key]
                   for key in ('bytes', 'sha256', 'git_blob_sha1'))]
        observations.append({'logical_path': target['logical_path'], 'role': target['role'],
            'expected_bytes': target['bytes'], 'expected_sha256': target['sha256'],
            'expected_git_blob_sha1': target['git_blob_sha1'],
            'actual_members': existing, 'matching_members': [row['archive_path'] for row in matches],
            'exact_original_observed': bool(matches), 'body_output': False})
        if target['role'] == 'original' and matches:
            chosen[target['logical_path']] = matches[0]
    report['historical_file_observations'] = observations
    report['assembly_count_in_original_inventory'] = 39
    report['assembly_exact_hash_matches'] = sum(x['role'] == 'assembly'
                                               and x['exact_original_observed'] for x in observations)
    report['assembly_body_bytes_output'] = 0
    report['prior_reader_diagnostic_refusals'] = []
    raw_selected = {}
    with zipfile.ZipFile(path) as archive:
        for logical, row in chosen.items():
            raw_selected[logical] = (row, member_bytes(archive, row, FRAME_RAW_LIMIT))
        accepted_layouts = []
        for layout, key in (('main', 'main_member'), ('hold', 'hold_member')):
            rows = {x['logical_path']: by_name.get(x[key]) for x in pins['reader_targets']}
            setup_row = rows['failed-reader/setup.json']
            guard_row = rows['failed-reader/guard/guardian.json']
            if setup_row is None or guard_row is None:
                continue
            try:
                setup_raw = member_bytes(archive, setup_row, FRAME_RAW_LIMIT)
                setup = json.loads(setup_raw)
                context = old_context(setup.get('context'), pins)
                old_root = context['root']
                require(setup.get('schema') == 'hia.actions.core-emitter-assets-setup.v1'
                        and setup.get('status') == 'PREPARED_NOT_EXECUTED'
                        and setup.get('controller_seconds') == 900
                        and setup.get('cleanup_seconds') == 3
                        and setup.get('command') == [context['python']['resolved'], '-I', '-S', '-B',
                            old_root + '/control/worker.py', '--root', old_root,
                            '--policy-sha256', context['policy_sha256']]
                        and type(setup.get('source_identities')) is dict,
                        'prior diagnostic setup shape differs')
                guard_raw = member_bytes(archive, guard_row, FRAME_RAW_LIMIT)
                guard = json.loads(guard_raw)
                life = guard.get('lifecycle', {})
                cleanup = life.get('cleanup', {})
                require(guard.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
                        and guard.get('command') == setup['command'] and guard.get('cwd') == old_root
                        and guard.get('external_controller_seconds') == 900
                        and guard.get('source_identities_before') == setup['source_identities']
                        and life.get('qualification_seconds') == 900
                        and life.get('cleanup_seconds') == 3
                        and cleanup.get('complete') is True and cleanup.get('observed_echild') is True,
                        'prior diagnostic guardian is not bound closed ownership')
                part = {'failed-reader/setup.json': (setup_row, setup_raw),
                        'failed-reader/guard/guardian.json': (guard_row, guard_raw)}
                for logical in ('failed-reader/guard/child.stdout.log',
                                'failed-reader/guard/child.stderr.log'):
                    row = rows[logical]
                    if row is not None:
                        raw = member_bytes(archive, row, FRAME_RAW_LIMIT)
                        suffix = logical.removeprefix('failed-reader/')
                        require(guard.get('logs', {}).get(old_root + '/' + suffix)
                                == sha256(raw).hexdigest(), 'prior diagnostic child log differs')
                        part[logical] = (row, raw)
                logical = 'failed-reader/recovery-terminal.json'
                row = rows[logical]
                if row is not None:
                    raw = member_bytes(archive, row, FRAME_RAW_LIMIT)
                    value = json.loads(raw)
                    require(value.get('schema') == 'hia.actions.core-emitter-assets-worker.v1'
                            and value.get('root') == old_root
                            and value.get('policy_sha256') == context['policy_sha256']
                            and value.get('source_artifact') == pins['historical_source_artifact']
                            and value.get('token_or_signed_URL_recorded') is False
                            and value.get('source_generated_again') is False,
                            'prior recovery report is not this failed-reader operation')
                    part[logical] = (row, raw)
                accepted_layouts.append((layout, part))
            except (Refusal, ValueError, TypeError, KeyError, AttributeError) as error:
                report['prior_reader_diagnostic_refusals'].append({
                    'layout': layout, 'type': type(error).__name__,
                    'safe_refusal': str(error) if type(error) is Refusal else None})
        if accepted_layouts:
            first_layout, first = accepted_layouts[0]
            for _, other in accepted_layouts[1:]:
                require(set(other) == set(first)
                        and all(other[key][1] == first[key][1] for key in first),
                        'two conflicting bound prior-reader diagnostic layouts')
            report['prior_reader_layout'] = first_layout
            report['prior_reader_root_observed'] = json.loads(first['failed-reader/setup.json'][1])['context']['root']
            raw_selected.update(first)
        result_row = by_name.get('RESULT.json')
        if result_row is not None:
            try:
                raw = member_bytes(archive, result_row, FRAME_RAW_LIMIT)
                value = json.loads(raw)
                require(value.get('schema') == 'hia.actions.core-emitter-assets-log-result.v1'
                        and value.get('status') in ('FRAMING_HOLD', 'ORIGINAL_FRAMES_COMPLETE_NOT_QUALIFICATION')
                        and value.get('qualification_executed') is False
                        and value.get('original_product_statuses_reclassified') is False,
                        'prior frame result schema differs')
                old_context(value.get('context'), pins)
                raw_selected['failed-reader/RESULT.json'] = (result_row, raw)
                report['prior_frame_result_status'] = value['status']
            except (Refusal, ValueError, TypeError, KeyError, AttributeError) as error:
                report['prior_reader_diagnostic_refusals'].append({
                    'logical_path': 'failed-reader/RESULT.json', 'type': type(error).__name__,
                    'safe_refusal': str(error) if type(error) is Refusal else None})
    targets = [row['logical_path'] for row in pins['historical_targets'] if row['role'] == 'original']
    targets += [row['logical_path'] for row in pins['reader_targets']]
    targets.append('failed-reader/RESULT.json')
    require(len(targets) == 20 and len(set(targets)) == 20
            and set(raw_selected) <= set(targets), 'fixed diagnostic target denominator differs')
    require(sum(len(raw) for _, raw in raw_selected.values()) <= FRAME_RAW_LIMIT,
            'all present original diagnostics exceed the fixed raw budget')
    files = []
    for index, logical in enumerate(targets):
        if logical not in raw_selected:
            continue
        row, raw = raw_selected[logical]
        require(not logical.startswith('source/'), 'assembly or ABI body entered diagnostic output')
        target = root / 'selected' / ('%03d.original' % index)
        create(target, raw)
        actual = file_record(target, FRAME_RAW_LIMIT)
        require(actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'],
                'diagnostic raw copy differs')
        files.append({'logical_path': logical, 'archive_path': row['archive_path'],
                      'origin': 'exact failed reader artifact member ' + row['archive_path'],
                      'record': actual})
    after = helper.read_file_hash(path, expected_size=policy['source_artifact']['bytes'],
                                  expected_sha=policy['source_artifact']['sha256'])
    require(before == after, 'complete failed-reader ZIP changed while inspected')
    report.update(artifact_before=before, artifact_after=after, diagnostic_targets=targets,
                  frame_files=files, missing_diagnostic_targets=[x for x in targets if x not in raw_selected],
                  selected_original_bytes=sum(row['record']['bytes'] for row in files),
                  all_selected_originals_fully_read=True, source_bodies_recovered=False)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    control = root / 'control'
    policy = json.loads(read(control / 'policy.json', 1 << 20, args.policy_sha256))
    require(policy.get('schema') == 'hia.actions.core-failed-reader-diagnostic-policy.v1',
            'fixed failed-reader diagnostic policy differs')
    pin = policy['source_artifact']
    require(pin.get('id') == 13915070523 and pin.get('bytes') == 7381515
            and pin.get('sha256') == '57e3f0db194d961e64dd4773b04dddf373fe5ca02ea2763924d0ec5040d2a2f8'
            and pin.get('run_id') == 43152508792
            and pin.get('head_sha') == '6049861e92f0f68dacaf3101bfdb0f98f06c9930',
            'fixed actual failed artifact differs')
    require(root == Path(os.environ['RUNNER_TEMP']).resolve() / policy['work_root_name'],
            'private diagnostic root differs')
    token = os.environ.pop(TOKEN_VARIABLE, None)
    require(type(token) is str and 0 < len(token) < 16384, 'Actions read token required')
    helper = load_helper(control, policy, root)
    started = time.monotonic_ns()
    deadline = started + 720 * 1000000000
    report = {'schema': 'hia.actions.core-failed-reader-diagnostic-worker.v1', 'status': 'READ_HOLD',
        'root': str(root), 'policy_sha256': args.policy_sha256,
        'external_pins_sha256': policy['control_files']['asset-pins.json']['sha256'],
        'API_attempts': [], 'GET_attempts': [], 'source_artifact': pin,
        'project_code_executed': False, 'qualification_executed': False,
        'original_product_statuses_reclassified': False, 'original_failure_reclassified': False,
        'source_generated_again': False, 'native_compiler_executed': False,
        'Core_VM_executed': False, 'product_tests_executed': False,
        'assembly_body_bytes_output': 0, 'source_bodies_recovered': False,
        'token_or_signed_URL_recorded': False}
    stage = 'FROZEN_INPUTS'
    try:
        load_pins(control, policy)
        helper.checkpoint(report)
        stage = 'OFFICIAL_METADATA'
        report['official_metadata'] = metadata(token, pin, root, deadline, report, helper)
        stage = 'OFFICIAL_LOCATION'
        url = official_location(token, pin, deadline, report, helper)
        stage = 'FAILED_ARTIFACT_GET'
        path = storage_download(url, pin, root, deadline, report, helper)
        del url
        stage = 'FAILED_ARTIFACT_DIAGNOSTICS'
        select_diagnostics(path, policy, root, helper, report)
        report.update(status='FAILURE_DIAGNOSTICS_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started)
        create(root / 'recovery-terminal.json', wire(report))
        helper.checkpoint(report)
        print(json.dumps({'status': report['status'], 'original_run_conclusion': 'failure',
                          'diagnostic_targets_present': len(report['frame_files']),
                          'missing_diagnostics': len(report['missing_diagnostic_targets']),
                          'assembly_body_bytes_output': 0, 'qualification_executed': False}), flush=True)
        return 0
    except BaseException as error:
        report.update(status='READ_HOLD', failed_stage=stage, error_type=type(error).__name__,
            safe_refusal=str(error) if type(error) in (Refusal, helper.Refusal) else None,
            errno=getattr(error, 'errno', None), http_status=getattr(error, 'code', None),
            elapsed_ns=time.monotonic_ns() - started)
        try:
            if not os.path.lexists(root / 'recovery-terminal.json'):
                create(root / 'recovery-terminal.json', wire(report))
            helper.checkpoint(report)
        except BaseException:
            pass
        print(json.dumps({'status': 'READ_HOLD', 'stage': stage,
                          'error_type': type(error).__name__}), flush=True)
        return 1
    finally:
        token = None

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(json.dumps({'status': 'INPUT_HOLD', 'safe_refusal': str(error)}), flush=True)
        raise SystemExit(1)
