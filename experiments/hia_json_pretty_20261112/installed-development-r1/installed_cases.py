"""Nine installed-package controls for the actual Pretty development image.

This standard-library consumer must run with -I -S -B and an empty PATH in its
own original five-second owned process. It imports product code only from the
explicit installed root. No authoring module or host JSON layout may service
a formatting call. This is not CLI or cold qualification.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from hashlib import sha1, sha256
import importlib.abc
import json
import os
from pathlib import Path
import stat
import sys
import traceback

MAX_RECEIPT = 64 << 20
IDS = (
    'installed_package_sources_and_native_output',
    'invalid_manifest_schema',
    'invalid_manifest_source_hash',
    'invalid_manifest_image_hash',
    'invalid_manifest_shape_and_compiler_field',
    'warm_source_mutation_rejected_and_restored',
    'warm_source_missing_rejected_and_restored',
    'missing_data_root_refuses_checkout_and_cwd_fallback',
    'manifest_size_duplicate_keys_and_reentry',
)
SOURCE_NAME = 'examples/hia_bootstrap/json_pretty.hiaasm'
BRIDGE_NAME = 'hepta/hia_json_pretty_native.py'
FIXTURE = b'{"a":[1,true],"b":"x"}'
EXPECTED = b'{\n  "a": [\n    1,\n    true\n  ],\n  "b": "x"\n}'
ORIGINAL_JSON_DUMPS = json.dumps

def require(value, message):
    if not value:
        raise AssertionError(message)

def wire(value):
    return (ORIGINAL_JSON_DUMPS(value, sort_keys=True, indent=2) + '\n').encode('utf-8')

def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()}

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

@contextmanager
def _checked_parent(path):
    """Retain the complete absolute directory chain without following symlinks."""
    path = Path(path)
    require(path.is_absolute() and path.anchor == '/' and '..' not in path.parts
            and len(path.parts) > 1, 'noncanonical controlled IO path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def stable():
        for parent, name, child, expected in links:
            require(_directory_identity(os.fstat(child)) == expected
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected,
                    'controlled IO directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'controlled IO ancestor is not a directory')
            links.append((parent, name, child, _directory_identity(info)))
        stable()
        yield descriptors[-1], path.parts[-1], stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def _read_extent(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        block = os.read(descriptor, min(1 << 20, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    require(remaining == 0, 'controlled IO original ended before its declared extent')
    return b''.join(chunks)

def _create_bytes(path, raw, mode):
    """Create through the retained parent; read back the same open descriptor."""
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            os.fchmod(descriptor, mode)
            remaining = memoryview(raw)
            while remaining:
                count = os.write(descriptor, remaining)
                require(count > 0, 'controlled IO write made no progress')
                remaining = remaining[count:]
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and before.st_size == len(raw),
                    'create-only controlled output identity differs')
            expected = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                        before.st_gid, before.st_nlink, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns)
            def same_leaf(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                        info.st_gid, info.st_nlink, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns) == expected
            require(same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only output name changed')
            stable()
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(_read_extent(descriptor, len(raw)) == raw
                    and same_leaf(os.fstat(descriptor))
                    and same_leaf(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'create-only descriptor readback differs')
            stable()
        finally:
            os.close(descriptor)

def _create_directory(path, mode=0o700):
    with _checked_parent(path) as (parent, name, stable):
        os.mkdir(name, mode=mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            observed = os.fstat(descriptor)
            require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == os.geteuid()
                    and not stat.S_IMODE(observed.st_mode) & 0o077
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False))
                        == _directory_identity(observed),
                    'create-only private directory differs')
            stable()
        finally:
            os.close(descriptor)

def read(path, maximum=MAX_RECEIPT, *, system_binary=False):
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), 'regular input required: ' + str(path))
            if system_binary:
                require(before.st_uid in (0, os.geteuid()) and before.st_nlink >= 1
                        and not stat.S_IMODE(before.st_mode) & 0o022,
                        'runner tool is writable or has unexpected ownership')
            else:
                require(before.st_uid == os.geteuid() and before.st_nlink == 1,
                        'owned single-link input required')
            require(0 <= before.st_size <= maximum, 'bounded original input required')
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed before reading')
            stable()
            raw = _read_extent(descriptor, before.st_size)
            require(identity(os.fstat(descriptor)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before), 'input changed during reading')
            stable()
            return raw, {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                         'identity': list(identity(before))}
        finally:
            os.close(descriptor)

def create(path, raw):
    _create_bytes(path, raw, 0o400)
    copied, record = read(path, max(len(raw), 1))
    require(copied == raw, 'create-only original readback differs')
    return record

def save(path, value):
    return create(path, wire(value))


def namespace(root):
    result = []
    def failed(error):
        raise error
    for directory, names, files in os.walk(root, followlinks=False, onerror=failed):
        for name in names:
            require(stat.S_ISDIR((Path(directory) / name).lstat().st_mode),
                    'installed directory became a link')
        for name in files:
            path = Path(directory) / name
            require(stat.S_ISREG(path.lstat().st_mode), 'installed leaf is not regular')
            result.append(path.relative_to(root).as_posix())
    return sorted(result)


def installed_inventory(root):
    names = namespace(root)
    rows = []
    total = 0
    for name in names:
        raw, record = read(root / name, 64 << 20)
        total += len(raw)
        require(total <= 128 << 20, 'installed inventory exceeds fixed budget')
        rows.append({'path': name, **pin(raw),
                     'mode': format(stat.S_IMODE(record['identity'][2]), '04o'),
                     'identity': record['identity']})
    require(namespace(root) == names, 'installed namespace changed')
    return rows


def bytes_and_modes(rows):
    return [{key: row[key] for key in ('path', 'bytes', 'sha256', 'git_blob_sha1', 'mode')}
            for row in rows]


def replace_source(path, raw):
    with _checked_parent(path) as (parent, name, stable):
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1
                    and identity(before) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'test-owned installed source identity differs')
            os.ftruncate(fd, 0)
            rest = memoryview(raw)
            while rest:
                count = os.write(fd, rest)
                require(count > 0, 'source restoration write stalled')
                rest = rest[count:]
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            require(_read_extent(fd, len(raw)) == raw, 'source restoration readback differs')
            stable()
        finally:
            os.close(fd)


def unlink_source(path):
    with _checked_parent(path) as (parent, name, stable):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1, 'only the owned installed source may be removed')
        stable()
        os.unlink(name, dir_fd=parent)
        stable()


def rename_data_root(source, target):
    require(source.parent == target.parent and not os.path.lexists(target),
            'data-root test rename must be same-parent/create-only')
    with _checked_parent(source) as (parent, name, stable):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(),
                'only owned installed resource directory may be renamed')
        stable()
        os.rename(name, target.name, src_dir_fd=parent, dst_dir_fd=parent)
        require(os.stat(target.name, dir_fd=parent, follow_symlinks=False).st_ino == info.st_ino,
                'data-root rename changed inode')
        stable()


class NoAuthoring(importlib.abc.MetaPathFinder):
    def __init__(self, attempts):
        self.attempts = attempts

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'tools', 'tests', 'setuptools', 'pip', 'wheel'}:
            self.attempts.append(fullname)
            raise AssertionError('installed consumer imported authoring/build modules: ' + fullname)


@contextmanager
def no_host_layout(attempts):
    originals = (json.dumps, json.dump, json.JSONEncoder.encode, json.JSONEncoder.iterencode)
    def forbidden(*args, **kwargs):
        attempts.append('host JSON layout')
        raise AssertionError('host JSON layout serviced a native formatting call')
    json.dumps = json.dump = json.JSONEncoder.encode = json.JSONEncoder.iterencode = forbidden
    try:
        yield
    finally:
        json.dumps, json.dump, json.JSONEncoder.encode, json.JSONEncoder.iterencode = originals


class Cases:
    def __init__(self, request, report):
        self.request, self.report = request, report
        self.root = Path(request['installation_root'])
        self.installed = Path(request['installed_root'])
        self.manifest = Path(request['manifest_path'])
        self.source = self.installed / 'hepta' / '_data' / SOURCE_NAME
        self.case_id = None
        self.objects = []
        self.completed = []
        self.attempts = []
        self.negative_originals = []
        self.original_source, self.source_record = read(self.source, 1 << 20)
        require(sha256(self.original_source).hexdigest() == request['source_sha256'],
                'installed HIA source differs from fresh compilation source')
        self.manifest_raw, actual_manifest_record = read(self.manifest, 16384)
        require(actual_manifest_record == request['manifest_original'], 'actual installed manifest changed')
        self.manifest_value = json.loads(self.manifest_raw)
        require(self.manifest_value == {
            'schema': 'hepta.hia.json-pretty-native.v1',
            'source_sha256': request['source_sha256'],
            'image_path': Path(request['image_original']['path']).name,
            'image_sha256': request['image_original']['sha256'],
            'compiler_sha256': request['compiler_input']['sha256'],
        }, 'development manifest does not bind actual source/image/compiler')
        native_raw, native_record = read(Path(request['image_original']['path']), 1 << 20)
        require(native_record == request['image_original'], 'actual development image changed')
        self.before = installed_inventory(self.installed)
        require(bytes_and_modes(self.before) == bytes_and_modes(request['installed_before']),
                'actual installed package differs from offline build')
        sys.path.insert(0, str(self.installed))
        sys.meta_path.insert(0, NoAuthoring(report['forbidden_authoring_attempts']))
        from hepta import hia_json_pretty_native as bridge
        from hepta import hia_json_preflight_native as admission
        self.bridge, self.admission = bridge, admission
        require(bridge.SOURCE == self.source, 'package source is not installed-owned')
        self.assert_origins()

    def assert_origins(self):
        origins = {}
        for name, module in list(sys.modules.items()):
            if name == 'hepta' or name.startswith('hepta.'):
                path = Path(module.__file__).resolve()
                require(self.installed in path.parents, 'product module came from checkout or cwd')
                origins[name] = str(path)
        require(origins and 'hepta.hia_json_pretty_native' in origins,
                'actual installed bridge was not imported')
        raw, _ = read(Path(origins['hepta.hia_json_pretty_native']), 1 << 20)
        require(sha256(raw).hexdigest() == self.request['bridge_sha256'], 'installed bridge bytes differ')
        require(not any(name.split('.')[0] in {'tools', 'tests', 'setuptools', 'pip', 'wheel'}
                        for name in sys.modules), 'authoring/build module already loaded')
        self.report['module_origins'] = origins

    def selected(self):
        owner = self.bridge.installed_json_pretty(str(self.manifest))
        require(owner.image_sha256 == self.request['image_original']['sha256']
                and owner.admitted_source_sha256 == self.request['source_sha256'],
                'actual source/image admission differs')
        if all(owner is not old for old in self.objects):
            entry = owner._entry
            def counted(*args):
                attempt = {'case': self.case_id, 'argument_count': len(args)}
                self.attempts.append(attempt)
                result = entry(*args)
                attempt['returned_status'] = result
                self.completed.append({'case': self.case_id, 'status': result})
                return result
            owner._entry = counted
            self.objects.append(owner)
        return owner

    def format(self, data=FIXTURE, expected=EXPECTED):
        owner = self.selected()
        count = len(self.completed)
        with no_host_layout(self.report['forbidden_host_layout_attempts']):
            actual = owner.format_admitted_compact(data)
        require(actual == expected, 'actual installed HIA output differs from literal fixture')
        require(len(self.completed) == count + 2
                and all(row['status'] == 0 for row in self.completed[count:]),
                'actual native measure/emit pair did not return successfully')
        return {'input': pin(data), 'output': pin(actual),
                'native_completed_calls': len(self.completed) - count}

    def negative(self, label, value=None, raw=None):
        path = self.root / 'invalid-manifests' / (label + '.json')
        if raw is None:
            value = dict(value)
            value['image_path'] = self.request['image_original']['path']
            raw = wire(value)
        record = create(path, raw)
        self.negative_originals.append(record)
        before = len(self.attempts)
        try:
            self.bridge.installed_json_pretty(str(path))
        except ValueError as error:
            observed = {'class': type(error).__qualname__, 'args': list(error.args),
                        'manifest': record}
        else:
            raise AssertionError('invalid manifest was admitted: ' + label)
        require(len(self.attempts) == before, 'invalid manifest reached existing native code')
        return observed

    def installed_package_sources_and_native_output(self):
        module_names = sorted(row['path'] for row in self.before
                              if row['path'].startswith('hepta/') and row['path'].endswith('.py')
                              and not row['path'].startswith('hepta/_data/'))
        resource_names = sorted(row['path'][len('hepta/_data/'):] for row in self.before
                                if row['path'].startswith('hepta/_data/'))
        require(module_names == self.request['module_names'] and len(module_names) == 169
                and resource_names == sorted(self.request['resource_names'])
                and len(resource_names) == 96, 'complete installed source population differs')
        return {'python_modules': len(module_names), 'source_resources': len(resource_names),
                'source_path': str(self.source), 'format': self.format(),
                'admitted_source_sha256': self.selected().admitted_source_sha256}

    def invalid_manifest_schema(self):
        value = dict(self.manifest_value, schema='hepta.hia.json-pretty-native.invalid')
        return self.negative('schema', value)

    def invalid_manifest_source_hash(self):
        value = dict(self.manifest_value, source_sha256='0' * 64)
        return self.negative('source', value)

    def invalid_manifest_image_hash(self):
        value = dict(self.manifest_value, image_sha256='0' * 64)
        return self.negative('image', value)

    def invalid_manifest_shape_and_compiler_field(self):
        extra = dict(self.manifest_value, unexpected='not an admitted manifest field')
        compiler_format = dict(self.manifest_value, compiler_sha256='g' * 64)
        return {'subcases': [self.negative('shape', extra),
                             self.negative('compiler-format', compiler_format)],
                'compiler_scope': 'Only malformed compiler hash syntax is rejected here. The actual compiler bytes are independently bound by the package and outer build records.'}

    def warm_source_mutation_rejected_and_restored(self):
        self.selected()
        before = len(self.attempts)
        changed = self.original_source + b'\n'
        replace_source(self.source, changed)
        try:
            try:
                self.bridge.installed_json_pretty(str(self.manifest))
            except ValueError as error:
                rejection = {'class': type(error).__qualname__, 'args': list(error.args)}
            else:
                raise AssertionError('warm cached image hid changed installed source')
            require(len(self.attempts) == before, 'changed source executed native code')
        finally:
            replace_source(self.source, self.original_source)
        restored, _ = read(self.source, 1 << 20)
        require(restored == self.original_source, 'mutated installed source was not restored')
        return {'rejection': rejection, 'changed_sha256': sha256(changed).hexdigest(),
                'restored_sha256': sha256(restored).hexdigest(), 'reentry': self.format()}

    def warm_source_missing_rejected_and_restored(self):
        self.selected()
        before = len(self.attempts)
        original_mode = stat.S_IMODE(self.source.lstat().st_mode)
        unlink_source(self.source)
        try:
            try:
                self.bridge.installed_json_pretty(str(self.manifest))
            except FileNotFoundError as error:
                rejection = {'class': type(error).__qualname__, 'filename': error.filename}
            else:
                raise AssertionError('warm cached image hid missing installed source')
            require(len(self.attempts) == before, 'missing source executed native code')
        finally:
            require(not os.path.lexists(self.source), 'another source appeared during missing-source control')
            _create_bytes(self.source, self.original_source, original_mode)
        restored, _ = read(self.source, 1 << 20)
        require(restored == self.original_source, 'missing source was not restored')
        return {'rejection': rejection, 'restored_sha256': sha256(restored).hexdigest(),
                'reentry': self.format()}

    def missing_data_root_refuses_checkout_and_cwd_fallback(self):
        self.selected()
        data = self.installed / 'hepta' / '_data'
        hidden = self.installed / 'hepta' / '_data.absent-control'
        cwd = Path.cwd()
        checkout = Path(self.request['source_checkout'])
        decoy_raw, _ = read(checkout / SOURCE_NAME, 1 << 20)
        require(decoy_raw == self.original_source, 'real checkout source is not available for fallback control')
        before = len(self.attempts)
        rename_data_root(data, hidden)
        try:
            os.chdir(checkout)
            require(self.admission._source_resource_path(SOURCE_NAME) == self.source,
                    'missing installed _data switched resource ownership to cwd')
            try:
                self.bridge.installed_json_pretty(str(self.manifest))
            except FileNotFoundError as error:
                rejection = {'class': type(error).__qualname__, 'filename': error.filename}
            else:
                raise AssertionError('missing entire _data root fell back to checkout/cwd')
            require(len(self.attempts) == before, 'missing _data executed native code')
        finally:
            os.chdir(cwd)
            rename_data_root(hidden, data)
        return {'rejection': rejection, 'fallback_checkout': str(checkout),
                'source_path_remained_installed': str(self.source), 'reentry': self.format()}

    def manifest_size_duplicate_keys_and_reentry(self):
        size = self.negative('oversized', raw=b' ' * 16385)
        duplicate_value = dict(self.manifest_value, image_path=self.request['image_original']['path'])
        body = wire(duplicate_value)
        duplicate = b'{"schema":' + ORIGINAL_JSON_DUMPS(duplicate_value['schema']).encode() + b',' + body[1:]
        pairs = self.negative('duplicate-key', raw=duplicate)
        return {'subcases': [size, pairs], 'successful_reentries': [
            self.format(b'{}', b'{}'),
            self.format(b'[1,2]', b'[\n  1,\n  2\n]'),
            self.format(),
        ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    raw_request, request_record = read(args.request, 4 << 20)
    require(sha256(raw_request).hexdigest() == args.request_sha256, 'installed request SHA differs')
    request = json.loads(raw_request)
    root = Path(request['installation_root'])
    output = Path(request['output'])
    require(args.request == root / 'installed-request.json'
            and output == root / 'installed-cases.json'
            and Path(__file__).absolute() == root / 'control' / 'installed_cases.py',
            'installed control/request/output path differs')
    report = {
        'schema': 'hia.json-pretty.installed-cases.v1', 'status': 'HOLD',
        'scope': 'DEVELOPMENT_INSTALLATION', 'request_sha256': args.request_sha256,
        'expected_test_ids': list(IDS), 'loaded_test_ids': [], 'executed_test_ids': [],
        'tests_run': 0, 'failures': 0, 'errors': 0, 'skipped': 0,
        'expected_failures': 0, 'unexpected_successes': 0,
        'cases': [], 'forbidden_authoring_attempts': [], 'forbidden_host_layout_attempts': [],
        'native_completions': 0, 'native_entry_attempts': [], 'native_entry_completed': [],
        'isolated_no_site': bool(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode),
        'empty_PATH': os.environ.get('PATH') == '',
        'cold_qualified': False, 'CLI_replacement_tested': False,
    }
    cases = None
    try:
        require(request['schema'] == 'hia.json-pretty.installed-request.v1'
                and request['scope'] == 'DEVELOPMENT_INSTALLATION'
                and request['expected_test_ids'] == list(IDS)
                and request['expected_native_completions'] == 14
                and request['qualification_seconds'] == 5 and request['cleanup_seconds'] == 3
                and request['formal_cold_qualification'] is False
                and request['CLI_replacement_tested'] is False
                and report['isolated_no_site'] and report['empty_PATH'],
                'installed child scope or isolation differs')
        source, source_record = read(Path(__file__).absolute(), 1 << 20)
        require(source_record == request['child_script'], 'executed child source differs')
        require(Path(request['installed_root']) == root / 'installed'
                and Path(request['manifest_path']) == root / 'native' / 'manifest.json',
                'fixed installation paths differ')
        cases = Cases(request, report)
        methods = [getattr(cases, name) for name in IDS]
        require([method.__name__ for method in methods] == list(IDS), 'fixed nine cases do not exist')
        report['loaded_test_ids'] = [method.__name__ for method in methods]
        for name, method in zip(IDS, methods, strict=True):
            cases.case_id = name
            report['executed_test_ids'].append(name)
            report['tests_run'] += 1
            count = len(cases.completed)
            item = {'id': name, 'status': 'HOLD'}
            try:
                item['observations'] = method()
                item['status'] = 'PASS'
            except BaseException as error:
                if isinstance(error, AssertionError):
                    report['failures'] += 1
                else:
                    report['errors'] += 1
                item['exception'] = {'type': type(error).__qualname__, 'args': repr(error.args),
                                     'traceback': traceback.format_exc()}
            item['native_completed_calls'] = len(cases.completed) - count
            report['cases'].append(item)
        report['native_entry_attempts'] = cases.attempts
        report['native_entry_completed'] = cases.completed
        report['native_completions'] = len(cases.completed)
        report['negative_manifest_originals'] = cases.negative_originals
        cases.assert_origins()
        final_installed = installed_inventory(cases.installed)
        report['installed_after'] = final_installed
        report['installed_source_bytes_and_modes_restored'] = (
            bytes_and_modes(final_installed) == bytes_and_modes(cases.before))
        final_source, _ = read(cases.source, 1 << 20)
        manifest_after, manifest_record = read(cases.manifest, 16384)
        image_after, image_record = read(Path(request['image_original']['path']), 1 << 20)
        require(report['installed_source_bytes_and_modes_restored']
                and final_source == cases.original_source
                and manifest_after == cases.manifest_raw and manifest_record == request['manifest_original']
                and image_record == request['image_original']
                and sha256(image_after).hexdigest() == request['image_original']['sha256'],
                'installed source or native input was not restored/preserved')
        require(report['expected_test_ids'] == report['loaded_test_ids'] == report['executed_test_ids']
                and report['tests_run'] == 9
                and all(report[name] == 0 for name in (
                    'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
                and all(item['status'] == 'PASS' for item in report['cases'])
                and report['native_completions'] == 14
                and len(cases.attempts) == len(cases.completed)
                and report['forbidden_authoring_attempts'] == []
                and report['forbidden_host_layout_attempts'] == [],
                'complete installed-case conjunction failed')
        report['status'] = 'DEVELOPMENT_INSTALLED_CASES_PASS'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['fatal_error'] = {'type': type(error).__qualname__,
                                 'traceback': traceback.format_exc()}
        if cases is not None:
            report['native_entry_attempts'] = cases.attempts
            report['native_entry_completed'] = cases.completed
            report['native_completions'] = len(cases.completed)
            report['negative_manifest_originals'] = cases.negative_originals
    finally:
        create(output, wire(report))
    print(ORIGINAL_JSON_DUMPS({'status': report['status'], 'tests_run': report['tests_run'],
                               'native_completions': report['native_completions'],
                               'cold_qualified': False}), flush=True)
    return 0 if report['status'] == 'DEVELOPMENT_INSTALLED_CASES_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
