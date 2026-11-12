"""Offline, owned sdist/wheel/target construction for one Pretty development image.

Unexecuted control source. This helper does not build a native image or claim
cold qualification; the outer author must bind image/compiler to its actual
fresh compilation report. All product/source inputs remain read-only.
"""
from __future__ import annotations
import ast
from contextlib import contextmanager
from hashlib import sha1, sha256
import importlib.util
import gzip
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import traceback
import zipfile

MAX_RECEIPT = 64 << 20
MAX_FILE = 64 << 20
MAX_PACKAGE_BYTES = 128 << 20
OWNER_SHA = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
RESOURCE_BASE_COMMIT = '325d28bf8857696132b22a86dab0d551a3ce87bf'
RESOURCE_BASE_TREE = '5739697d49188ce0e4cc809980d42a314a0a2787'
SOURCE_NAME = 'examples/hia_bootstrap/json_pretty.hiaasm'
BRIDGE_NAME = 'hepta/hia_json_pretty_native.py'
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

def require(value, message):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')

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


def canonical_name(name):
    require(type(name) is str and name and '\\' not in name and '\0' not in name
            and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
            'noncanonical package member')
    return name


def ensure_directory(path, root):
    require(path == root or root in path.parents, 'directory outside private installation root')
    parts = path.relative_to(root).parts
    current = root
    for part in parts:
        current = current / part
        if not os.path.lexists(current):
            _create_directory(current)
        else:
            with _checked_parent(current / '.directory-spine'):
                info = current.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(),
                        'private ordinary package directory required')


def namespace(root):
    files = []
    def failed(error):
        raise error
    for directory, names, leaves in os.walk(root, followlinks=False, onerror=failed):
        for name in names:
            require(stat.S_ISDIR((Path(directory) / name).lstat().st_mode),
                    'package directory is a link or special file')
        for name in leaves:
            path = Path(directory) / name
            require(stat.S_ISREG(path.lstat().st_mode), 'package leaf is not regular')
            files.append(path.relative_to(root).as_posix())
    return sorted(files)


def inventory(root):
    before = namespace(root)
    rows = []
    total = 0
    for name in before:
        raw, record = read(root / name, MAX_FILE)
        total += len(raw)
        require(total <= MAX_PACKAGE_BYTES, 'full installed/package byte budget exceeded')
        rows.append({'path': name, **pin(raw),
                     'mode': format(stat.S_IMODE(record['identity'][2]), '04o'),
                     'identity': record['identity']})
    require(namespace(root) == before, 'package namespace changed while reading')
    return rows


def byte_projection(rows):
    return [{key: row[key] for key in ('path', 'bytes', 'sha256', 'git_blob_sha1', 'mode')}
            for row in rows]


def declared_resources(contract_raw):
    tree = ast.parse(contract_raw, filename='hepta/hia_agent_contract.py')
    values = {}
    for symbol in ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'PUBLICATION_BUILD_FILES'):
        declarations = [node for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == symbol
                                for target in node.targets)]
        require(len(declarations) == 1, 'one actual resource declaration required: ' + symbol)
        value = ast.literal_eval(declarations[0].value)
        require(type(value) is tuple and all(type(name) is str and name for name in value),
                'actual resource tuple malformed')
        values[symbol] = value
    require(all(Path(name).name == name for name in values['DISCOVERY_FILES']),
            'discovery resource filename is not ordinary')
    resources = (tuple('docs/' + name for name in values['DISCOVERY_FILES'])
                 + values['NATIVE_SOURCE_FILES'] + values['PUBLICATION_BUILD_FILES'])
    require(len(resources) == len(set(resources))
            and len(values['DISCOVERY_FILES']) == 11
            and len(values['NATIVE_SOURCE_FILES']) == 81
            and len(values['PUBLICATION_BUILD_FILES']) == 4
            and len(resources) == 96 and SOURCE_NAME in resources,
            'current candidate resource population differs')
    for name in resources:
        canonical_name(name)
    return values, resources


def source_inputs(source):
    hepta_names = namespace(source / 'hepta')
    require(len(hepta_names) == 170
            and sum(name.endswith('.py') for name in hepta_names) == 169
            and set(name for name in hepta_names if not name.endswith('.py'))
                == {'hia_core_lowering_abi.json'},
            'complete current hepta population differs')
    contract, _ = read(source / 'hepta/hia_agent_contract.py', 1 << 20)
    declarations, resources = declared_resources(contract)
    manifest_raw, _ = read(source / 'MANIFEST.in', 1 << 20)
    includes = []
    for line in manifest_raw.decode('utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        words = line.split()
        require(len(words) == 2 and words[0] == 'include', 'unexpected MANIFEST directive')
        includes.append(canonical_name(words[1]))
    require(len(includes) == 96 and set(includes) == set(resources),
            'sdist MANIFEST does not contain the current complete 96 resources')
    names = sorted(set('hepta/' + name for name in hepta_names)
                   | set(resources) | {'setup.py', 'pyproject.toml', 'MANIFEST.in'})
    data, rows = {}, []
    for name in names:
        raw, record = read(source / name, MAX_FILE)
        require(stat.S_IMODE(record['identity'][2]) in (0o644, 0o755),
                'source file mode differs')
        data[name] = raw
        rows.append({'path': name, **pin(raw),
                     'mode': format(stat.S_IMODE(record['identity'][2]), '04o'),
                     'identity': record['identity']})
    require(namespace(source / 'hepta') == hepta_names, 'hepta namespace changed while reading')
    return data, rows, declarations, resources


def read_owner(path):
    raw, record = read(path, 1 << 20)
    require(sha256(raw).hexdigest() == OWNER_SHA, 'original process owner changed')
    spec = importlib.util.spec_from_file_location('_pretty_install_original_owner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, record


def natural_process(raw_receipt, returned, request, command, cwd, environment, seconds):
    # Receipt bytes are preserved and hashed before parsing by owned_step.
    # Never use a reserialization as the identity of an original owner record.
    require(returned['supervisor_returncode'] == 0, 'process owner did not exit zero')
    require(request['command'] == command and request['cwd'] == str(cwd)
            and request['env'] == environment and request['qualification_seconds'] == seconds
            and request['cleanup_seconds'] == 3 and request['implementation_sha256'] == OWNER_SHA,
            'actual owned request differs')
    cleanup = raw_receipt['cleanup']
    require(raw_receipt['status'] == 'OWNED_PROCESS_COMPLETED'
            and type(raw_receipt['returncode']) is int and raw_receipt['returncode'] == 0
            and raw_receipt['qualification_seconds'] == seconds
            and raw_receipt['cleanup_seconds'] == 3
            and raw_receipt['qualification_started'] is True
            and raw_receipt['exit_observed_before_deadline'] is True
            and raw_receipt['timed_out'] is False and raw_receipt['event_overflow'] is False
            and raw_receipt['subreaper_enabled'] is True
            and raw_receipt['interrupted_signals'] == [] and raw_receipt.get('owner_error') is None
            and cleanup['complete'] is True and cleanup['observed_echild'] is True
            and cleanup['leader_reaped'] is True and cleanup['deadline_exceeded'] is False
            and cleanup['remaining_direct_children'] == [] and cleanup['errors'] == []
            and raw_receipt['events']
            and all(event['kind'] in {
                'qualification_started', 'owned_child_observed',
                'qualification_exit_observed', 'owned_child_reaped'}
                for event in raw_receipt['events']),
            'process did not complete naturally with empty owned descendants')


def owned_step(owner, root, report, label, command, cwd, environment, seconds):
    out = root / (label + '.stdout.log')
    err = root / (label + '.stderr.log')
    receipt = root / (label + '.process-owner.json')
    step = {'label': label, 'command': command, 'cwd': str(cwd),
            'qualification_seconds': seconds, 'cleanup_seconds': 3, 'status': 'HOLD',
            'original_files': []}
    report['processes'].append(step)
    returned = None
    try:
        returned = owner.run_owned(command, cwd=cwd, env=environment,
            stdout_path=out, stderr_path=err, receipt_path=receipt,
            qualification_seconds=seconds, cleanup_seconds=3)
        step['owner_returned'] = returned
    finally:
        for path in (out, err, receipt, Path(str(receipt) + '.request.json'),
                     Path(str(receipt) + '.stdout.log'), Path(str(receipt) + '.stderr.log')):
            try:
                raw, observed = read(path, 4 << 20 if path.name.endswith('.json') else 16 << 20)
                step['original_files'].append(observed)
            except BaseException as error:
                step.setdefault('custody_errors', []).append({
                    'path': str(path), 'type': type(error).__name__,
                    'traceback': traceback.format_exc()})
    require(returned is not None and not step.get('custody_errors'), 'owned process originals incomplete')
    receipt_raw, receipt_record = read(receipt, 4 << 20)
    request_raw, request_record = read(Path(str(receipt) + '.request.json'), 1 << 20)
    actual, request = json.loads(receipt_raw), json.loads(request_raw)
    require(actual['schema'] == request['schema'] == owner.SCHEMA
            and actual['request_sha256'] == sha256(request_raw).hexdigest()
            and actual['implementation_sha256'] == OWNER_SHA,
            'actual owner receipt/request binding differs')
    augmented = dict(actual, supervisor_returncode=0, receipt_sha256=sha256(receipt_raw).hexdigest())
    require(returned == augmented, 'returned owner metadata differs from actual original receipt')
    natural_process(actual, returned, request, command, cwd, environment, seconds)
    out_raw, out_record = read(out, 16 << 20)
    _, err_record = read(err, 16 << 20)
    step.update(status='OWNED_STEP_PASS', receipt=receipt_record, request=request_record,
                stdout=out_record, stderr=err_record)
    create(root / (label + '.step.json'), wire(step))
    return out_raw


def sdist_inventory(path, expected_inputs):
    raw, observed = read(path, MAX_PACKAGE_BYTES)
    rows, names, roots = [], set(), set()
    total = 0
    decoded = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        while True:
            block = compressed.read(min(1 << 20, MAX_PACKAGE_BYTES + 1 - len(decoded)))
            if not block:
                break
            decoded.extend(block)
            require(len(decoded) <= MAX_PACKAGE_BYTES, 'decoded sdist exceeds fixed archive budget')
    # Reading gzip to EOF verifies its actual CRC/trailer before tar inspection.
    with tarfile.open(fileobj=io.BytesIO(decoded), mode='r:') as archive:
        for member in archive.getmembers():
            name = member.name.rstrip('/') if member.isdir() else member.name
            canonical_name(name)
            require(name not in names, 'duplicate sdist archive member')
            names.add(name)
            roots.add(name.split('/')[0])
            require(member.isfile() or member.isdir(), 'sdist contains a link or special member')
            if member.isdir():
                continue
            require(0 <= member.size <= MAX_FILE, 'sdist member exceeds bound')
            total += member.size
            require(total <= MAX_PACKAGE_BYTES, 'decoded sdist exceeds bound')
            stream = archive.extractfile(member)
            require(stream is not None, 'regular sdist member unreadable')
            data = stream.read(member.size + 1)
            require(len(data) == member.size, 'sdist member extent differs')
            relative = name.split('/', 1)[1]
            rows.append({'path': relative, **pin(data), 'mode': format(member.mode, '04o')})
    require(len(roots) == 1, 'sdist must have one ordinary top-level directory')
    actual = {row['path']: row for row in rows}
    for name, data in expected_inputs.items():
        require(name in actual and all(actual[name][key] == value for key, value in pin(data).items()),
                'sdist lost or changed a required package input: ' + name)
    return observed, rows


def wheel_inventory(path, expected_inputs, resources):
    raw, observed = read(path, MAX_PACKAGE_BYTES)
    rows, names, total = [], set(), 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            name = info.filename.rstrip('/') if info.is_dir() else info.filename
            canonical_name(name)
            require(name not in names and not info.flag_bits & 1, 'duplicate or encrypted wheel member')
            names.add(name)
            mode = info.external_attr >> 16
            require(not stat.S_ISLNK(mode) and (info.is_dir() or mode == 0 or stat.S_ISREG(mode)),
                    'wheel link or special member is not admitted')
            if info.is_dir():
                continue
            require(info.file_size <= MAX_FILE, 'wheel member exceeds bound')
            total += info.file_size
            require(total <= MAX_PACKAGE_BYTES, 'decoded wheel exceeds bound')
            data = archive.read(info)
            require(len(data) == info.file_size, 'wheel member length differs')
            rows.append({'path': info.filename, **pin(data), 'zip_crc32': info.CRC,
                         'mode': format(stat.S_IMODE(mode), '04o')})
    actual = {row['path']: row for row in rows}
    for name, data in expected_inputs.items():
        if name.startswith('hepta/'):
            require(name in actual and all(actual[name][key] == value for key, value in pin(data).items()),
                    'wheel module/data bytes differ: ' + name)
    for name in resources:
        installed_name = 'hepta/_data/' + name
        require(installed_name in actual
                and all(actual[installed_name][key] == value for key, value in pin(expected_inputs[name]).items()),
                'wheel source-owned resource differs: ' + name)
    require({name for name in actual if name.startswith('hepta/_data/')}
            == {'hepta/_data/' + name for name in resources},
            'wheel resource namespace differs from actual tuple union')
    require({name for name in actual if name.startswith('hepta/') and name.endswith('.py')
             and not name.startswith('hepta/_data/')}
            == {name for name in expected_inputs if name.startswith('hepta/') and name.endswith('.py')},
            'wheel Python source namespace differs')
    return observed, rows


def verify_installed(rows, expected_inputs, resources):
    actual = {row['path']: row for row in rows}
    for name, raw in expected_inputs.items():
        if name.startswith('hepta/'):
            require(name in actual and all(actual[name][key] == value for key, value in pin(raw).items()),
                    'installed module bytes differ: ' + name)
    for name in resources:
        target = 'hepta/_data/' + name
        require(target in actual and all(actual[target][key] == value for key, value in pin(expected_inputs[name]).items()),
                'installed resource differs: ' + name)
    require({name for name in actual if name.startswith('hepta/_data/')}
            == {'hepta/_data/' + name for name in resources},
            'installed resource namespace differs')
    require({name for name in actual if name.startswith('hepta/') and name.endswith('.py')
             and not name.startswith('hepta/_data/')}
            == {name for name in expected_inputs if name.startswith('hepta/') and name.endswith('.py')},
            'installed Python population differs')


def run(source, evidence, python, image, compiler, child_script, *,
        source_sha256, bridge_sha256, child_sha256):
    source, evidence, python, image, compiler, child_script = map(
        Path, (source, evidence, python, image, compiler, child_script))
    root = evidence / 'installation'
    require(all(path.is_absolute() and '..' not in path.parts
                for path in (source, evidence, python, image, compiler, child_script)),
            'absolute canonical installation inputs required')
    require(not os.path.lexists(root), 'installation evidence already exists; do not replay')
    _create_directory(root)
    report = {
        'schema': 'hia.json-pretty.development-installation.v1', 'status': 'HOLD',
        'scope': 'DEVELOPMENT_INSTALLATION', 'candidate_commit': None,
        'resource_baseline': {'commit': RESOURCE_BASE_COMMIT, 'tree': RESOURCE_BASE_TREE},
        'full_tree_binding': 'The outer frozen source policy must bind the observed detached HEAD to its full tree. This helper independently reads every packaging input and installed member.',
        'source': str(source),
        'evidence': str(root), 'expected_test_ids': list(IDS), 'processes': [],
        'source_resource_count': 96, 'native_source_resource_count': 81,
        'source_python_count': 169, 'native_compilation_performed_here': False,
        'formal_cold_qualification': False, 'CLI_replacement_tested': False,
        'whole_native_delivery_qualified': False, 'errors': [],
    }
    before_inputs = None
    immutable_before = None
    installed_before = None
    source_head_before = source_head_raw = None
    try:
        require(python.resolve() == Path(sys.executable).resolve()
                and sys.version_info[:3] == (3, 14, 4),
                'package tool interpreter differs from controlled Python')
        source_head_raw, source_head_before = read(source / '.git' / 'HEAD', 128)
        require(len(source_head_raw) == 41 and source_head_raw[-1:] == b'\n'
                and all(value in b'0123456789abcdef' for value in source_head_raw[:-1]),
                'actual source HEAD must be a detached full Git identity')
        report['source_head_original'] = source_head_before
        report['source_head'] = source_head_raw[:-1].decode('ascii')
        report['candidate_commit'] = report['source_head']
        original_owner = Path(__file__).absolute().parent / 'process_owner_impl.py'
        owner, owner_record = read_owner(original_owner)
        report['owner_implementation'] = owner_record
        inputs, before_inputs, declarations, resources = source_inputs(source)
        require(sha256(inputs[SOURCE_NAME]).hexdigest() == source_sha256
                and sha256(inputs[BRIDGE_NAME]).hexdigest() == bridge_sha256,
                'actual candidate pretty source or bridge SHA differs')
        report['source_inputs_before'] = before_inputs
        report['actual_resource_declarations'] = {key: list(value) for key, value in declarations.items()}
        immutable_before = {}
        for name, path in (('image', image), ('compiler', compiler), ('child_script', child_script),
                           ('python', python.resolve())):
            raw, record = read(path, MAX_FILE, system_binary=name == 'python')
            immutable_before[name] = record
            if name == 'image':
                require(0 < len(raw) <= 1 << 20, 'native image outside original image profile')
                image_raw = raw
            elif name == 'child_script':
                require(sha256(raw).hexdigest() == child_sha256, 'installed child control SHA differs')
                child_raw = raw
        report['immutable_inputs_before'] = immutable_before
        for name in ('package-source', 'sdist', 'wheels', 'native', 'control', 'consumer-cwd', 'invalid-manifests'):
            _create_directory(root / name)
        packaging = root / 'package-source'
        for name, data in inputs.items():
            target = packaging / name
            ensure_directory(target.parent, packaging)
            _create_bytes(target, data, int(next(row['mode'] for row in before_inputs if row['path'] == name), 8))
        environment = {
            'PATH': str(python.resolve().parent) + ':/usr/bin:/bin',
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1', 'PIP_NO_INDEX': '1',
            'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_CONFIG_FILE': '/dev/null',
        }
        versions = owned_step(owner, root, report, 'packaging-tools',
            [str(python), '-I', '-B', '-c',
             'import importlib.metadata,json;print(json.dumps({k:importlib.metadata.version(k) for k in ("pip","setuptools","wheel")},sort_keys=True))'],
            root / 'consumer-cwd', environment, 15)
        tool_versions = json.loads(versions)
        require(tool_versions['setuptools'] == '78.1.1' and tool_versions['wheel'] == '0.46.3',
                'fixed installed packaging versions differ')
        report['packaging_versions'] = tool_versions
        owned_step(owner, root, report, 'sdist',
            [str(python), '-I', '-B', 'setup.py', 'sdist', '--dist-dir', str(root / 'sdist')],
            packaging, environment, 120)
        sdist_files = list((root / 'sdist').iterdir())
        require(len(sdist_files) == 1 and sdist_files[0].name.endswith('.tar.gz'), 'one actual sdist required')
        sdist_record, sdist_rows = sdist_inventory(sdist_files[0], inputs)
        report['sdist'] = sdist_record
        report['sdist_members'] = sdist_rows
        owned_step(owner, root, report, 'wheel',
            [str(python), '-I', '-B', '-m', 'pip', '--isolated', 'wheel',
             '--no-cache-dir', '--no-deps', '--no-index', '--no-build-isolation',
             '--wheel-dir', str(root / 'wheels'), str(sdist_files[0])],
            root / 'consumer-cwd', environment, 120)
        wheels = list((root / 'wheels').iterdir())
        require(len(wheels) == 1 and wheels[0].suffix == '.whl', 'one actual wheel required')
        wheel_record, wheel_rows = wheel_inventory(wheels[0], inputs, resources)
        report['wheel'] = wheel_record
        report['wheel_members'] = wheel_rows
        installed = root / 'installed'
        require(not os.path.lexists(installed), 'pip target must be new')
        owned_step(owner, root, report, 'install',
            [str(python), '-I', '-B', '-m', 'pip', '--isolated', 'install',
             '--no-cache-dir', '--no-deps', '--no-index', '--no-compile',
             '--target', str(installed), str(wheels[0])],
            root / 'consumer-cwd', environment, 120)
        installed_before = inventory(installed)
        verify_installed(installed_before, inputs, resources)
        report['installed_before'] = installed_before
        native_image = root / 'native' / 'native.bin'
        copied_image = create(native_image, image_raw)
        manifest = {
            'schema': 'hepta.hia.json-pretty-native.v1', 'source_sha256': source_sha256,
            'image_path': native_image.name, 'image_sha256': immutable_before['image']['sha256'],
            'compiler_sha256': immutable_before['compiler']['sha256'],
        }
        manifest_path = root / 'native' / 'manifest.json'
        manifest_record = create(manifest_path, wire(manifest))
        executed_script = root / 'control' / 'installed_cases.py'
        script_record = create(executed_script, child_raw)
        request = {
            'schema': 'hia.json-pretty.installed-request.v1', 'scope': 'DEVELOPMENT_INSTALLATION',
            'candidate_commit': report['source_head'],
            'source_head_original': source_head_before,
            'installation_root': str(root), 'installed_root': str(installed),
            'manifest_path': str(manifest_path), 'manifest_original': manifest_record,
            'image_original': copied_image, 'compiler_input': immutable_before['compiler'],
            'source_sha256': source_sha256, 'bridge_sha256': bridge_sha256,
            'child_script': script_record, 'source_checkout': str(source),
            'source_resource': SOURCE_NAME, 'expected_test_ids': list(IDS),
            'expected_native_completions': 14,
            'installed_before': installed_before,
            'module_names': sorted(name for name in inputs if name.startswith('hepta/') and name.endswith('.py')),
            'resource_names': list(resources),
            'output': str(root / 'installed-cases.json'),
            'qualification_seconds': 5, 'cleanup_seconds': 3,
            'formal_cold_qualification': False, 'CLI_replacement_tested': False,
        }
        request_record = create(root / 'installed-request.json', wire(request))
        report.update(installed_root=str(installed), bridge_path=str(installed / BRIDGE_NAME),
                      manifest_path=str(manifest_path), manifest=manifest_record,
                      native_image=copied_image, executed_child=script_record,
                      installed_request=request_record)
        child_environment = {'PATH': '', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                             'PYTHONDONTWRITEBYTECODE': '1'}
        owned_step(owner, root, report, 'installed-child',
            [str(python), '-I', '-S', '-B', str(executed_script),
             '--request', str(root / 'installed-request.json'),
             '--request-sha256', request_record['sha256']],
            root / 'consumer-cwd', child_environment, 5)
        child_result_raw, child_result_record = read(root / 'installed-cases.json', 4 << 20)
        child_result = json.loads(child_result_raw)
        report['installed_cases'] = child_result_record
        require(child_result['schema'] == 'hia.json-pretty.installed-cases.v1'
                and child_result['status'] == 'DEVELOPMENT_INSTALLED_CASES_PASS'
                and child_result['request_sha256'] == request_record['sha256']
                and child_result['expected_test_ids'] == list(IDS)
                and child_result['loaded_test_ids'] == list(IDS)
                and child_result['executed_test_ids'] == list(IDS)
                and child_result['tests_run'] == 9
                and all(child_result[name] == 0 for name in (
                    'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
                and child_result['native_completions'] == 14
                and child_result['forbidden_authoring_attempts'] == []
                and child_result['forbidden_host_layout_attempts'] == []
                and child_result['isolated_no_site'] is True and child_result['empty_PATH'] is True,
                'actual installed child complete result differs')
        report['status'] = 'DEVELOPMENT_INSTALLATION_PENDING_FINAL_INPUT_CHECK'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['errors'].append({'stage': 'INSTALLATION', 'type': type(error).__name__,
                                 'traceback': traceback.format_exc()})
    finally:
        try:
            _, after_inputs, _, _ = source_inputs(source)
            report['source_inputs_after'] = after_inputs
            require(before_inputs is not None and after_inputs == before_inputs,
                    'source-owned package inputs changed')
            head_after, source_head_after = read(source / '.git' / 'HEAD', 128)
            report['source_head_after'] = source_head_after
            require(source_head_before is not None and source_head_after == source_head_before
                    and head_after == source_head_raw, 'source checkout HEAD changed')
            if immutable_before is not None:
                immutable_after = {}
                for name, path in (('image', image), ('compiler', compiler), ('child_script', child_script),
                                   ('python', python.resolve())):
                    _, immutable_after[name] = read(path, MAX_FILE, system_binary=name == 'python')
                report['immutable_inputs_after'] = immutable_after
                require(immutable_after == immutable_before, 'fresh image/compiler/control inputs changed')
            if installed_before is not None:
                after_installed = inventory(root / 'installed')
                report['installed_after'] = after_installed
                report['installed_bytes_and_modes_restored'] = (
                    byte_projection(after_installed) == byte_projection(installed_before))
                require(report['installed_bytes_and_modes_restored'],
                        'installed source/resource bytes or modes were not restored')
            if 'manifest' in report:
                _, current_manifest = read(Path(report['manifest_path']), 16384)
                _, current_image = read(Path(report['native_image']['path']), 1 << 20)
                require(current_manifest == report['manifest'] and current_image == report['native_image'],
                        'development manifest/image changed')
            for archive_name in ('sdist', 'wheel'):
                if archive_name in report:
                    _, archive_after = read(Path(report[archive_name]['path']), MAX_PACKAGE_BYTES)
                    require(archive_after == report[archive_name],
                            'actual built archive changed: ' + archive_name)
            if 'owner_implementation' in report:
                _, current_owner = read(Path(report['owner_implementation']['path']), 1 << 20)
                require(current_owner == report['owner_implementation'], 'original owner source changed')
            report['source_and_inputs_stable'] = True
            if report['status'] == 'DEVELOPMENT_INSTALLATION_PENDING_FINAL_INPUT_CHECK':
                report['status'] = 'DEVELOPMENT_INSTALLATION_PASS'
        except BaseException as error:
            report['status'] = 'HOLD'
            report['errors'].append({'stage': 'FINAL_INPUTS', 'type': type(error).__name__,
                                     'traceback': traceback.format_exc()})
        create(root / 'package-report.json', wire(report))
    if report['status'] != 'DEVELOPMENT_INSTALLATION_PASS':
        raise RuntimeError('Pretty development installation HOLD; original report: ' + str(root / 'package-report.json'))
    return report
