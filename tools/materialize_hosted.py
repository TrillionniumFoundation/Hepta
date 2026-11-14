"""Prepare the frozen R2 input; only explicit launch invokes its original gate."""
from pathlib import Path
import argparse
import base64
import copy
import errno
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import sysconfig
import time
import traceback
import zlib

HARNESS = Path(__file__).resolve().parents[1]
INPUTS = HARNESS / 'inputs'
BASE_COMMIT = '26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d'
BASE_TREE = '84df4b42f1e20fd7d0c7229e658cf3b458984ffb'
TARGET_TREE = '4c62be4ed66ff107fa6f88c6131313a354868bd9'
FREE_FLOOR = 3221225472
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
DOCS = {'generation': 'GENERATION-EXECUTION-PLAN.json',
        'storage': 'C0-EXECUTION-PLAN-R2.json',
        'projection': 'authoring/full-qualification-r2/PROJECTION-PROOF.json',
        'full': 'FULL-QUALIFICATION-EXECUTION-PLAN-R2.json'}


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def pin(raw, mode=0o644):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': mode, 'git_mode': '100755' if mode & 0o111 else '100644'}


def stamp(value):
    return {name: getattr(value, name) for name in FIELDS}


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and all(part not in ('.', '..') for part in path.parts),
            'absolute ordinary path required')
    return path


def relative(name):
    parts = name.split('/')
    require(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in parts),
            'unsafe relative material path')
    return Path(*parts)


def open_directory(path, *, create=False):
    path = absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    try:
        for part in path.parts[1:]:
            parent = descriptors[-1]
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=parent)
            descriptors.append(child)
            links.append((parent, part, child))
        return descriptors, links
    except BaseException:
        for fd in reversed(descriptors):
            os.close(fd)
        raise


def guard_directories(links):
    for parent, name, child in links:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(child)
        require(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino, current.st_mode)
                == (opened.st_dev, opened.st_ino, opened.st_mode), 'directory binding changed')


def directory(path, *, new=False):
    path = absolute(path)
    if new:
        descriptors, links = open_directory(path.parent, create=True)
        try:
            os.mkdir(path.name, 0o700, dir_fd=descriptors[-1])
            guard_directories(links)
        finally:
            for fd in reversed(descriptors):
                os.close(fd)
    descriptors, links = open_directory(path, create=True)
    try:
        guard_directories(links)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def read_regular(path):
    path = absolute(path)
    descriptors, links = open_directory(path.parent)
    fd = None
    try:
        parent = descriptors[-1]
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode), 'nonregular file: ' + str(path))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        opened = os.fstat(fd)
        require(stamp(opened) == stamp(before), 'file changed before capture')
        chunks, remaining = [], opened.st_size + 1
        while remaining:
            block = os.read(fd, min(1 << 20, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b''.join(chunks)
        ended = os.fstat(fd)
        after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        guard_directories(links)
        require(len(raw) == opened.st_size and stamp(before) == stamp(ended) == stamp(after),
                'file changed during bounded capture')
        return raw, pin(raw, stat.S_IMODE(opened.st_mode)), stamp(opened)
    finally:
        if fd is not None:
            os.close(fd)
        for fd in reversed(descriptors):
            os.close(fd)


def write_new(path, raw, mode=0o644):
    path = absolute(path)
    descriptors, links = open_directory(path.parent, create=True)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=descriptors[-1])
        view = memoryview(raw)
        while view:
            done = os.write(fd, view)
            require(done > 0, 'short evidence write')
            view = view[done:]
        os.fchmod(fd, mode)
        guard_directories(links)
    finally:
        if fd is not None:
            os.close(fd)
        for fd in reversed(descriptors):
            os.close(fd)


def dump(path, value):
    write_new(path, encode(value))


def load(path):
    return json.loads(read_regular(path)[0])


def tree(rows):
    root = {}
    for name, row in rows.items():
        current = root
        parts = relative(name).parts
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        require(parts[-1] not in current, 'duplicate tree leaf')
        current[parts[-1]] = (row['git_mode'], row['git_blob'])
    def digest(node):
        raw = b''
        for name, row in sorted(node.items(), key=lambda item:
                               (item[0] + ('/' if type(item[1]) is dict else '')).encode()):
            mode, value = ('40000', digest(row)) if type(row) is dict else row
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(value)
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return digest(root)


def harness_guard():
    raw, identity, _ = read_regular(INPUTS / 'HARNESS-INDEX.json')
    data = json.loads(raw)
    observed = {}
    for name, expected in data['files'].items():
        _, actual, _ = read_regular(HARNESS / relative(name))
        require(actual == expected, 'authored harness input changed: ' + name)
        observed[name] = actual
    return {'index': identity, 'files': observed}


def material_payload():
    index = load(INPUTS / 'MATERIAL-INDEX.json')
    pieces = []
    for row in index['parts']:
        raw, actual, _ = read_regular(INPUTS / relative(row['path']))
        require(actual == row['identity'], 'material part wrapper changed')
        decoded = base64.b64decode(raw, validate=True)
        require(pin(decoded) == row['decoded_identity'], 'material part decode differs')
        pieces.append(decoded)
    compressed = b''.join(pieces)
    require(pin(compressed) == index['compressed_identity'], 'complete material stream differs')
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, index['payload_identity']['bytes'] + 1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and pin(raw) == index['payload_identity'], 'material payload is not exact complete zlib')
    data = json.loads(raw)
    files = {}
    for row in data['files']:
        name = row['path']
        relative(name)
        require(name not in files, 'duplicate material path')
        content = row['text'].encode('utf-8')
        require(pin(content, row['identity']['mode']) == row['identity'], 'material bytes differ')
        files[name] = (content, row['identity'])
    require(len(files) == index['file_count'] and sum(len(v[0]) for v in files.values()) == index['logical_bytes'],
            'material inventory differs')
    return files, index


def run_recorded(argv, cwd, env, out, label, timeout=30):
    dump(out / (label + '.REQUEST.json'), {'argv': argv, 'cwd': str(cwd), 'environment': env,
                                         'timeout_seconds': timeout, 'product_operation': False})
    record = {'returncode': None, 'timed_out': False}
    try:
        with (out / (label + '.stdout.bin')).open('xb') as stdout, (out / (label + '.stderr.bin')).open('xb') as stderr:
            result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=timeout)
        record['returncode'] = result.returncode
    except BaseException as error:
        record.update(timed_out=isinstance(error, subprocess.TimeoutExpired),
                      error_type=type(error).__name__, error=str(error))
        raise
    finally:
        dump(out / (label + '.EXIT.json'), record)
    require(record['returncode'] == 0, 'preparation subprocess failed: ' + label)
    return read_regular(out / (label + '.stdout.bin'))[0]


def prepare(args, out):
    scope, baseline = absolute(args.scope), absolute(args.baseline)
    require(os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'one hosted attempt only; workflow rerun is not authorized by this plan')
    require(not scope.exists() and not scope.is_symlink(), 'new isolated scope required')
    controls = harness_guard()
    files, index = material_payload()
    target = json.loads(files['plan/SOURCE-MATERIALIZATION.json'][0])
    base = json.loads(files['plan/BASE-MANIFEST.json'][0])
    require(len(base) == 3177 and tree(base) == BASE_TREE, 'base manifest differs')
    require(target['target_files'] == 3180 and target['target_tree'] == TARGET_TREE
            and tree(target['target_manifest']) == TARGET_TREE, 'frozen R2 target differs')
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    commit = run_recorded(['/usr/bin/git', 'rev-parse', 'HEAD'], baseline, env, out, 'git-head').decode().strip()
    tree_id = run_recorded(['/usr/bin/git', 'rev-parse', 'HEAD^{tree}'], baseline, env, out, 'git-tree').decode().strip()
    require(commit == BASE_COMMIT and tree_id == BASE_TREE, 'actual checked-out base commit/tree differs')
    listing = run_recorded(['/usr/bin/git', 'ls-tree', '-rz', '--full-tree', 'HEAD'], baseline, env, out, 'git-leaves')
    tracked = {}
    for item in listing.split(b'\0'):
        if not item:
            continue
        header, name = item.split(b'\t', 1)
        mode, kind, digest = header.decode().split(' ')
        name = name.decode('utf-8')
        require(kind == 'blob' and mode in ('100644', '100755') and name not in tracked, 'unexpected tracked node')
        tracked[name] = (mode, digest)
    require(tracked == {name: (row['git_mode'], row['git_blob']) for name, row in base.items()},
            'published base leaf identity set differs')
    directory(scope, new=True)
    for name, (raw, identity) in files.items():
        if name.startswith('scope/') and not name.startswith('scope/candidate/source/'):
            write_new(scope / relative(name[6:]), raw, identity['mode'])
        elif name.startswith('custody/'):
            write_new(scope / 'hosted-custody' / relative(name[8:]), raw, identity['mode'])
        elif name.startswith('plan/'):
            write_new(scope / 'hosted-plan' / relative(name[5:]), raw, identity['mode'])
    observed_base, observed_target = {}, {}
    wanted = target['target_manifest']
    for name, expected in base.items():
        raw, identity, _ = read_regular(baseline / relative(name))
        require(identity == expected, 'actual base byte/mode mismatch: ' + name)
        observed_base[name] = identity
        if name in wanted and wanted[name] == expected:
            write_new(scope / 'candidate/source' / relative(name), raw, identity['mode'])
    for row in target['changes']:
        if row['after'] is None:
            require(not (scope / 'candidate/source' / relative(row['path'])).exists(), 'R2 absence not preserved')
            continue
        raw, identity = files['scope/candidate/source/' + row['path']]
        require(identity == row['after'], 'listed after-image differs')
        write_new(scope / 'candidate/source' / relative(row['path']), raw, identity['mode'])
    for name, expected in wanted.items():
        _, actual, _ = read_regular(scope / 'candidate/source' / relative(name))
        require(actual == expected, 'actual target byte/mode mismatch: ' + name)
        observed_target[name] = actual
    actual_paths = set()
    for folder, dirs, names in os.walk(scope / 'candidate/source', followlinks=False):
        for name in dirs:
            require(stat.S_ISDIR((Path(folder) / name).lstat().st_mode), 'nonordinary target directory')
        actual_paths.update((Path(folder) / name).relative_to(scope / 'candidate/source').as_posix() for name in names)
    require(actual_paths == set(wanted) and tree(observed_target) == TARGET_TREE, 'complete target inventory differs')
    dump(out / 'BASE-ACTUAL.json', observed_base)
    dump(out / 'TARGET-ACTUAL.json', observed_target)
    require(harness_guard() == controls, 'harness changed during preparation')
    return {'status': 'FIXED_R2_SOURCE_MATERIALIZED_NOT_EXECUTED', 'source_files': len(observed_target),
            'source_tree': tree(observed_target), 'base_commit': commit, 'base_tree': tree_id,
            'material_index': index, 'harness_controls': controls, 'product_invocations': 0}


def capture_runtime():
    require(sys.version_info[:3] == (3, 14, 4) and sys.platform == 'linux'
            and platform.python_implementation() == 'CPython'
            and platform.machine() in ('x86_64', 'AMD64'), 'actual Linux x86_64 CPython 3.14.4 required')
    executable = absolute(sys.executable)
    mappings = Path('/proc/self/maps').read_text()
    candidates = set()
    for line in mappings.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and 'libpython3.14' in fields[5]:
            require(not fields[5].endswith(' (deleted)'), 'deleted loaded libpython')
            candidates.add(fields[5])
    require(len(candidates) == 1, 'unique actual libpython required')
    library = absolute(next(iter(candidates)))
    declared = {sysconfig.get_config_var(key) for key in ('LDLIBRARY', 'INSTSONAME')}
    require(library.name in declared, 'mapped libpython differs from runtime declaration')
    result = {'executable': {'path': str(executable)}, 'library': {'path': str(library)}}
    for key in ('executable', 'library'):
        _, identity, identity_stat = read_regular(Path(result[key]['path']))
        result[key].update(identity=identity, stat=identity_stat)
    return {'runtime': result, 'version': sys.version, 'sys_executable': sys.executable,
            'proc_maps': mappings, 'platform': platform.platform(),
            'sysconfig': {key: sysconfig.get_config_var(key) for key in ('LDLIBRARY', 'INSTSONAME', 'LIBDIR', 'Py_ENABLE_SHARED')},
            'credentials_or_ambient_environment_recorded': False}


def pointer_value(doc, parts):
    for part in parts:
        doc = doc[part]
    return doc


def replace_pointer(doc, parts, value):
    pointer_value(doc, parts[:-1])[parts[-1]] = value


def capture_copied_materials(scope, files, *, bound=False):
    """Capture copied controls against the immutable capsule before consumption."""
    captures, records = {}, {}
    copied_documents = set(DOCS.values())
    for name, (expected_raw, expected_identity) in files.items():
        if name.startswith('scope/') and not name.startswith('scope/candidate/source/'):
            suffix = name[6:]
            path = scope / relative(suffix)
            if bound and suffix in copied_documents:
                path = path.with_name(path.name + '.hosted-original')
        elif name.startswith('custody/'):
            path = scope / 'hosted-custody' / relative(name[8:])
        elif name.startswith('plan/'):
            path = scope / 'hosted-plan' / relative(name[5:])
        else:
            continue
        raw, actual, observed_stat = read_regular(path)
        require(raw == expected_raw and actual == expected_identity,
                'copied fixed material differs from capsule: ' + name)
        captures[name] = (raw, actual, observed_stat)
        records[name] = {'path': str(path), 'identity': actual, 'stat': observed_stat}
    return captures, records


def bind(args, out):
    scope = absolute(args.scope)
    archive_root = absolute(args.archives)
    prepared = load(absolute(args.evidence) / 'prepare/RESULT.json')
    require(prepared['status'] == 'FIXED_R2_SOURCE_MATERIALIZED_NOT_EXECUTED', 'preparation did not complete')
    controls = harness_guard()
    require(controls == prepared['harness_controls'], 'prepared harness controls changed')
    fixed_files, material_index = material_payload()
    require(material_index == prepared['material_index'], 'prepared material capsule changed')
    captured, material_before = capture_copied_materials(scope, fixed_files)
    dump(out / 'FIXED-MATERIALS-BEFORE.json', material_before)
    allow = json.loads(captured['plan/JSON-POINTER-ALLOWLIST.json'][0])
    archive_report_raw, archive_report_identity, _ = read_regular(archive_root / 'VERIFIED-ARCHIVES.json')
    records = json.loads(archive_report_raw)
    require(records['status'] == 'TWO_ORIGINAL_ZIPS_FULL_SHA_AND_ALL_MEMBER_CRC_PASS', 'original ZIP verification is incomplete')
    require(records['harness_controls'] == controls, 'archive verifier harness differs')
    old_policy = json.loads(captured['scope/' + DOCS['storage']][0])['completed_artifact_storage']
    require(set(records['archives']) == {row['key'] for row in old_policy['archives']}, 'original ZIP set differs')
    for row in old_policy['archives']:
        item = records['archives'][row['key']]
        require(item['path'] == str(archive_root / row['original']['file'])
                and item['identity'] == row['original']
                and item['full_crc_verified'] is True
                and item['run_id'] == 43553551892 and item['head_sha'] == '28b8e6f5b44022f9d6e90d561573d41f0f7e8633'
                and item['artifact_id'] == row['transfer']['record']['artifact_id'], 'actual ZIP binding differs')
    write_new(out / 'ACTUAL-ZIP-VERIFICATION.json', archive_report_raw)
    current = capture_runtime()
    runtime = {key: {k: value[k] for k in ('path', 'identity')} for key, value in current['runtime'].items()}
    environment = {'HOME': str(scope), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'LD_LIBRARY_PATH': str(Path(runtime['library']['path']).parent),
        'PATH': '/usr/local/bin:/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1', 'TZ': 'UTC'}
    probe_raw = run_recorded([runtime['executable']['path'], '-I', '-S', '-B', str(Path(__file__).resolve()),
                             'capture-runtime'], scope, environment, out, 'runtime-clean-context')
    probe = json.loads(probe_raw)
    require(probe['runtime'] == current['runtime'] and probe['sys_executable'] == runtime['executable']['path'],
            'clean child runtime differs from actual selected interpreter')
    dump(out / 'RUNTIME-CAPTURE.json', current)
    toolchain = {}
    for name in ('as', 'cc', 'ld', 'objdump', 'readelf'):
        selected = shutil.which(name, path=environment['PATH'])
        require(selected is not None and Path(selected).is_absolute(), 'host tool is absent')
        resolved = Path(selected).resolve(strict=True)
        _, identity, identity_stat = read_regular(resolved)
        version = run_recorded([selected, '--version'], scope, environment, out, 'tool-' + name)
        if name == 'ld':
            require(version.startswith(b'GNU ld '), 'original B0 requires actual GNU ld')
        toolchain[name] = {'selected_path': selected, 'path': str(resolved), 'identity': identity}
        dump(out / ('tool-' + name + '.IDENTITY.json'), dict(toolchain[name], stat=identity_stat))
    rebound_identities, changes, bound_documents = {}, {}, {}
    def resolve(spec):
        kind = spec['kind']
        if kind == 'scope_path':
            suffix = spec['suffix']
            require(not suffix or suffix.startswith('/'), 'invalid anchored scope suffix')
            return str(scope) + suffix
        if kind == 'environment_assignment':
            return spec['key'] + '=' + environment[spec['key']]
        if kind == 'runtime_path':
            return runtime[spec['key']]['path']
        if kind == 'runtime_library_parent':
            return environment['LD_LIBRARY_PATH']
        if kind == 'runtime':
            return copy.deepcopy(runtime[spec['key']][spec['field']])
        if kind == 'toolchain':
            return copy.deepcopy(toolchain[spec['tool']][spec['field']])
        if kind == 'rebound_json_identity':
            return copy.deepcopy(rebound_identities[spec['document']])
        if kind == 'custody_path':
            return str(scope / 'hosted-custody' / relative(spec['file']))
        if kind == 'archive_path':
            return records['archives'][spec['key']]['path']
        if kind == 'verified_archive_stat':
            return records['archives'][spec['key']]['post_verification_stat'][spec['field']]
        raise AssertionError('unrecognized binding source')
    for name in ('generation', 'storage', 'projection', 'full'):
        path = scope / DOCS[name]
        raw, original_identity, _ = captured['scope/' + DOCS[name]]
        expected = allow['documents'][name]
        require(original_identity == expected['original_identity'], 'original binding document changed')
        original = json.loads(raw)
        require(encode(original) == raw, 'original JSON serialization differs')
        bound = copy.deepcopy(original)
        rows = []
        for row in expected['pointers']:
            require(pointer_value(bound, row['parts']) == row['before'], 'pointer preimage differs')
            actual = resolve(row['after_from_actual_context'])
            replace_pointer(bound, row['parts'], actual)
            rows.append({'pointer': row['pointer'], 'parts': row['parts'], 'before': row['before'], 'after': actual})
        inverse = copy.deepcopy(bound)
        for row in reversed(rows):
            require(pointer_value(inverse, row['parts']) == row['after'], 'pointer after-image differs')
            replace_pointer(inverse, row['parts'], row['before'])
        require(encode(inverse) == raw, 'unlisted JSON mutation or inverse mismatch')
        write_new(out / ('ORIGINAL-' + name + '.json'), raw, original_identity['mode'])
        # Retire only this copied pathname in the new CI scope, retaining its
        # exact preimage. Original workstation documents are never changed.
        original_path = path.with_name(path.name + '.hosted-original')
        require(not original_path.exists(), 'unique binding attempt required')
        path.rename(original_path)
        saved_raw, saved_identity, _ = read_regular(original_path)
        require(saved_raw == raw and saved_identity == original_identity, 'copied JSON changed after capture')
        write_new(path, encode(bound), original_identity['mode'])
        after_raw, after_identity, _ = read_regular(path)
        require(after_raw == encode(bound), 'bound JSON write/readback differs')
        rebound_identities[name] = after_identity
        bound_documents[name] = bound
        changes[name] = {'original': original_identity, 'bound': after_identity, 'changes': rows,
                         'inverse_full_bytes_exact': True}
    full = bound_documents['full']
    require(full['source_files'] == 3180 and full['source_tree'] == TARGET_TREE
            and full['budgets']['qualification_seconds'] == 180 and full['budgets']['cleanup_seconds'] == 3
            and full['storage']['required_free_bytes'] == FREE_FLOOR, 'original gate constraints changed')
    require(full['environment'] == environment and full['runtime'] == runtime and full['toolchain'] == toolchain,
            'context fields do not agree')
    for name, record in full['controls'].items():
        require(read_regular(Path(record['path']))[1] == record['identity'], 'final actual control binding differs: ' + name)
    for name, item in records['archives'].items():
        require(stamp(Path(item['path']).lstat()) == item['post_verification_stat'], 'verified ZIP identity changed')
    _, material_after = capture_copied_materials(scope, fixed_files, bound=True)
    dump(out / 'FIXED-MATERIALS-AFTER.json', material_after)
    require(capture_runtime()['runtime'] == current['runtime'], 'runtime drift during binding')
    require(harness_guard() == controls, 'harness drift during binding')
    require(read_regular(archive_root / 'VERIFIED-ARCHIVES.json')[1] == archive_report_identity,
            'actual ZIP verification record changed')
    free = shutil.disk_usage(scope).free
    require(free >= FREE_FLOOR, 'original 3 GiB instantaneous floor not met')
    dump(out / 'JSON-BINDING-READBACK.json', changes)
    return {'status': 'ACTUAL_HOSTED_BINDINGS_FROZEN_PRODUCT_NOT_EXECUTED',
            'scope': str(scope), 'full_plan_identity': rebound_identities['full'],
            'source_files': 3180, 'source_tree': TARGET_TREE,
            'runtime': current, 'toolchain': toolchain, 'environment': environment,
            'harness_controls': controls, 'free_bytes': free, 'required_free_bytes': FREE_FLOOR,
            'pointer_counts': {name: len(item['changes']) for name, item in changes.items()},
            'product_invocations': 0}


def launch(args, out):
    scope = absolute(args.scope)
    binding = load(absolute(args.evidence) / 'bind/RESULT.json')
    require(binding['status'] == 'ACTUAL_HOSTED_BINDINGS_FROZEN_PRODUCT_NOT_EXECUTED', 'hosted binding did not complete')
    raw, identity, _ = read_regular(scope / DOCS['full'])
    require(identity == binding['full_plan_identity'], 'final bound plan changed')
    plan = json.loads(raw)
    require(plan['source_tree'] == TARGET_TREE and plan['storage']['required_free_bytes'] == FREE_FLOOR,
            'wrong frozen gate')
    require(harness_guard() == binding['harness_controls'], 'harness changed before launch')
    require(shutil.disk_usage(scope).free >= FREE_FLOOR, 'original launch space floor not met')
    require(not Path(plan['evidence']).exists(), 'original gate evidence already exists; no retry')
    request = {'argv': plan['argv'], 'cwd': plan['cwd'], 'environment_transport': {},
               'effective_clean_environment': plan['environment'],
               'bound_plan_identity': identity, 'started_monotonic_ns': time.monotonic_ns(),
               'product_gate_owner_seconds': 180, 'cleanup_seconds': 3}
    dump(out / 'REQUEST.json', request)
    with (out / 'stdout.bin').open('xb') as stdout, (out / 'stderr.bin').open('xb') as stderr:
        process = subprocess.Popen(plan['argv'], cwd=plan['cwd'], env={}, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        dump(out / 'STARTED.json', {'pid': process.pid, 'monotonic_ns': time.monotonic_ns()})
        returncode = process.wait()
    result = {'status': 'GATE_PROCESS_TERMINATED', 'returncode': returncode,
              'ended_monotonic_ns': time.monotonic_ns(), 'product_invocations': 1,
              'workflow_exit': returncode if returncode >= 0 else 128 - returncode,
              'ordinary_current_cold_R8_aggregate_whole_authority': False}
    dump(out / 'PROCESS-EXIT.json', result)
    require(returncode == 0, 'original full gate returned nonzero; all partial evidence retained')
    original = load(Path(plan['evidence']) / 'OUTER.json')
    require(original['status'] == 'PASS_EXPLICIT_U32_FULL_QUALIFICATION_ONLY', 'original outer result is not PASS')
    result['status'] = 'ORIGINAL_R2_PROCESS_AND_OUTER_PASS_FIXED_SCOPE_ONLY'
    return result


def collect_file(path, target, before):
    """Preserve actual bytes after termination; no symlink is followed."""
    source_dirs, source_links = open_directory(path.parent)
    target_dirs, target_links = open_directory(target.parent, create=True)
    source_fd = target_fd = None
    try:
        source_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                            dir_fd=source_dirs[-1])
        opened = os.fstat(source_fd)
        require(stat.S_ISREG(opened.st_mode) and stamp(opened) == stamp(before), 'collection source changed before open')
        method = 'hardlink-after-gate'
        try:
            os.link(path.name, target.name, src_dir_fd=source_dirs[-1], dst_dir_fd=target_dirs[-1], follow_symlinks=False)
            linked = os.stat(target.name, dir_fd=target_dirs[-1], follow_symlinks=False)
            if not stat.S_ISREG(linked.st_mode) or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino):
                os.unlink(target.name, dir_fd=target_dirs[-1])
                raise AssertionError('collection hardlink did not bind the captured ordinary file')
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
            method = 'stream-copy-after-gate'
            target_fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                stat.S_IMODE(opened.st_mode), dir_fd=target_dirs[-1])
        digest = hashlib.sha256()
        git = hashlib.sha1(b'blob ' + str(opened.st_size).encode() + b'\0')
        total, remaining = 0, opened.st_size + 1
        while remaining:
            block = os.read(source_fd, min(1 << 20, remaining))
            if not block:
                break
            total += len(block)
            remaining -= len(block)
            require(total <= opened.st_size, 'collection source grew')
            digest.update(block)
            git.update(block)
            if target_fd is not None:
                view = memoryview(block)
                while view:
                    done = os.write(target_fd, view)
                    require(done > 0, 'short collection copy')
                    view = view[done:]
        if target_fd is not None:
            os.fchmod(target_fd, stat.S_IMODE(opened.st_mode))
        ended = os.fstat(source_fd)
        named = os.stat(path.name, dir_fd=source_dirs[-1], follow_symlinks=False)
        guard_directories(source_links)
        guard_directories(target_links)
        stable = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns')
        require(total == opened.st_size and all(getattr(before, key) == getattr(ended, key) == getattr(named, key)
                for key in stable), 'collection source identity or bytes changed')
        require(ended.st_nlink == named.st_nlink, 'collection source link count changed after capture')
        if method == 'stream-copy-after-gate':
            require(before.st_ctime_ns == ended.st_ctime_ns, 'cross-filesystem source changed')
        # A hardlink changes ctime/nlink after the product has terminated. Keep
        # both observations; never rewrite an original product receipt.
        return {'bytes': total, 'sha256': digest.hexdigest(), 'git_blob': git.hexdigest(),
                'transport': method, 'stat_after': stamp(ended), 'nlink_after': ended.st_nlink}
    finally:
        for fd in (target_fd, source_fd):
            if fd is not None:
                os.close(fd)
        for fd in reversed(target_dirs + source_dirs):
            os.close(fd)


def collect(args, out):
    scope, evidence = absolute(args.scope), absolute(args.evidence)
    destination, archives = absolute(args.collection), absolute(args.archives)
    directory(destination, new=True)
    records = []
    write_new(destination / 'NODE-STREAM.jsonl', b'')
    def append(row):
        with (destination / 'NODE-STREAM.jsonl').open('ab') as stream:
            stream.write((json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n').encode())
            stream.flush()
        records.append(row)
    completed_archives = {}
    if (archives / 'VERIFIED-ARCHIVES.json').exists():
        report = load(archives / 'VERIFIED-ARCHIVES.json')
        if report['status'] == 'TWO_ORIGINAL_ZIPS_FULL_SHA_AND_ALL_MEMBER_CRC_PASS':
            completed_archives = {Path(row['path']): row for row in report['archives'].values()}
    roots = [('evidence', evidence), ('scope', scope), ('harness', HARNESS), ('archive-inputs', archives)]
    for prefix, root in roots:
        if not root.exists():
            append({'path': prefix, 'kind': 'absent', 'reason': 'stage never created this root'})
            continue
        stack = [('', root)]
        while stack:
            suffix, path = stack.pop()
            logical = prefix + ('/' + suffix if suffix else '')
            if path == out or path.is_relative_to(out):
                continue
            if prefix == 'harness' and path == HARNESS / '.git':
                append({'path': logical, 'kind': 'excluded-checkout-metadata',
                        'reason': 'not a fixed harness material, source file, or product execution artifact'})
                continue
            before = path.lstat()
            row = {'path': logical, 'mode': stat.S_IMODE(before.st_mode), 'stat_before': stamp(before),
                   'nlink_before': before.st_nlink}
            if path in completed_archives:
                item = completed_archives[path]
                require(stamp(before) == item['post_verification_stat'], 'completed original ZIP changed before collection')
                row.update(kind='external-original-Actions-ZIP', original=item,
                           bytes_not_duplicated_in_new_artifact=True)
                append(row)
            elif stat.S_ISDIR(before.st_mode):
                row['kind'] = 'directory'
                append(row)
                for child in sorted(path.iterdir(), key=lambda value: value.name, reverse=True):
                    stack.append((suffix + '/' + child.name if suffix else child.name, child))
            elif stat.S_ISLNK(before.st_mode):
                target = os.fsencode(os.readlink(path))
                require(stamp(path.lstat()) == stamp(before), 'link changed during collection')
                row.update(kind='symlink', target_base64=base64.b64encode(target).decode('ascii'),
                           target_sha256=hashlib.sha256(target).hexdigest())
                append(row)
            elif stat.S_ISREG(before.st_mode):
                target = destination / 'files' / relative(logical)
                row.update(kind='file', storage_path='files/' + logical,
                           **collect_file(path, target, before))
                append(row)
            else:
                row.update(kind='nonregular-node-metadata', raw_type=stat.S_IFMT(before.st_mode), st_rdev=before.st_rdev)
                append(row)
    dump(destination / 'NODE-MANIFEST.json', records)
    return {'status': 'ALL_EXISTING_LOGICAL_NODES_RECORDED_FOR_ARTIFACT_UPLOAD',
            'node_count': len(records), 'file_bytes': sum(row.get('bytes', 0) for row in records),
            'symlinks_never_followed': True, 'POSIX_modes_restored_from_manifest_not_upload_defaults': True,
            'completed_original_R20_ZIP_wrappers_not_duplicated': True,
            'incomplete_downloads_retained_as_actual_files': True,
            'gate_result_not_changed_by_collection': True, 'product_invocations': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=('prepare', 'bind', 'launch', 'collect', 'capture-runtime'))
    parser.add_argument('--scope')
    parser.add_argument('--baseline')
    parser.add_argument('--archives')
    parser.add_argument('--evidence')
    parser.add_argument('--collection')
    args = parser.parse_args()
    if args.stage == 'capture-runtime':
        require(all(getattr(args, key) is None for key in ('scope', 'baseline', 'archives', 'evidence', 'collection')),
                'capture-runtime accepts no path overrides')
        sys.stdout.buffer.write(encode(capture_runtime()))
        return 0
    require(args.scope and args.evidence, 'explicit scope and evidence required')
    evidence = absolute(args.evidence)
    directory(evidence)
    out = evidence / args.stage
    directory(out, new=True)
    started = time.monotonic_ns()
    dump(out / 'INTENT.json', {'argv': sys.argv, 'stage': args.stage,
         'started_monotonic_ns': started, 'intent_is_not_execution': True,
         'workflow_context': {key: os.environ.get(key) for key in (
             'GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB',
             'GITHUB_SHA', 'GITHUB_REF', 'GITHUB_WORKFLOW', 'RUNNER_OS', 'RUNNER_ARCH')}})
    result = {'status': 'FAIL', 'stage': args.stage}
    exit_code = 1
    try:
        operation = {'prepare': prepare, 'bind': bind, 'launch': launch, 'collect': collect}[args.stage]
        result = operation(args, out)
        exit_code = 0
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
        if args.stage == 'launch' and (out / 'PROCESS-EXIT.json').exists():
            exit_code = load(out / 'PROCESS-EXIT.json')['workflow_exit'] or 1
    finally:
        result.update(elapsed_ns=time.monotonic_ns() - started, stage=args.stage, exit_code=exit_code)
        dump(out / 'RESULT.json', result)
        print(json.dumps({key: result.get(key) for key in ('status', 'stage', 'exit_code', 'elapsed_ns')}, sort_keys=True))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
