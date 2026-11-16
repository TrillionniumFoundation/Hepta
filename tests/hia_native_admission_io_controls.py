"""Finite controls for the explicit admission I/O capability.

No original Capture input, oracle, race, expected field, or budget is replaced.
Each invocation is an owned fresh process launched by the test module.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import posix
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / 'tests/fixtures/hia_native_admission_io'
REFERENCE_PINS = {
    'regular_bytes.py.txt': {'bytes': 746, 'sha256': 'cf1cb85c24fb435ed336a6451f5ea3aceeae66c86fed7a7911543eac06a3240d'},
    'source_resource_path.py.txt': {'bytes': 447, 'sha256': '5b0d8d966e5a17f94efa86d3ee7a73a4cf075065a8947b96707c5aed3770892c'},
}
SOURCE_NAMES = (
    'hepta/hia_native_admission_io.py', 'hepta/hia_json_preflight_native.py',
    'hepta/hia_native_helpers.py', 'hepta/hia_store_file_capture_native.py',
    'tools/build_hia_store_file_capture.py',
    'tests/test_hia_native_admission_io.py', 'tests/hia_native_admission_io_controls.py',
    'tools/read_hia_native_admission_io.py',
    'tests/fixtures/hia_native_admission_io/regular_bytes.py.txt',
    'tests/fixtures/hia_native_admission_io/source_resource_path.py.txt',
    'tests/fixtures/hia_native_admission_io/source-identity.json',
    'tests/test_hia_store_file_capture_native.py',
    'tests/hia_store_file_capture_controls.py',
    'tests/hia_store_file_capture_installed.py',
    'examples/hia_bootstrap/store_file_capture.hepta',
)
ACTIONS = ('paths', 'regular', 'io-failures', 'resolver-failures', 'cold-source',
           'admission', 'cold-public', 'pinned', 'installed')
FAMILIES = ('OSError', 'MemoryError', 'KeyboardInterrupt', 'SystemExit')
IO_FAULTS = (
    ('open', 1, 'before'), ('open', 1, 'after'),
    ('fstat', 1, 'before'), ('fstat', 1, 'after'),
    ('read', 1, 'before'), ('read', 1, 'after'),
    ('fstat', 2, 'before'), ('fstat', 2, 'after'),
    ('close', 1, 'before'), ('close', 1, 'after'),
)
_OS_NAMES = ('open', 'read', 'close', 'fstat', 'stat', 'lstat', 'readlink', 'getcwd', 'getcwdb')
_RAW = {name: getattr(posix, name) for name in _OS_NAMES}


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def write(path, value):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value))


def sources():
    return {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for name in SOURCE_NAMES for raw in [(ROOT / name).read_bytes()]}


def require(value, message):
    if not value:
        raise AssertionError(message)


def error_record(error):
    def item(value):
        if value is None or type(value) in (str, int, bool, float):
            return {'type': type(value).__name__, 'value': value}
        if type(value) is bytes:
            return {'type': 'bytes', 'hex': value.hex()}
        return {'type': type(value).__module__ + '.' + type(value).__qualname__,
                'text': str(value)}
    return {'type': type(error).__module__ + '.' + type(error).__qualname__,
            'text': str(error), 'args': [item(x) for x in error.args],
            'errno': getattr(error, 'errno', None),
            'filename': item(getattr(error, 'filename', None)),
            'filename2': item(getattr(error, 'filename2', None)),
            'name': item(getattr(error, 'name', None)),
            'obj': item(getattr(error, 'obj', None))}


def outcome(callback):
    try:
        value = callback()
    except BaseException as error:
        return {'status': 'raised', 'error': error_record(error)}
    if type(value) is bytes:
        return {'status': 'returned', 'type': 'bytes', 'hex': value.hex()}
    return {'status': 'returned', 'type': type(value).__name__, 'value': str(value)}


@contextmanager
def attributes(target, values):
    old = {name: getattr(target, name) for name in values}
    try:
        for name, value in values.items():
            setattr(target, name, value)
        yield
    finally:
        for name, value in old.items():
            setattr(target, name, value)


@contextmanager
def selected(selector, manifest):
    marker = object()
    old = os.environ.get(selector, marker)
    os.environ[selector] = str(manifest)
    try:
        yield
    finally:
        if old is marker:
            os.environ.pop(selector, None)
        else:
            os.environ[selector] = old


def forbidden(*args, **kwargs):
    raise AssertionError('admission/control reached forbidden business or retained provider')


def originals():
    identity_raw = (FIXTURES / 'source-identity.json').read_bytes()
    identity = json.loads(identity_raw)
    require(identity['originals'] == REFERENCE_PINS, 'independent reference pin manifest differs')
    namespace = {'os': os, 'Path': Path, 'stat': stat, '__file__': ''}
    captured = {}
    for name, pin in identity['originals'].items():
        raw = (FIXTURES / name).read_bytes()
        require(type(pin['bytes']) is int and len(raw) == pin['bytes']
                and sha256(raw).hexdigest() == pin['sha256'], 'private admission original differs')
        captured[name] = raw
        exec(compile(raw, str(FIXTURES / name), 'exec'), namespace)
    require((FIXTURES / 'source-identity.json').read_bytes() == identity_raw
            and all((FIXTURES / name).read_bytes() == raw for name, raw in captured.items()),
            'private admission original changed while consumed')
    return namespace


def compare(output, expected, actual):
    expected_raw, actual_raw = canonical(expected), canonical(actual)
    write(output / 'actual.json', actual)
    require((output / 'expected.json').read_bytes() == expected_raw, 'original observations changed')
    rows = [{'index': n, 'expected': left, 'actual': right}
            for n, (left, right) in enumerate(zip(expected, actual)) if left != right]
    if len(expected) != len(actual):
        rows.append({'lengths': [len(expected), len(actual)]})
    write(output / 'differences.json', rows)
    require(not rows and expected_raw == actual_raw, 'complete admission original comparison differs')
    return {'count': len(expected), 'differences': 0, 'expected_sha256': sha256(expected_raw).hexdigest(),
            'actual_sha256': sha256(actual_raw).hexdigest()}


def path_controls(output):
    original = originals()
    with tempfile.TemporaryDirectory(prefix='hia-admission-path-') as temporary:
        base = Path(temporary)
        (base / 'd/sub').mkdir(parents=True)
        (base / 'd/data').write_bytes(b'abc')
        (base / 'relative').symlink_to('d')
        (base / 'absolute').symlink_to(base / 'd', target_is_directory=True)
        (base / 'dangling').symlink_to('absent')
        (base / 'loop').symlink_to('loop')
        paths = [base, base / 'd/data', base / 'd/./sub/../data', base / 'relative/data',
                 base / 'absolute/sub/../data', base / 'dangling', base / 'missing/../d/data',
                 base / 'loop', base / 'loop/suffix', base / 'd/data/child',
                 base / 'missing', Path(str(base) + '/d/data/'), Path('.')]
        calls = [(str(index) + '.' + str(strict), path, strict)
                 for index, path in enumerate(paths) for strict in (False, True)]
        expected = [{'id': label, 'outcome': outcome(lambda p=path, s=strict: p.resolve(strict=s))}
                    for label, path, strict in calls]
        anchors = []
        for label in ('checkout', 'installed', 'missing-package', 'directory-marker'):
            anchor = base / label / 'hepta/module.py'
            anchor.parent.mkdir(parents=True)
            anchor.write_text('# independent source anchor\n')
            marker = anchor.parent.parent / 'pyproject.toml'
            if label == 'checkout':
                marker.write_text('[build-system]\n')
            elif label == 'directory-marker':
                marker.mkdir()
            anchors.append((label, anchor))
        for label, anchor in anchors:
            for name in ('examples/hia_bootstrap/missing.hepta', 'hepta/not-present.py', '../sibling'):
                original['__file__'] = str(anchor)
                expected.append({'id': label + ':' + name,
                    'outcome': outcome(lambda n=name: original['_source_resource_path'](n))})
        write(output / 'expected.json', expected)
        from hepta import hia_native_admission_io as io
        actual = [{'id': label, 'outcome': outcome(lambda p=path, s=strict: io.resolve_path(p, strict=s))}
                  for label, path, strict in calls]
        for label, anchor in anchors:
            for name in ('examples/hia_bootstrap/missing.hepta', 'hepta/not-present.py', '../sibling'):
                actual.append({'id': label + ':' + name,
                    'outcome': outcome(lambda n=name, a=anchor: io.source_resource_path(str(a), n))})
        report = compare(output, expected, actual)
        report['canonical_runtime_original_first'] = True
        return report


def regular_controls(output):
    reference = originals()['_regular_bytes']
    with tempfile.TemporaryDirectory(prefix='hia-admission-regular-') as temporary:
        base = Path(temporary)
        (base / 'small').write_bytes(b'bounded\0bytes\n')
        (base / 'large').write_bytes(bytes(range(256)) * 300)
        (base / 'empty').write_bytes(b'')
        (base / 'directory').mkdir()
        (base / 'link').symlink_to('small')
        posix.mkfifo(base / 'fifo')
        cases = [('small', 4096), ('large', 100000), ('small', 2), ('empty', 4096),
                 ('directory', 4096), ('link', 4096), ('fifo', 4096), ('missing', 4096)]
        expected = [{'id': name, 'outcome': outcome(lambda n=name, bound=limit:
                    reference(base / n, bound))} for name, limit in cases]
        write(output / 'expected.json', expected)
        from hepta import hia_native_admission_io as io
        actual = [{'id': name, 'outcome': outcome(lambda n=name, bound=limit:
                  io.regular_bytes(base / n, bound))} for name, limit in cases]
        report = compare(output, expected, actual)
        flags = [];inheritable = []
        captured = io._CAPABILITIES
        def observe_open(*args, **kwargs):
            descriptor = captured[io._OPEN](*args, **kwargs)
            flags.append(descriptor)
            inheritable.append(posix.get_inheritable(descriptor))
            return descriptor
        changed = list(captured);changed[io._OPEN] = observe_open
        capsule = io._AdmissionIO(tuple(changed))
        require(capsule.regular_bytes(base / 'small', 4096) == (base / 'small').read_bytes(),
                'explicit admission reader returned different bytes')
        require(len(flags) == 1 and not descriptor_open(flags[0]) and inheritable == [False],
                'healthy admission descriptor escaped or lacked CLOEXEC')
        report['one_descriptor_closed'] = True
        return report


def descriptor_open(descriptor):
    try:
        _RAW['fstat'](descriptor)
    except OSError as error:
        if error.errno == 9:
            return False
        raise
    return True


def injected(family):
    if family == 'OSError':
        return OSError(5, 'declared admission fault')
    return {'MemoryError': MemoryError, 'KeyboardInterrupt': KeyboardInterrupt,
            'SystemExit': SystemExit}[family]('declared admission fault')


def io_failure_controls(output):
    from hepta import hia_native_admission_io as io
    rows = []
    with tempfile.TemporaryDirectory(prefix='hia-admission-fault-') as temporary:
        path = Path(temporary) / 'data';path.write_bytes(b'actual descriptor bytes')
        for operation, occurrence, phase in IO_FAULTS:
            for family in FAMILIES:
                error = injected(family);counts = {};opened = [];events = []
                table = list(io._CAPABILITIES)
                for name in ('open', 'read', 'fstat', 'close'):
                    index = io._NAMES.index(name);raw = table[index]
                    def watched(*args, _name=name, _raw=raw, **kwargs):
                        counts[_name] = counts.get(_name, 0) + 1
                        hit = _name == operation and counts[_name] == occurrence
                        events.append([_name, counts[_name], 'enter'])
                        if hit and phase == 'before':
                            raise error
                        value = _raw(*args, **kwargs)
                        if _name == 'open':
                            opened.append(value)
                        events.append([_name, counts[_name], 'return'])
                        if hit and phase == 'after':
                            raise error
                        return value
                    table[index] = watched
                capsule = io._AdmissionIO(tuple(table))
                caught = None
                try:
                    capsule.regular_bytes(path, 4096)
                except BaseException as raised:
                    caught = raised
                alive = [fd for fd in opened if descriptor_open(fd)]
                label = '.'.join((operation, str(occurrence), phase, family))
                unknown = ((operation == 'open' and phase == 'after')
                           or (operation == 'close' and phase == 'before'))
                row = {'id': label, 'same_error': caught is error,
                       'error': None if caught is None else error_record(caught),
                       'events': events, 'counts': counts, 'opened': len(opened),
                       'open_after_return': len(alive),
                       'unknown_descriptor_boundary': unknown,
                       'capsule_retried_close': counts.get('close', 0) > 1,
                       'fixture_cleanup_after_observation': len(alive)}
                rows.append(row)
                write(output / ('io-failure-' + str(len(rows)).zfill(3) + '.json'), row)
                # This is explicit test-owned cleanup AFTER the observed endpoint.
                # It never counts as the capsule having closed an unknown result.
                for descriptor in alive:
                    _RAW['close'](descriptor)
                require(caught is error, label + ': original exception identity lost')
                require(counts.get('close', 0) == (0 if operation == 'open' else 1),
                        label + ': wrong close claim count')
                require(len(alive) == int(unknown), label + ': wrong descriptor endpoint')
        write(output / 'io-failures.json', rows)
    require(len(rows) == 40, 'finite failure table changed')
    return {'count': len(rows), 'all_exception_identities_preserved': True,
            'unknown_open_or_close_is_not_claimed_closed': True,
            'no_capsule_close_retry': True}


def resolver_failure_controls(output):
    from hepta import hia_native_admission_io as io
    rows = []
    with tempfile.TemporaryDirectory(prefix='hia-admission-resolver-') as temporary:
        root = Path(temporary);data = root / 'data';data.write_bytes(b'x')
        link = root / 'link';link.symlink_to('data')
        tests = (
            ('lstat', lambda c: c.resolve_path(data, strict=True)),
            ('readlink', lambda c: c.resolve_path(link, strict=True)),
            ('getcwd', lambda c: c.resolve_path(Path('.'), strict=True)),
            ('getcwdb', lambda c: c._realpath(b'.', True)),
            ('stat', lambda c: c.is_file(data)),
            ('strerror', lambda c: c.resolve_path(data / 'child', strict=True)),
        )
        for name, call in tests:
            for family in FAMILIES:
                error = injected(family);calls = [];table = list(io._CAPABILITIES)
                def fail(*args, **kwargs):
                    calls.append(True)
                    raise error
                table[io._NAMES.index(name)] = fail
                caught = None;value = None
                try:
                    value = call(io._AdmissionIO(tuple(table)))
                except BaseException as raised:
                    caught = raised
                reachable = not (name == 'strerror' and sys.version_info < (3, 13))
                expected_false = name == 'stat' and family == 'OSError' and sys.version_info >= (3, 14)
                row = {'id': name + '.' + family, 'calls': len(calls),
                       'same_error': caught is error,
                       'returned_false': value is False and caught is None,
                       'original_path_predicate_suppresses_OSerror': expected_false,
                       'capability_cutpoint_reachable_in_this_runtime': reachable}
                rows.append(row)
                write(output / ('resolver-failure-' + str(len(rows)).zfill(3) + '.json'), row)
                if not reachable:
                    expected = outcome(lambda: (data / 'child').resolve(strict=True))
                    require(calls == [] and caught is not None
                            and {'status': 'raised', 'error': error_record(caught)} == expected,
                            row['id'] + ': legacy resolver acquired an invented strerror call')
                else:
                    require(calls == [True], row['id'] + ': declared capability was not reached once')
                    require((value is False and caught is None) if expected_false else caught is error,
                            row['id'] + ': private resolver error semantics differ')
        write(output / 'resolver-failures.json', rows)
    return {'count': len(rows), 'complete_capability_failures': True}


def cold_source_controls(output):
    require('hepta.hia_native_admission_io' not in sys.modules
            and 'hepta.hia_json_preflight_native' not in sys.modules
            and 'hepta.hia_store_file_capture_native' not in sys.modules,
            'cold admission control began with a loaded product dependency')
    expected = str((ROOT / 'hepta/hia_json_preflight_native.py').resolve().parent.parent
                   / 'examples/hia_bootstrap/json_preflight.hepta')
    calls = []
    def touched(*args, **kwargs):
        calls.append(True)
        raise AssertionError('source admission used a dynamic business os capability')
    with attributes(os, {name: touched for name in _OS_NAMES}):
        from hepta import hia_json_preflight_native as preflight
        from hepta import hia_store_file_capture_native as native
        from hepta import hia_native_admission_io as io
        actual = str(preflight.SOURCE)
        require(actual == expected, 'cold source anchor differs')
        require(native.SOURCE == ROOT / 'examples/hia_bootstrap/store_file_capture.hepta',
                'cold capture source anchor differs')
        require(io._CAPABILITIES is not None, 'POSIX capability table absent')
    require(calls == [], 'cold module source discovery used business OS hooks')
    return {'count': 1, 'cold_before_import': True, 'business_os_calls': calls,
            'source': actual, 'all_admission_operations_remain_real_POSIX_IO': True}


def monitored_capsule(io, *, callback=None):
    events = [];owners = {};counts = {}
    table = list(io._CAPABILITIES)
    for name in ('open', 'read', 'fstat', 'close', 'lstat', 'readlink', 'stat', 'getcwd', 'getcwdb'):
        index = io._NAMES.index(name);raw = table[index]
        def observed(*args, _name=name, _raw=raw, **kwargs):
            path = str(args[0]) if _name in ('open', 'lstat', 'readlink', 'stat') else owners.get(args[0] if args else None)
            key = (_name, path);counts[key] = counts.get(key, 0) + 1
            events.append({'operation': _name, 'path': path, 'phase': 'enter',
                           'ordinal': counts[key]})
            if callback is not None:
                callback(_name, path, counts[key], 'before', args)
            value = _raw(*args, **kwargs)
            if _name == 'open':
                owners[value] = path
            events.append({'operation': _name, 'path': path, 'phase': 'return',
                           'ordinal': counts[key]})
            if callback is not None:
                callback(_name, path, counts[key], 'after', args)
            if _name == 'close':
                owners.pop(args[0], None)
            return value
        table[index] = observed
    return io._AdmissionIO(tuple(table)), events, owners


def admission_controls(manifest, output):
    from hepta import hia_store_file_capture_native as native
    from hepta import hia_native_admission_io as io
    original_manifest = Path(manifest).read_bytes();record = json.loads(original_manifest)
    source_raw = native.SOURCE.read_bytes()
    image_raw = (Path(manifest).parent / record['image_path']).read_bytes()
    rows = []
    with tempfile.TemporaryDirectory(prefix='hia-admission-loader-') as temporary:
        root = Path(temporary);source = root / 'source.hepta';image = root / record['image_path']
        selected_manifest = root / 'manifest.json'
        source.write_bytes(source_raw);image.write_bytes(image_raw);selected_manifest.write_bytes(original_manifest)
        initial = {selected_manifest: original_manifest, source: source_raw, image: image_raw}
        capsule, events, owners = monitored_capsule(io)
        with attributes(native, {'SOURCE': source}), attributes(io, {'_ADMISSION': capsule}):
            first = native.installed_store_file_capture(selected_manifest)
            split = len(events)
            second = native.installed_store_file_capture(selected_manifest)
        require(first is second, 'immutable image cache identity changed')
        for label, lane in (('first', events[:split]), ('second', events[split:])):
            opens = [x['path'] for x in lane if x['operation'] == 'open' and x['phase'] == 'enter']
            require(opens == [str(selected_manifest), str(source), str(image)] * 2,
                    'fresh manifest/source/image plus exact terminal reread changed: ' + label)
            require(sum(x['operation'] == 'fstat' and x['phase'] == 'return' for x in lane) == 12,
                    'descriptor identity checks were cached/skipped')
        require(not owners, 'healthy admission retained open descriptors')
        rows.append({'id': 'fresh-two-admissions', 'events': events, 'same_immutable_image': True})
        # Each mutation occurs AFTER an actual first descriptor read. Initial
        # hash checks still use the captured original; terminal reread must reject.
        for label, target in (('manifest', selected_manifest), ('source', source), ('image', image)):
            saved = initial[target];changed = [False]
            replacement = (saved + b'\n') if label == 'manifest' else bytes([saved[0] ^ 1]) + saved[1:]
            def mutate(name, path, ordinal, phase, args):
                if name == 'close' and path == str(target) and ordinal == 1 and phase == 'after':
                    require(not changed[0], 'mutation occurred twice')
                    target.write_bytes(replacement);changed[0] = True
            capsule, events, owners = monitored_capsule(io, callback=mutate)
            caught = None
            try:
                with attributes(native, {'SOURCE': source}), attributes(io, {'_ADMISSION': capsule}):
                    native.installed_store_file_capture(selected_manifest)
            except BaseException as error:
                caught = error
            finally:
                target.write_bytes(saved)
            write(output / ('terminal-change-' + label + '.json'), {
                'changed': changed, 'events': events, 'still_owned': list(owners),
                'error': None if caught is None else error_record(caught)})
            require(changed == [True] and type(caught) is ValueError
                    and str(caught) == 'native store file capture selection changed during admission',
                    label + ': terminal fresh-byte comparison failed')
            require(not owners, label + ': descriptor remained owned after rejection')
            rows.append({'id': 'terminal-change.' + label, 'events': events,
                         'error': error_record(caught), 'same_length_change': len(saved) == len(replacement)})
        # Same-size change between pre/post fstat must be refused independently
        # of the terminal selection comparison.
        changed = [False];source_status = _RAW['stat'](source)
        def during_read(name, path, ordinal, phase, args):
            if name == 'read' and path == str(source) and ordinal == 1 and phase == 'after':
                source.write_bytes(bytes([source_raw[0] ^ 1]) + source_raw[1:])
                posix.utime(source, ns=(source_status.st_atime_ns, source_status.st_mtime_ns + 1000000000))
                changed[0] = True
        capsule, events, owners = monitored_capsule(io, callback=during_read)
        caught = None
        try:
            with attributes(native, {'SOURCE': source}), attributes(io, {'_ADMISSION': capsule}):
                native.installed_store_file_capture(selected_manifest)
        except BaseException as error:
            caught = error
        finally:
            source.write_bytes(source_raw)
        write(output / 'same-size-during-read.json', {'changed': changed, 'events': events,
              'still_owned': list(owners), 'error': None if caught is None else error_record(caught)})
        require(changed[0] and type(caught) is ValueError
                and str(caught) == 'store-lifecycle input changed while being read',
                'same-size descriptor mutation was admitted')
        require(not owners, 'same-size rejection leaked descriptor')
        rows.append({'id': 'same-size-during-read', 'events': events, 'error': error_record(caught)})
        # The manifest may resolve a symlink as before; source/image remain
        # O_NOFOLLOW leaves. No fallback to a different source path is allowed.
        alias = root / 'manifest-link';alias.symlink_to(selected_manifest.name)
        with attributes(native, {'SOURCE': source}):
            require(native.installed_store_file_capture(alias) is first, 'manifest symlink changed view')
        rows.append({'id': 'manifest-symlink-canonical-key', 'accepted': True})
        for label, target in (('source', source), ('image', image)):
            saved = initial[target];backup = target.with_name(target.name + '.target')
            backup.write_bytes(saved);target.unlink();target.symlink_to(backup.name)
            caught = None
            try:
                with attributes(native, {'SOURCE': source}):
                    native.installed_store_file_capture(selected_manifest)
            except BaseException as error:
                caught = error
            finally:
                target.unlink();target.write_bytes(saved);backup.unlink()
            require(isinstance(caught, OSError) and caught.errno == 40,
                    label + ': O_NOFOLLOW leaf was bypassed')
            rows.append({'id': 'leaf-symlink.' + label, 'error': error_record(caught)})
        require(all(path.read_bytes() == raw for path, raw in initial.items()), 'control fixture not restored')
    require(Path(manifest).read_bytes() == original_manifest and native.SOURCE.read_bytes() == source_raw,
            'external admission inputs changed')
    write(output / 'admission.json', rows)
    return {'count': len(rows), 'all_six_fresh_reads_per_call': True,
            'all_IO_is_explicit_admission_IO': True, 'same_size_and_terminal_changes_rejected': True}


def cold_public_controls(manifest, output):
    from hepta import hia_agent_store as api
    require('hepta.hia_store_file_capture_native' not in sys.modules,
            'fresh public control imported selected owner early')
    with tempfile.TemporaryDirectory(prefix='hia-admission-public-') as temporary:
        root = Path(temporary);target = root / 'data';target.write_bytes(b'cold public\0capture')
        expected = api._CAPTURE_PATH_REFERENCE(str(target), [root], 4096)
        calls = []
        def counted_fstat(*args, **kwargs):
            value = _RAW['fstat'](*args, **kwargs);calls.append('fstat');return value
        with selected('HEPTA_HIA_STORE_FILE_CAPTURE_MANIFEST', manifest), attributes(
                api, {'_STABLE_READ_REFERENCE': forbidden, '_CAPTURE_PATH_REFERENCE': forbidden}), \
                attributes(os, {'fstat': counted_fstat}):
            actual = api.capture_path(str(target), [root], 4096)
        require(actual == expected and calls == ['fstat', 'fstat'],
                'cold public capture mixed admission I/O with the business fstat provider')
        write(output / 'cold-public.json', {'expected_hex': expected.hex(), 'actual_hex': actual.hex(),
                                            'business_fstat_calls': calls,
                                            'selected_owner_initially_absent': True})
    # These are the unchanged complete original controls, including exact
    # fstat counts and same-size race timing; no replacement expectations.
    from tests import hia_store_file_capture_controls as original
    os_rows = original.real_os_cases(manifest, output)
    race_rows = original.real_os_races(manifest, output)
    require(len(os_rows) == 12 and len(race_rows) == 3, 'original OS/race domain changed')
    return {'count': 16, 'cold_public': True, 'original_OS_cases': 12,
            'original_race_cases': 3, 'retained_bodies_poisoned': True}


def pinned_controls(manifest, output):
    from hepta import hia_store_file_capture_native as native
    from hepta import hia_native_admission_io as io
    from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
    raw = Path(manifest).read_bytes()
    bundle = output / 'bundle.json'
    write(bundle, {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
        {'selector': native.SELECTOR, 'manifest_path': str(Path(manifest).absolute()),
         'manifest_sha256': sha256(raw).hexdigest()}]})
    digest = sha256(bundle.read_bytes()).hexdigest()
    rows = []
    with native_helpers_scope(str(bundle), digest):
        first = native.installed_store_file_capture(manifest)
        capsule, events, owners = monitored_capsule(io)
        touched = []
        def no_business_io(*args, **kwargs):
            touched.append(True);raise AssertionError('pinned admission used business os')
        with attributes(os, {name: no_business_io for name in _OS_NAMES}), \
                attributes(io, {'_ADMISSION': capsule}):
            second = native.installed_store_file_capture(manifest)
        require(first is second and not touched and not owners, 'actual pinned image/capability differs')
        require(sum(x['operation'] == 'open' and x['phase'] == 'enter' for x in events) == 6,
                'pinned image skipped fresh admission bytes')
        rows.append({'id': 'real-pinned-image', 'events': events, 'same_image': True,
                     'business_os_calls': touched})
        changed = json.loads(raw);changed['source_sha256'] = '0' * 64
        caught = None
        try:
            Path(manifest).write_bytes(canonical(changed))
            try:
                native.installed_store_file_capture(manifest)
            except BaseException as error:
                caught = error
        finally:
            Path(manifest).write_bytes(raw)
        require(type(caught) is ValueError and 'source identity mismatch' in str(caught),
                'pinned image concealed actual source manifest drift')
        rows.append({'id': 'pinned-fresh-source-digest', 'error': error_record(caught)})
    require(Path(manifest).read_bytes() == raw, 'pinned control left manifest drift')
    write(output / 'pinned.json', rows)
    return {'count': len(rows), 'actual_bundle_scope': True, 'fresh_file_checks_inside_scope': True}


def installed_controls(manifest, output):
    from tests.hia_store_file_capture_installed import run
    report = run(manifest, output / 'installed')
    files = report['wheel_files_checked_against_installed']
    require('hepta/hia_native_admission_io.py' in files, 'wheel omitted admission module')
    require(files['hepta/hia_native_admission_io.py'] ==
            sha256((ROOT / 'hepta/hia_native_admission_io.py').read_bytes()).hexdigest(),
            'installed admission source differs')
    require(report['observations']['normal_counts']['request'] > 0
            and report['observations']['replay_counts']['request'] == 0,
            'unchanged installed worker routes differ')
    return {'count': 4, 'whole_original_installed_control': True,
            'wheel_contains_actual_capsule': True, 'report': 'installed/installed.json'}



# Explicit successor observer. The legacy regular_controls function above is
# intentionally intact: its same-process old8 -> candidate8 mode remains v1.
REGULAR_MATCHED = 'PASS_MATCHED_FINITE_OBSERVER'
REGULAR_CASES = (('small', 4096), ('large', 100000), ('small', 2), ('empty', 4096),
                 ('directory', 4096), ('link', 4096), ('fifo', 4096), ('missing', 4096))
REGULAR_LANES = ('original-a', 'original-b', 'candidate')
REGULAR_STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                       'st_rdev', 'st_size', 'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')


def _matched_call(callback):
    try:
        return {'status': 'returned', 'value': callback()}
    except BaseException as error:
        return {'status': 'raised', 'error': error_record(error)}


def _matched_stat(value):
    return {name: getattr(value, name) for name in REGULAR_STAT_FIELDS}


def _matched_fd(descriptor):
    import fcntl
    return {'fd': descriptor,
            'readlink': _matched_call(lambda: posix.readlink('/proc/self/fd/' + str(descriptor))),
            'fstat': _matched_call(lambda: _matched_stat(posix.fstat(descriptor))),
            'getfd': _matched_call(lambda: fcntl.fcntl(descriptor, fcntl.F_GETFD)),
            'getfl': _matched_call(lambda: fcntl.fcntl(descriptor, fcntl.F_GETFL)),
            'position': _matched_call(lambda: posix.lseek(descriptor, 0, os.SEEK_CUR))}


def _matched_fds():
    # listdir's own temporary descriptor has closed before probing. Keep that
    # enumerated-but-absent row, with its actual errors; this is not an atomic
    # snapshot and no descriptor is closed, duplicated, or renumbered here.
    import fcntl
    names = sorted(posix.listdir('/proc/self/fd'), key=int)
    require(all(name.isdecimal() and str(int(name)) == name for name in names),
            'noncanonical /proc descriptor name')
    return {'enumerated': names, 'rows': [_matched_fd(int(name)) for name in names],
            'atomic_snapshot_claimed': False, 'fd_cleanup_performed': False}


def _matched_inputs(base):
    rows = {}
    for name in ('small', 'large', 'empty', 'directory', 'link', 'fifo', 'missing'):
        path = base / name
        row = {'path': str(path)}
        if name in ('small', 'large', 'empty'):
            raw = path.read_bytes()
            row['content'] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
        if name == 'link':
            row['target'] = posix.readlink(path)
        row['lstat'] = _matched_call(lambda p=path: _matched_stat(posix.lstat(p)))
        rows[name] = row
    return rows


def _matched_initial(base):
    import resource
    limits = {name: list(resource.getrlimit(getattr(resource, name))) for name in (
        'RLIMIT_NOFILE', 'RLIMIT_NPROC', 'RLIMIT_CPU', 'RLIMIT_AS',
        'RLIMIT_DATA', 'RLIMIT_STACK', 'RLIMIT_CORE')}
    tasks = sorted(int(name) for name in posix.listdir('/proc/self/task'))
    inputs = _matched_inputs(base)
    common = {'runtime': {'executable': sys.executable, 'version': sys.version,
                         'implementation': sys.implementation.name, 'flags': str(sys.flags)},
              'cwd': posix.getcwd(), 'uid': posix.getuid(), 'euid': posix.geteuid(),
              'gid': posix.getgid(), 'egid': posix.getegid(), 'groups': posix.getgroups(),
              'environment_sha256': sha256(canonical(dict(os.environ))).hexdigest(),
              'limits': limits, 'inputs': inputs, 'fds': _matched_fds()}
    return {'common': common, 'task_ids': tasks,
            'full_process_or_heap_equivalence_claimed': False}


def _matched_lane(args):
    import time
    version = _regular_version(args.regular_observer)
    args.output.mkdir(mode=0o700)
    started = time.monotonic_ns()
    before = sources()
    write(args.output / 'source-before.json', before)
    plan_raw = args.regular_plan.read_bytes()
    plan = json.loads(plan_raw)
    require(plan['schema'] == 'hepta.hia.native-admission-regular-plan.v' + version
            and plan['source_before'] == before and plan['input_root'] == str(args.regular_base)
            and plan['lanes'] == list(REGULAR_LANES)
            and plan['cases'] == [{'index': i, 'id': name, 'limit': limit}
                                 for i, (name, limit) in enumerate(REGULAR_CASES)],
            'matched lane plan/source binding differs')
    report = {'schema': 'hepta.hia.native-admission-regular-lane.v' + version,
              'status': 'HOLD', 'lane': args.regular_lane,
              'pid': posix.getpid(), 'ppid': posix.getppid(), 'pgid': posix.getpgrp(),
              'argv': list(sys.argv), 'cwd': posix.getcwd(), 'started_monotonic_ns': started,
              'source_before': before, 'plan_sha256': sha256(plan_raw).hexdigest(),
              'provider_replaced': False, 'fd_cleanup_performed': False,
              'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False}
    failure = None
    try:
        reference = originals()['_regular_bytes']
        if args.regular_lane == 'candidate':
            from hepta import hia_native_admission_io as io
            provider = io.regular_bytes
        else:
            provider = reference
        report['initial'] = _matched_initial(args.regular_base)
        # Exactly the original eight uninterrupted outcome calls. In particular,
        # there is no per-case probe, output write, manual close, or extra call.
        rows = [{'id': name, 'outcome': outcome(lambda n=name, bound=limit:
                 provider(args.regular_base / n, bound))} for name, limit in REGULAR_CASES]
        report['final_fds'] = _matched_fds()
        directory = rows[4]['outcome']
        filename = directory.get('error', {}).get('filename', {})
        require(directory.get('status') == 'raised'
                and filename.get('type') == 'int' and type(filename.get('value')) is int,
                'directory observation has no actual integer filename')
        report['directory_filename'] = filename['value']
        report['directory_fd_after_all_eight'] = _matched_fd(filename['value'])
        report['inputs_after'] = _matched_inputs(args.regular_base)
        report['ordered_cases'] = plan['cases']
        write(args.output / 'observations.json', rows)
        report['observation_pin'] = {'bytes': len(canonical(rows)),
                                     'sha256': sha256(canonical(rows)).hexdigest()}
        report['status'] = 'LANE_RECORDED'
    except BaseException as error:
        report['error'] = error_record(error);failure = error
    finally:
        report['source_after'] = sources()
        report['source_unchanged'] = report['source_after'] == before
        report['plan_unchanged'] = args.regular_plan.read_bytes() == plan_raw
        report['ended_monotonic_ns'] = time.monotonic_ns()
        if not report['source_unchanged'] or not report['plan_unchanged']:
            report['status'] = 'HOLD'
        write(args.output / 'report.json', report)
    if failure is not None:
        raise failure
    require(report['status'] == 'LANE_RECORDED', 'matched lane custody changed')
    return 0


def _regular_version(observer):
    require(type(observer) is str and observer in ('matched-v2', 'matched-v3'),
            'unknown matched regular observer version')
    return '3' if observer == 'matched-v3' else '2'


def _matched_prepare_inputs(base, output, before):
    """Record one fixed setup history before any lane; never retry a provider."""
    import time
    record = {
        'schema': 'hepta.hia.native-admission-regular-input-preparation.v3',
        'status': 'HOLD', 'input_root': str(base),
        'owner_pid': posix.getpid(), 'owner_pgid': posix.getpgrp(),
        'source_before': before,
        'requested_delay_ns': 1000000000, 'delay_calls': 0, 'snapshot_calls': 0,
        'provider_calls': 0, 'fd_cleanup_performed': False,
        'timestamp_override_performed': False, 'retry_performed': False,
        'candidate_derived_expectation': False,
        'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False,
        'started_monotonic_ns': time.monotonic_ns(),
        'started_time_ns': time.time_ns(), 'error': None,
    }
    failure = None
    try:
        record['before_snapshot_started_monotonic_ns'] = time.monotonic_ns()
        record['snapshot_calls'] = 1
        record['before_inputs'] = _matched_inputs(base)
        record['before_snapshot_ended_monotonic_ns'] = time.monotonic_ns()
        record['delay_started_time_ns'] = time.time_ns()
        record['delay_started_monotonic_ns'] = time.monotonic_ns()
        record['delay_calls'] = 1
        # One declared second is inside the existing enclosing 60-second owner.
        # This is not a stability polling loop and does not change any timestamp.
        time.sleep(1)
        record['delay_ended_monotonic_ns'] = time.monotonic_ns()
        record['delay_ended_time_ns'] = time.time_ns()
        record['after_snapshot_started_monotonic_ns'] = time.monotonic_ns()
        record['snapshot_calls'] = 2
        record['after_inputs'] = _matched_inputs(base)
        record['after_snapshot_ended_monotonic_ns'] = time.monotonic_ns()
        record['status'] = 'PREPARED_FIXED_HISTORY'
    except BaseException as error:
        record['error'] = error_record(error)
        failure = error
    finally:
        record['ended_time_ns'] = time.time_ns()
        record['ended_monotonic_ns'] = time.monotonic_ns()
        write(output / 'input-preparation.json', record)
    if failure is not None:
        raise failure
    return record


def _matched_regular(output, before, *, observer='matched-v2'):
    import subprocess
    import time
    version = _regular_version(observer)
    with tempfile.TemporaryDirectory(prefix='hia-admission-regular-') as temporary:
        base = Path(temporary)
        (base / 'small').write_bytes(b'bounded\0bytes\n')
        (base / 'large').write_bytes(bytes(range(256)) * 300)
        (base / 'empty').write_bytes(b'')
        (base / 'directory').mkdir()
        (base / 'link').symlink_to('small')
        posix.mkfifo(base / 'fifo')
        environment = dict(os.environ)
        preparation = None
        if observer == 'matched-v3':
            preparation = _matched_prepare_inputs(base, output, before)
        plan = {'schema': 'hepta.hia.native-admission-regular-plan.v' + version,
                'lanes': list(REGULAR_LANES), 'source_before': before,
                'cases': [{'index': i, 'id': name, 'limit': limit}
                          for i, (name, limit) in enumerate(REGULAR_CASES)],
                'input_root': str(base),
                'input_before': (_matched_inputs(base) if observer == 'matched-v2'
                                 else preparation['after_inputs']),
                'owner_pid': posix.getpid(), 'owner_pgid': posix.getpgrp(),
                'environment_sha256': sha256(canonical(environment)).hexdigest(),
                'owner_budget_seconds': 60, 'owner_cleanup_seconds': 3,
                'additional_lane_budget': None,
                'launch': {'close_fds': True, 'start_new_session': False,
                           'stdin': 'INHERIT', 'stdout': 'INHERIT', 'stderr': 'INHERIT'},
                'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False}
        if observer == 'matched-v3':
            preparation_path = output / 'input-preparation.json'
            preparation_raw = preparation_path.read_bytes()
            require(preparation_raw == canonical(preparation),
                    'fixed preparation raw bytes differ from the actual record')
            plan['input_preparation'] = {'path': str(preparation_path),
                'bytes': len(preparation_raw), 'sha256': sha256(preparation_raw).hexdigest()}
            from tools.read_hia_native_admission_io import matched_input_preparation
            matched_input_preparation(plan, preparation)
        plan_path = output / 'matched-plan.json'
        write(plan_path, plan)
        receipts = []
        for lane in REGULAR_LANES:
            command = [sys.executable, '-I', '-B', str(Path(__file__).absolute()),
                       '--action', 'regular', '--output', str(output / lane),
                       '--regular-observer', observer, '--regular-lane', lane,
                       '--regular-base', str(base), '--regular-plan', str(plan_path)]
            receipt = {'schema': 'hepta.hia.native-admission-regular-lane-owner.v' + version,
                       'lane': lane, 'command': command, 'cwd': str(ROOT),
                       'owner_pid': posix.getpid(), 'owner_pgid': posix.getpgrp(),
                       'environment_sha256': plan['environment_sha256'],
                       'launch': plan['launch'], 'additional_lane_budget': None,
                       'started_monotonic_ns': time.monotonic_ns()}
            process = subprocess.Popen(command, cwd=ROOT, env=environment,
                                       close_fds=True, start_new_session=False,
                                       stdin=None, stdout=None, stderr=None)
            receipt['pid'] = process.pid
            # The original run_process 60-second owner bounds this wait and all
            # three descendants together. No new session or per-lane deadline.
            write(output / (lane + '.start.json'), receipt)
            receipt['returncode'] = process.wait()
            receipt['leader_reaped'] = process.returncode is not None
            receipt['ended_monotonic_ns'] = time.monotonic_ns()
            write(output / (lane + '.result.json'), receipt)
            receipts.append(receipt)
        write(output / 'input-after.json', _matched_inputs(base))
        require(all(type(row['returncode']) is int and row['returncode'] == 0
                    and row['leader_reaped'] is True for row in receipts),
                'a complete matched lane did not finish naturally')
        lane_reports = [json.loads((output / lane / 'report.json').read_bytes())
                        for lane in REGULAR_LANES]
        # Reader code is data-only. It independently checks the full actual
        # preconditions before a comparison is eligible; it never imports a
        # product provider or derives an expected observation from candidate.
        from tools.read_hia_native_admission_io import matched_preconditions
        matched_preconditions(plan, lane_reports, json.loads((output / 'input-after.json').read_bytes()),
                              observer=observer, preparation=preparation)
        observations = [json.loads((output / lane / 'observations.json').read_bytes())
                        for lane in REGULAR_LANES]
        expected, repeat, actual = observations
        write(output / 'expected.json', expected)
        write(output / 'repeat-original.json', repeat)
        write(output / 'actual.json', actual)
        differences = [{'index': i, 'original_a': a, 'original_b': b, 'candidate': c}
                       for i, (a, b, c) in enumerate(zip(expected, repeat, actual))
                       if a != b or a != c]
        write(output / 'differences.json', differences)
        require(all(len(rows) == 8 for rows in observations) and not differences
                and canonical(expected) == canonical(repeat) == canonical(actual),
                'complete matched admission original comparison differs')
        final_a, final_b, final_c = [row['final_fds'] for row in lane_reports]
        require(final_a == final_b, 'repeat-original final FD state differs')
        lifecycle = {'schema': 'hepta.hia.native-admission-regular-fd-lifecycle.v' + version,
                     'status': ('FD_STATES_EQUAL_IN_OBSERVED_DOMAIN' if final_a == final_c
                                else 'FD_SEMANTICS_DIFFERENT'),
                     'original_repeat_equal': True, 'candidate_end_state_equal': final_a == final_c,
                     'cutpoint': 'AFTER_ALL_EIGHT_BEFORE_TERMINAL_REPORT_FILES',
                     'close_call_or_count_claimed': False, 'fd_cleanup_performed': False,
                     'directory_probes': [row['directory_fd_after_all_eight'] for row in lane_reports],
                     'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False}
        write(output / 'fd-lifecycle.json', lifecycle)
        from hepta import hia_native_admission_io as io
        flags = [];inheritable = []
        captured = io._CAPABILITIES
        def observe_open(*args, **kwargs):
            descriptor = captured[io._OPEN](*args, **kwargs)
            flags.append(descriptor)
            inheritable.append(posix.get_inheritable(descriptor))
            return descriptor
        changed = list(captured);changed[io._OPEN] = observe_open
        capsule = io._AdmissionIO(tuple(changed))
        require(capsule.regular_bytes(base / 'small', 4096) == (base / 'small').read_bytes(),
                'explicit admission reader returned different bytes')
        require(len(flags) == 1 and not descriptor_open(flags[0]) and inheritable == [False],
                'healthy admission descriptor escaped or lacked CLOEXEC')
        write(output / 'healthy-descriptor.json', {
            'opened': flags, 'inheritable': inheritable, 'one_descriptor_closed': True})
        return {'count': 8, 'lanes': list(REGULAR_LANES), 'actual_outcome_calls': 24,
                'differences': 0, 'one_descriptor_closed': True,
                'fd_lifecycle_status': lifecycle['status'],
                'qualification_scope': 'MATCHED_INITIAL_FD_FINITE_VALUE_ERROR_OBSERVER_ONLY',
                'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False,
                'legacy_v1_failure_reclassified': False}


def _matched_main(args):
    import time
    version = _regular_version(args.regular_observer)
    require(args.action == 'regular' and args.manifest is None,
            'matched observer is only the explicit Source regular successor')
    if args.regular_lane is not None:
        require(args.regular_base is not None and args.regular_plan is not None,
                'matched lane lacks actual input root/plan')
        return _matched_lane(args)
    require(args.regular_base is None and args.regular_plan is None,
            'top-level matched observer acquired lane-only arguments')
    args.output.mkdir(mode=0o700)
    before = sources();write(args.output / 'source-before.json', before)
    report = {'schema': 'hepta.hia.native-admission-regular-matched-control.v' + version,
              'status': 'HOLD', 'action': 'regular', 'observer': args.regular_observer,
              'pid': posix.getpid(), 'ppid': posix.getppid(), 'pgid': posix.getpgrp(),
              'runtime': {'executable': sys.executable, 'version': sys.version,
                          'implementation': sys.implementation.name},
              'started_monotonic_ns': time.monotonic_ns(), 'source_before': before,
              'qualified_whole_native_stack': False, 'native_Capture_inputs_replaced': False,
              'whole_admission_qualification': 'HOLD', 'all_input_equivalence': False,
              'legacy_v1_failure_reclassified': False}
    failure = None
    try:
        report['observations'] = _matched_regular(args.output, before, observer=args.regular_observer)
        report['status'] = REGULAR_MATCHED
    except BaseException as error:
        report['error'] = error_record(error);failure = error
    finally:
        report['source_after'] = sources()
        report['source_unchanged'] = report['source_after'] == before
        if not report['source_unchanged']:
            report['status'] = 'HOLD'
        report['ended_monotonic_ns'] = time.monotonic_ns()
        report['files'] = {str(path.relative_to(args.output)): {
            'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for path in sorted(args.output.rglob('*')) if path.is_file()
            for raw in [path.read_bytes()]}
        write(args.output / 'report.json', report)
    if failure is not None:
        raise failure
    require(report['source_unchanged'], 'actual matched observer source changed')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', required=True, choices=ACTIONS)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--regular-observer', choices=('matched-v2', 'matched-v3'))
    parser.add_argument('--regular-lane', choices=REGULAR_LANES)
    parser.add_argument('--regular-base', type=Path)
    parser.add_argument('--regular-plan', type=Path)
    args = parser.parse_args()
    if args.regular_observer in ('matched-v2', 'matched-v3'):
        return _matched_main(args)
    require(args.regular_lane is None and args.regular_base is None and args.regular_plan is None,
            'legacy observer does not accept matched-only lane arguments')
    args.output.mkdir(mode=0o700)
    before = sources();write(args.output / 'source-before.json', before)
    report = {'schema': 'hepta.hia.native-admission-io-control.v1', 'action': args.action,
              'qualified_whole_native_stack': False, 'native_Capture_inputs_replaced': False,
              'pid': os.getpid(), 'ppid': os.getppid(), 'pgid': os.getpgrp(),
              'runtime': {'executable': sys.executable, 'version': sys.version,
                          'implementation': sys.implementation.name},
              'status': 'HOLD', 'source_before': before}
    failure = None
    try:
        simple = {'paths': path_controls, 'regular': regular_controls,
                  'io-failures': io_failure_controls,
                  'resolver-failures': resolver_failure_controls,
                  'cold-source': cold_source_controls}
        if args.action in simple:
            report['observations'] = simple[args.action](args.output)
        else:
            require(args.manifest is not None, 'native control requires explicit actual manifest')
            report['manifest'] = {'path': str(args.manifest), 'sha256': sha256(args.manifest.read_bytes()).hexdigest()}
            run = {'admission': admission_controls, 'cold-public': cold_public_controls,
                   'pinned': pinned_controls, 'installed': installed_controls}[args.action]
            report['observations'] = run(args.manifest, args.output)
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = error_record(error);failure = error
    finally:
        after = sources();report['source_after'] = after
        report['source_unchanged'] = before == after
        if before != after:
            report['status'] = 'HOLD'
        report['files'] = {str(path.relative_to(args.output)): {
            'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for path in sorted(args.output.rglob('*')) if path.is_file()
            for raw in [path.read_bytes()]}
        write(args.output / 'report.json', report)
    if failure is not None:
        raise failure
    require(report['source_unchanged'], 'actual control source changed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
