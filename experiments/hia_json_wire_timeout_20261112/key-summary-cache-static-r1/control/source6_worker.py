"""One frozen 04 source/Core-VM phase; no native loader/compiler/subprocess."""
from hashlib import sha256
import ctypes
import importlib
import json
import mmap
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def record(path):
    path = Path(path)
    before = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1 and before.st_size <= 64 << 20, 'fixed regular file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(all(getattr(os.fstat(fd), k) == getattr(before, k) for k in FIELDS), 'file changed at open')
        pieces, size = [], 0
        while block := os.read(fd, 1 << 20):
            size += len(block)
            require(size <= before.st_size, 'file grew')
            pieces.append(block)
        after, named = os.fstat(fd), path.lstat()
        require(size == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(named, k)
                                               for k in FIELDS), 'file identity changed')
    finally:
        os.close(fd)
    raw = b''.join(pieces)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': {k: getattr(before, k) for k in FIELDS}}, raw


def write_raw(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    got, body = record(path)
    require(body == raw, 'new original readback differs')
    return got


def save(path, value):
    return write_raw(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def inventory(folder):
    files, directories = {}, []
    for path in sorted(folder.rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            require(path.resolve() == path, 'directory alias refused')
            directories.append(str(path.relative_to(folder)))
        else:
            files[str(path.relative_to(folder))] = record(path)[0]
    return {'files': files, 'directories': directories}


def main():
    request_pin, raw = record(ROOT / 'SOURCE6-REQUEST.json')
    request = json.loads(raw)
    require(request['schema'] == 'hepta.hia.json-wire-key-summary.source6-request.v1'
            and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3
            and len(request['expected_ids']) == 6, 'source six request scope differs')
    require(tuple(sys.version_info[:3]) == (3, 12, 14), 'local development runtime differs')
    require(not any(name.startswith('HEPTA_HIA_') for name in os.environ), 'selected image environment refused')
    output, source = Path(request['operation_root']), Path(request['source_root'])
    require(output.is_dir() and not os.path.lexists(output / 'REPORT.json'), 'parent-created fresh output required')
    report = {'schema': 'hepta.hia.json-wire-key-summary.source6-report.v1', 'status': 'HOLD',
              'request': request_pin, 'scope': 'LOCAL312_GENERATION_AND_SIX_SOURCE_CORE_VM_ONLY',
              'expected_ids': request['expected_ids'], 'loaded_ids': [], 'actual_ids': [], 'tests_run': 0,
              'failures': [], 'errors': [], 'skipped': [], 'expected_failures': [], 'unexpected_successes': [],
              'forbidden_attempts': [], 'native_executed': False,
              'old_wire89_or_native7_or_native6_executed': False,
              'old_5_second_assertion_modified': False, 'whole_stack_qualification': False}
    started = time.monotonic()
    before = None
    try:
        for name, expected in request['input_pins'].items():
            require(record(name)[0] == expected, 'frozen source/runtime/control changed: ' + name)
        before = inventory(source)
        require(before == request['source_before'], 'full physical source subset differs')
        save(output / 'SOURCE-BEFORE.json', before)
        sys.path.insert(0, str(source))
        attempts = report['forbidden_attempts']

        def forbidden(label):
            def stop(*args, **kwargs):
                attempts.append(label)
                raise AssertionError('forbidden source-phase entry: ' + label)
            return stop

        def audit(event, args):
            if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.fork', 'os.forkpty',
                         'os.posix_spawn', 'os.posix_spawnp', 'ctypes.dlopen', 'ctypes.dlsym'):
                attempts.append(event)
                raise AssertionError('forbidden source-phase audit event: ' + event)

        real_mmap = mmap.mmap
        def data_mmap(*args, **kwargs):
            prot = kwargs.get('prot', args[3] if len(args) > 3 else mmap.PROT_READ | mmap.PROT_WRITE)
            if prot & mmap.PROT_EXEC:
                return forbidden('executable-mmap')()
            return real_mmap(*args, **kwargs)

        # The stdlib ctypes memory primitives above are already initialized.
        # Keep raw byte transport; deny new executable images/callables/processes.
        sys.addaudithook(audit)
        subprocess.Popen = forbidden('subprocess.Popen')
        subprocess.run = forbidden('subprocess.run')
        ctypes.CDLL = forbidden('ctypes.CDLL')
        ctypes.PyDLL = forbidden('ctypes.PyDLL')
        ctypes.CFUNCTYPE = forbidden('ctypes.CFUNCTYPE')
        ctypes.PYFUNCTYPE = forbidden('ctypes.PYFUNCTYPE')
        mmap.mmap = data_mmap
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        NativeHiaJsonImage.__init__ = forbidden('native-image-construction')
        from tools.generate_hia_json_wire import document, source_program, SOURCE_PATH
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        generation_started = time.monotonic()
        doc = document()
        assembly = render_assembly(doc).encode()
        generated = source / SOURCE_PATH
        require(generated == source / 'examples/hia_bootstrap/json_wire.hiaasm'
                and not os.path.lexists(generated), 'one fresh generated HIA source only')
        generated.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        report['generated_source'] = write_raw(generated, assembly)
        report['assembly_original'] = write_raw(output / 'json_wire.hiaasm', assembly)
        report['authoring_original'] = write_raw(output / 'authoring.py.txt', source_program().encode())
        report['core_document_original'] = save(output / 'core-document.json', doc)
        require(assemble_program(assembly).as_dict() == doc, 'complete Core/assembly roundtrip differs')
        report['generation_seconds'] = time.monotonic() - generation_started
        suite = unittest.defaultTestLoader.loadTestsFromNames(request['expected_ids'])
        def flatten(node):
            for item in node:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item
        report['loaded_ids'] = [test.id() for test in flatten(suite)]
        require(report['loaded_ids'] == request['expected_ids'] and not unittest.defaultTestLoader.errors,
                'exact six source methods did not load')
        class Result(unittest.TextTestResult):
            def startTest(self, test):
                report['actual_ids'].append(test.id())
                super().startTest(test)
        with (output / 'unittest.log').open('x') as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
        report['tests_run'] = result.testsRun
        for key, field in (('failures', 'failures'), ('errors', 'errors'), ('skipped', 'skipped'),
                           ('expected_failures', 'expectedFailures'), ('unexpected_successes', 'unexpectedSuccesses')):
            report[key] = [str(item) for item in getattr(result, field)]
        require(result.wasSuccessful() and result.testsRun == 6
                and report['actual_ids'] == report['loaded_ids'] == report['expected_ids']
                and not any(report[key] for key in ('failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
                and attempts == [], 'source six controls incomplete, failed, or entered a forbidden path')
        report['status'] = 'SOURCE6_PASS_ONLY'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    finally:
        try:
            after = inventory(source)
            report['source_after'] = save(output / 'SOURCE-AFTER.json', after)
            if before is not None:
                old = before['files']
                require(all(after['files'].get(name) == expected for name, expected in old.items()),
                        'fixed source bytes or identity changed')
                extra = set(after['files']) - set(old)
                require(extra <= {'examples/hia_bootstrap/json_wire.hiaasm'}, 'unexpected source output')
                require(set(before['directories']) <= set(after['directories'])
                        and set(after['directories']) - set(before['directories'])
                        <= {'examples', 'examples/hia_bootstrap'}, 'source directory population changed')
                if report['status'] == 'SOURCE6_PASS_ONLY':
                    require(extra == {'examples/hia_bootstrap/json_wire.hiaasm'}, 'generated source missing')
                    require(set(after['directories']) - set(before['directories'])
                            == {'examples', 'examples/hia_bootstrap'}, 'generated directory population differs')
                    require(after['files']['examples/hia_bootstrap/json_wire.hiaasm'] == report['generated_source'],
                            'generated source changed after verification')
            report['inputs_after'] = {name: record(name)[0] for name in request['input_pins']}
            require(report['inputs_after'] == request['input_pins'], 'frozen external input changed')
            report['project_modules'] = {name: str(Path(module.__file__).resolve())
                for name, module in sorted(sys.modules.items())
                if name.split('.')[0] in ('hepta', 'tools', 'tests') and getattr(module, '__file__', None)}
            require(all(Path(path).is_relative_to(source) for path in report['project_modules'].values()),
                    'project import escaped the frozen source subset')
        except BaseException as error:
            report['status'] = 'HOLD'
            report['preservation_error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
        report['seconds'] = time.monotonic() - started
        save(output / 'REPORT.json', report)
    print(json.dumps({'status': report['status'], 'tests_run': report['tests_run'],
                      'forbidden_attempts': len(report['forbidden_attempts']), 'seconds': report['seconds']}))
    return 0 if report['status'] == 'SOURCE6_PASS_ONLY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
