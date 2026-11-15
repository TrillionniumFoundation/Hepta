"""Independent real-OS, complete-buffer and actual lost-ACK controls.

No original expected value is obtained from the candidate graph. Unknown
descriptor cases run in owned fresh processes and retain their record until
that process exits; they never clear the shared registry to make cleanup pass.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_store_file_capture_oracle import canonical
from tools.qualify_hia_store_file_capture_originals import stop_owned

def write(path, value):
    raw = canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()

def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}

def run_process(output, label, arguments, *, env, body=None, expected=0, timeout=60):
    output = Path(output)
    command = [sys.executable, '-I', '-B', *map(str, arguments)]
    start_ns, started = time.time_ns(), time.monotonic()
    process = None
    timed_out, cleanup, cleanup_error = False, None, None
    with (output / (label + '.stdout.log')).open('xb') as out, \
         (output / (label + '.stderr.log')).open('xb') as err:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE,
                                       stdout=out, stderr=err, start_new_session=True)
            write(output / (label + '.start.json'), {'command': command, 'cwd': str(ROOT),
                  'pid': process.pid, 'pgid': process.pid, 'started_time_ns': start_ns,
                  'timeout_seconds': timeout, 'cleanup_seconds': 3})
            try:
                process.communicate(body, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if process is not None:
                try:
                    cleanup = stop_owned(process)
                except BaseException as error:
                    cleanup_error = {'type': type(error).__name__, 'text': str(error)}
    stdout = (output / (label + '.stdout.log')).read_bytes()
    stderr = (output / (label + '.stderr.log')).read_bytes()
    receipt = {'command': command, 'cwd': str(ROOT), 'pid': None if process is None else process.pid,
               'pgid': None if process is None else process.pid, 'started_time_ns': start_ns,
               'ended_time_ns': time.time_ns(), 'elapsed_seconds': time.monotonic() - started,
               'timeout_seconds': timeout, 'cleanup_seconds': 3, 'timeout': timed_out,
               'returncode': None if process is None else process.returncode,
               'expected_returncode': expected, 'cleanup': cleanup, 'cleanup_error': cleanup_error,
               'stdout_sha256': sha256(stdout).hexdigest(), 'stderr_sha256': sha256(stderr).hexdigest()}
    write(output / (label + '.result.json'), receipt)
    if (process is None or timed_out or cleanup_error or process.returncode != expected
            or cleanup is None or cleanup['after']):
        raise AssertionError(receipt)
    return stdout, stderr, receipt

@contextmanager
def attributes(target, values):
    before = {key: getattr(target, key) for key in values}
    for key, value in values.items():
        setattr(target, key, value)
    try:
        yield
    finally:
        for key, value in before.items():
            setattr(target, key, value)

def forbidden(*args, **kwargs):
    raise AssertionError('selected file capture called a retained whole body')

def _record_real_os_fd_failure(output, label, before, after, provider, result):
    """Failure-only diagnostics; no observed provider descriptor is repaired."""
    targets = []
    for descriptor in sorted(before | after):
        row = {'descriptor': descriptor, 'in_before': descriptor in before,
               'in_after': descriptor in after}
        try:
            row['target'] = os.readlink('/proc/self/fd/' + descriptor)
        except OSError as error:
            row['lookup_error'] = {
                'type': type(error).__module__ + '.' + type(error).__qualname__,
                'errno': error.errno, 'text': str(error)}
        targets.append(row)
    provider_type = type(provider)
    write(Path(output) / 'real-os-fd-failure.json', {
        'schema': 'hepta.hia.file-capture-real-os-fd-failure.v1',
        'diagnostic_only': True, 'fd_comparison_already_failed': True,
        'case_label': label,
        'before': sorted(before), 'after': sorted(after),
        'gained': sorted(after - before), 'lost': sorted(before - after),
        'provider': {
            'type': provider_type.__module__ + '.' + provider_type.__qualname__,
            'module': getattr(provider, '__module__', None),
            'name': getattr(provider, '__name__', None),
            'qualname': getattr(provider, '__qualname__', None)},
        'result': result,
        'fd_targets': targets,
        'fd_targets_phase': 'after_set_mismatch_before_original_assertion',
        'fd_target_identity_before_provider_observed': False,
        'descriptor_leak_direction_assumed': False,
        'descriptor_cleanup_performed': False})


def real_os_cases(manifest, output):
    from hepta import hia_agent_store as api
    from hepta import hia_store_file_capture_native as native
    image = native.installed_store_file_capture(manifest)
    rows = []
    with tempfile.TemporaryDirectory(prefix='hia-capture-real-') as temporary:
        root = Path(temporary)
        allowed = root / 'allowed'; allowed.mkdir()
        nested = allowed / 'a'; nested.mkdir()
        target = nested / 'data'; target.write_bytes(b'bounded\x00binary\n')
        outside = root / 'outside'; outside.write_bytes(b'not authorized')
        (allowed / 'link').symlink_to(outside)
        (allowed / 'dirlink').symlink_to(root, target_is_directory=True)
        os.mkfifo(allowed / 'fifo')
        cases = [
            ('ordinary', str(target), [allowed], 64),
            ('empty', str(allowed / 'empty'), [allowed], 0),
            ('outside', str(outside), [allowed], 64),
            ('file_symlink', str(allowed / 'link'), [allowed], 64),
            ('directory_symlink', str(allowed / 'dirlink/outside'), [allowed], 64),
            ('fifo', str(allowed / 'fifo'), [allowed], 64),
            ('directory', str(nested), [allowed], 64),
            ('extent', str(target), [allowed], 3),
            ('relative', 'relative', [allowed], 64),
            ('no_root', str(target), [], 64),
            ('root_itself', str(allowed), [allowed], 64),
            ('traversal', str(allowed) + '/../outside', [allowed], 64),
        ]
        (allowed / 'empty').write_bytes(b'')
        for label, path, roots, limit in cases:
            def observe(provider):
                before = set(os.listdir('/proc/self/fd'))
                try:
                    value = provider(path, roots, limit)
                    result = {'bytes': value.hex()}
                except BaseException as error:
                    result = {'type': type(error).__name__, 'text': str(error),
                              'code': getattr(error, 'code', None),
                              'cause_type': None if error.__cause__ is None else type(error.__cause__).__name__}
                after = set(os.listdir('/proc/self/fd'))
                if before != after:
                    try:
                        _record_real_os_fd_failure(output, label, before, after, provider, result)
                    finally:
                        # Diagnostics cannot replace or bypass the original failure.
                        raise AssertionError('ordinary real-OS control leaked a descriptor')
                return result
            # Both complete literal originals are used only for expected data.
            with attributes(api, {'stable_read': api._STABLE_READ_REFERENCE}):
                original = observe(api._CAPTURE_PATH_REFERENCE)
            saved = os.environ.get(native.SELECTOR)
            os.environ[native.SELECTOR] = str(manifest)
            try:
                with attributes(api, {'_STABLE_READ_REFERENCE': forbidden, '_CAPTURE_PATH_REFERENCE': forbidden}):
                    actual = observe(api.capture_path)
            finally:
                if saved is None:
                    os.environ.pop(native.SELECTOR, None)
                else:
                    os.environ[native.SELECTOR] = saved
            if canonical(original) != canonical(actual):
                raise AssertionError({'id': label, 'original': original, 'actual': actual})
            rows.append({'id': label, 'original': original, 'actual': actual})
    write(output / 'real-os.json', {'scope': '12 complete literal original/public selected cases',
                                   'observations': rows, 'raw_syscall_primitive_substituted': False})
    return rows


def real_os_races(manifest, output):
    """Three controlled real namespace/identity races through complete providers."""
    from hepta import hia_agent_store as api
    from hepta import hia_store_file_capture_native as native
    rows=[]
    for kind in ('directory-renamed-after-open', 'file-replaced-by-fifo', 'same-size-identity-change'):
        lanes=[]
        for selected in (False,True):
            with tempfile.TemporaryDirectory(prefix='hia-capture-race-') as temporary:
                root=Path(temporary);allowed=root/'allowed';allowed.mkdir()
                component=allowed/'a';component.mkdir()
                target=component/'data';target.write_bytes(b'authorized')
                elsewhere=root/'elsewhere';elsewhere.mkdir()
                (elsewhere/'data').write_bytes(b'outside')
                actual_open,actual_fstat=api.os.open,api.os.fstat
                actions=[];stats=[0]
                def open_at(path,flags,*args,**kwargs):
                    if kind=='file-replaced-by-fifo' and path=='data' and not actions:
                        target.unlink();os.mkfifo(target);actions.append('fifo-before-file-open')
                    fd=actual_open(path,flags,*args,**kwargs)
                    if kind=='directory-renamed-after-open' and path=='a' and not actions:
                        component.rename(allowed/'held-a')
                        component.symlink_to(elsewhere,target_is_directory=True)
                        actions.append('rename-after-directory-open')
                    return fd
                def fstat(fd):
                    result=actual_fstat(fd);stats[0]+=1
                    if kind=='same-size-identity-change' and stats[0]==1:
                        current=target.stat()
                        os.utime(target,ns=(current.st_atime_ns,current.st_mtime_ns+1_000_000_000))
                        actions.append('mtime-after-first-fstat')
                    return result
                prior=os.environ.get(native.SELECTOR);before_fds=set(os.listdir('/proc/self/fd'))
                try:
                    if selected:os.environ[native.SELECTOR]=str(manifest)
                    else:os.environ.pop(native.SELECTOR,None)
                    with attributes(api.os,{'open':open_at,'fstat':fstat}):
                        if selected:
                            with attributes(api,{'_STABLE_READ_REFERENCE':forbidden,'_CAPTURE_PATH_REFERENCE':forbidden}):
                                try:value=api.capture_path(str(target),[allowed],64)
                                except api.AgentRejected as error:result={'code':error.code,'message':str(error)}
                                else:result={'bytes':value.hex()}
                        else:
                            with attributes(api,{'stable_read':api._STABLE_READ_REFERENCE}):
                                try:value=api._CAPTURE_PATH_REFERENCE(str(target),[allowed],64)
                                except api.AgentRejected as error:result={'code':error.code,'message':str(error)}
                                else:result={'bytes':value.hex()}
                finally:
                    if prior is None:os.environ.pop(native.SELECTOR,None)
                    else:os.environ[native.SELECTOR]=prior
                if set(os.listdir('/proc/self/fd'))!=before_fds or len(actions)!=1:
                    raise AssertionError('real race was not reached or leaked a descriptor')
                lanes.append({'result':result,'actions':actions,'fstat_calls':stats[0]})
        if canonical(lanes[0])!=canonical(lanes[1]):
            raise AssertionError({'case':kind,'original':lanes[0],'actual':lanes[1]})
        if kind=='directory-renamed-after-open' and lanes[1]['result']!={'bytes':b'authorized'.hex()}:
            raise AssertionError('open directory handle did not retain the authorized inode')
        if kind=='file-replaced-by-fifo' and lanes[1]['result'].get('code')!='E_HIA_ARTIFACT_FILE':
            raise AssertionError('nonblocking regular-file check did not refuse FIFO replacement')
        if kind=='same-size-identity-change' and lanes[1]['result'].get('code')!='E_HIA_ARTIFACT_CHANGED':
            raise AssertionError('post-read descriptor identity did not reject same-size mutation')
        rows.append({'id':kind,'original':lanes[0],'actual':lanes[1]})
    write(output/'real-os-races.json',{'scope':'three controlled actual OS races',
          'rows':rows,'complete_original_and_actual_public_route':True,
          'opaque_os_provider_replaced_by_raw_primitive':False})
    return rows

class TwinEntry:
    def __init__(self, actual, program, stream):
        from tests.hia_store_file_capture_observer import VMEntry
        self.actual, self.vm, self.stream, self.calls = actual, VMEntry(program), stream, 0
    def __call__(self, source, size, output, capacity, state, extent):
        raw = ctypes.string_at(source, size)
        before_output, before_state = ctypes.string_at(output, capacity), ctypes.string_at(state, extent)
        a = ctypes.create_string_buffer(raw, size)
        b = ctypes.create_string_buffer(before_output, capacity)
        c = ctypes.create_string_buffer(before_state, extent)
        expected = self.vm(a, size, b, capacity, c, extent)
        actual = self.actual(source, size, output, capacity, state, extent)
        actual_output, actual_state = ctypes.string_at(output, capacity), ctypes.string_at(state, extent)
        row = {'request': raw.hex(), 'output_before': before_output.hex(), 'state_before': before_state.hex(),
               'VM_code': expected, 'native_code': actual, 'VM_output': b.raw.hex(),
               'native_output': actual_output.hex(), 'VM_state': c.raw.hex(), 'native_state': actual_state.hex()}
        self.stream.write(canonical(row) + b'\n')
        self.calls += 1
        if raw != ctypes.string_at(source, size) or expected != actual or b.raw != actual_output or c.raw != actual_state:
            raise AssertionError('complete native/VM ABI buffers differ')
        return actual

def packet_cases(manifest, output):
    from hepta import hia_store_file_capture_native as native
    from hepta.hia_agent_assembly import assemble_program
    from tests import hia_store_file_capture_oracle as oracle
    from tests.hia_store_file_capture_observer import _FORWARD_CODE
    image = native.installed_store_file_capture(manifest)
    original_entry = image._entry
    inputs_raw = (ROOT / 'tests/fixtures/hia_store_file_capture_inputs_v1.json').read_bytes()
    cases = json.loads(inputs_raw)['cases']
    with (output / 'complete-packets.jsonl').open('xb') as stream:
        twin = TwinEntry(original_entry, assemble_program(native.SOURCE.read_bytes()), stream)
        image._entry = twin
        def factory(namespace, mode):
            old = namespace['stable_read']
            overridden = old.__class__.__name__ == 'method'
            namespace.update(_FRAME=native.StoreFileCaptureFrame, _IMAGE=image, _NAMESPACE=namespace)
            exec(_FORWARD_CODE, namespace)
            if overridden:
                namespace['stable_read'] = old
            return namespace['capture_path' if mode == 'capture' else 'stable_read']
        try:
            for case in cases:
                oracle.observe(case, factory=factory)
        finally:
            image._entry = original_entry
    report = {'schema': 'hepta.hia.store-file-capture-full-packets.v1',
              'inputs_sha256': sha256(inputs_raw).hexdigest(), 'count': len(cases),
              'ordered_ids': [case['id'] for case in cases], 'entries': twin.calls,
              'complete_VM_and_native_raw_copies_saved': True,
              'packets_sha256': sha256((output / 'complete-packets.jsonl').read_bytes()).hexdigest()}
    if twin.calls == 0:
        raise AssertionError('no actual packet comparison occurred')
    write(output / 'packets.json', report)
    return report

ACK_CASES = (
    ('stable.open', 1, 'stable_open'), ('stable.fdopen', 1, 'stable_fdopen'),
    ('stable.read', 1, 'stable_read'), ('stable.exit', 1, 'stable_exit_normal'),
    ('stable.release', 1, 'stable_release_locals'),
    ('capture.root', 2, 'capture_open_root'), ('capture.component', 2, 'capture_open_component'),
    ('capture.read', 2, 'capture_read'), ('capture.close', 2, 'capture_close'),
    ('capture.release', 2, 'capture_release_locals'),
    ('stable.finalize', 1, 'FINALIZE'), ('capture.finalize', 2, 'FINALIZE'),
)

def lost_ack_case(manifest, case_id, family, output):
    from hepta import hia_agent_store as api
    from hepta import hia_store_file_capture_native as native
    label, mode, port = next(row for row in ACK_CASES if row[0] == case_id)
    image = native.installed_store_file_capture(manifest)
    entry = image._entry
    fault = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt,
             'SystemExit': SystemExit, 'MemoryError': MemoryError}[family]('actual machine return lost')
    calls, lost = [], []
    def observed(source, size, result, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        code = entry(source, size, result, capacity, state, extent)
        calls.append(list(packet))
        event = native.FINALIZE if port == 'FINALIZE' else native.SUCCEEDED
        if not lost and packet[1] == event and packet[5] == mode and (
                port == 'FINALIZE' or packet[3] == native.PORT[port]):
            lost.append({'actual_code': code, 'result': ctypes.string_at(result, capacity).hex(),
                         'state': ctypes.string_at(state, extent).hex()})
            raise fault
        return code
    with tempfile.TemporaryDirectory(prefix='hia-file-ack-') as temporary:
        root = Path(temporary); (root / 'a').mkdir(); path = root / 'a/data'; path.write_bytes(b'payload')
        initial = {'path': str(path), 'limit': 64, 'dir_fd': None} if mode == 1 else {
            'path': str(path), 'roots': [root], 'limit': 64}
        image._entry = observed
        frame = native.StoreFileCaptureFrame(image, mode, initial)
        initial.clear()
        try:
            frame.finish()
        except BaseException as error:
            if error is not fault:
                raise AssertionError('actual lost-ACK exception identity changed') from error
        else:
            raise AssertionError('lost actual native return completed')
        if len(lost) != 1 or lost[0]['actual_code'] != native.OUTPUT_BYTES:
            raise AssertionError('control did not lose a real completed machine return')
        if frame._delivery.loss is None or not frame.fenced or frame.finished:
            raise AssertionError('actual unconfirmed record was not retained')
        before = len(calls)
        try:
            frame.finish()
        except native.StoreFileCaptureUnknown:
            pass
        else:
            raise AssertionError('unknown frame was replayed')
        if len(calls) != before:
            raise AssertionError('reuse issued another native request')
        # Do not repair/delete the unknown registry or close retained stream/fds.
        write(output / 'control.json', {'schema': 'hepta.hia.file-capture-ACK-loss.v1',
              'id': label, 'family': family, 'calls': calls, 'lost': lost,
              'same_exception': True, 'loss_retained': True, 'fenced': True,
              'private_data_slots': sorted(frame.data), 'extra_replay_entries': 0,
              'descriptor_retirement_claimed': False, 'process_exit_is_cleanup_boundary': True})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ack-case')
    parser.add_argument('--family', default='RuntimeError')
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    if args.ack_case:
        lost_ack_case(args.manifest, args.ack_case, args.family, args.output)
    else:
        real_os_cases(args.manifest, args.output)
if __name__ == '__main__':
    main()
