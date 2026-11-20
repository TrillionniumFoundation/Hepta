"""Actual descriptor and actual lost-return controls for the explicit v2 contract."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import traceback
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_store_file_capture_controls import attributes, forbidden, write

ORDINARY_CASES = ('normal', 'directory', 'fdopen-before', 'fdopen-after',
                  'close-before', 'close-after')
CLOSE_PORTS = ('stable_close_normal', 'stable_close_error')
ACK_EVENTS = ('CLAIM', 'SUCCEEDED', 'RAISED')
FAMILIES = ('RuntimeError', 'KeyboardInterrupt', 'SystemExit', 'MemoryError')


def error_record(error, fault, seen=None):
    if error is None:
        return None
    if seen is None:
        seen = set()
    if id(error) in seen:
        return {'cycle_to_same_live_error': True}
    seen.add(id(error))
    return {'type': type(error).__module__ + '.' + type(error).__qualname__,
            'args': list(error.args), 'text': str(error), 'errno': getattr(error, 'errno', None),
            'code': getattr(error, 'code', None), 'name': getattr(error, 'name', None),
            'obj_type': None if getattr(error, 'obj', None) is None else
                        type(error.obj).__module__ + '.' + type(error.obj).__qualname__,
            'same_fault': error is fault, 'suppress_context': error.__suppress_context__,
            'cause': error_record(error.__cause__, fault, seen),
            'context': error_record(error.__context__, fault, seen)}


def ordinary(manifest, label, lane, path, output):
    from hepta import hia_agent_store as api
    from hepta import hia_store_file_capture_native as native
    real = api.os
    fault = OSError('declared owned-fd provider error')
    events, opened, close_attempts, close_completed, keyword_values = [], [], [], [], []

    class Provider:
        def __getattr__(self, name):
            return getattr(real, name)
        def open(self, *args, **kwargs):
            fd = real.open(*args, **kwargs)
            opened.append(fd)
            events.append(['open.returned', fd])
            return fd
        def fdopen(self, fd, mode, *, closefd=True):
            keyword_values.append(closefd)
            events.append(['fdopen', fd, mode, closefd])
            if closefd is not False:
                raise AssertionError('v2 did not explicitly retain descriptor ownership')
            if label == 'fdopen-before':
                raise fault
            stream = real.fdopen(fd, mode, closefd=closefd)
            if label == 'fdopen-after':
                raise fault
            return stream
        def close(self, fd):
            close_attempts.append(fd)
            events.append(['close.before', fd])
            if label == 'close-before':
                raise fault
            real.close(fd)
            close_completed.append(fd)
            events.append(['close.after', fd])
            if label == 'close-after':
                raise fault

    prior = os.environ.get(native.SELECTOR)
    if lane == 'selected':
        os.environ[native.SELECTOR] = str(manifest)
    else:
        os.environ.pop(native.SELECTOR, None)
    before = set(os.listdir('/proc/self/fd'))
    result, raw_traceback = None, []
    try:
        with attributes(api, {'os': Provider()}):
            if lane == 'selected':
                with attributes(api, {'_STABLE_READ_REFERENCE': forbidden,
                                      '_CAPTURE_PATH_REFERENCE': forbidden}):
                    try:
                        value = api.stable_read(path, 64)
                    except BaseException as error:
                        result = {'error': error_record(error, fault)}
                        raw_traceback = traceback.format_exception(error)
                    else:
                        result = {'return': value.hex()}
            else:
                try:
                    value = api._STABLE_READ_REFERENCE(path, 64)
                except BaseException as error:
                    result = {'error': error_record(error, fault)}
                    raw_traceback = traceback.format_exception(error)
                else:
                    result = {'return': value.hex()}
    finally:
        if prior is None:
            os.environ.pop(native.SELECTOR, None)
        else:
            os.environ[native.SELECTOR] = prior
    after = set(os.listdir('/proc/self/fd'))
    if len(opened) != 1 or close_attempts != opened or keyword_values != [False]:
        raise AssertionError('owned fd was not acquired and close attempted exactly once')
    expected_closed = 0 if label == 'close-before' else 1
    if len(close_completed) != expected_closed:
        raise AssertionError('actual close completion differs from the declared provider effect')
    if (len(after - before) != (1 if label == 'close-before' else 0)
            or before - after):
        raise AssertionError('v2 descriptor endpoint differs')
    # A declared close-before fault leaves the actual fd open. No observer
    # closes it; the owned fresh process exit is the cleanup boundary.
    semantic = {'result': result, 'fdopen_closefd': keyword_values,
                'open_count': len(opened), 'close_attempt_count': len(close_attempts),
                'close_completed_count': len(close_completed),
                'gained_count': len(after - before), 'lost_count': len(before - after)}
    write(output / 'control.json', {
        'schema': 'hepta.hia.store-file-capture-owned-fd-ordinary.v2',
        'label': label, 'lane': lane, 'semantic': semantic,
        'raw_events': events, 'before_fd_names': sorted(before),
        'after_fd_names': sorted(after), 'raw_traceback': raw_traceback,
        'observer_closed_descriptor': False, 'process_exit_cleanup_boundary': True})


def lost_close_ack(manifest, port, event_name, family, output):
    from hepta import hia_agent_store as api
    from hepta import hia_store_file_capture_native as native
    image = native.installed_store_file_capture(manifest)
    entry, real = image._entry, api.os
    fault = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt,
             'SystemExit': SystemExit, 'MemoryError': MemoryError}[family]('actual v2 return lost')
    ordinary_error = OSError('declared close error after actual close')
    packets, lost, close_attempts, closed, keywords = [], [], [], [], []
    selected_event = getattr(native, event_name)

    class Provider:
        def __getattr__(self, name):
            return getattr(real, name)
        def fdopen(self, fd, mode, *, closefd=True):
            keywords.append(closefd)
            if closefd is not False:
                raise AssertionError('stream stole the v2 descriptor')
            return real.fdopen(fd, mode, closefd=closefd)
        def close(self, fd):
            close_attempts.append(fd)
            real.close(fd)
            closed.append(fd)
            if event_name == 'RAISED':
                raise ordinary_error

    def observed(source, size, result, capacity, state, extent):
        packet = struct.unpack('<10Q', ctypes.string_at(source, size))
        code = entry(source, size, result, capacity, state, extent)
        packets.append(list(packet))
        if (not lost and packet[1] == selected_event and packet[3] == native.PORT[port]
                and packet[5] == native.STABLE_READ):
            lost.append({'code': code, 'request': list(packet),
                         'output': ctypes.string_at(result, capacity).hex(),
                         'state': ctypes.string_at(state, extent).hex()})
            raise fault
        return code

    with tempfile.TemporaryDirectory(prefix='hia-owned-fd-v2-loss-') as temporary:
        path = Path(temporary) / 'data'
        path.write_bytes(b'payload')
        namespace = dict(vars(api))
        namespace['os'] = Provider()
        image._entry = observed
        frame = native.StoreFileCaptureFrame(image, native.STABLE_READ,
            {'path': path, 'limit': 0 if port == 'stable_close_error' else 64,
             'dir_fd': None}, namespace=namespace)
        try:
            frame.finish()
        except BaseException as error:
            if error is not fault:
                raise AssertionError('real lost-close return changed exception identity') from error
        else:
            raise AssertionError('unconfirmed close returned success')
        if (len(lost) != 1 or lost[0]['code'] != native.OUTPUT_BYTES
                or frame._delivery.loss is None or not frame.fenced or frame.finished):
            raise AssertionError('actual pending return custody was not retained')
        expected_close_count = 0 if event_name == 'CLAIM' else 1
        if (len(close_attempts) != expected_close_count or len(closed) != expected_close_count
                or keywords != [False]):
            raise AssertionError('close claim was confused with effect completion or close was retried')
        raw_state = bytes.fromhex(lost[0]['state'])
        if struct.unpack('<16Q', raw_state)[9] != native.FD_CLOSE_CLAIMED:
            raise AssertionError('control did not reach the actual HIA close claim')
        before = len(packets)
        try:
            frame.finish()
        except native.StoreFileCaptureUnknown:
            pass
        else:
            raise AssertionError('unknown close frame replayed')
        if len(packets) != before:
            raise AssertionError('reuse performed native work')
        write(output / 'control.json', {
            'schema': 'hepta.hia.store-file-capture-owned-fd-ACK-loss.v2',
            'port': port, 'event': event_name, 'family': family,
            'same_exception': True, 'loss_retained': True, 'fenced': True,
            'packets': packets, 'lost': lost, 'close_attempts': close_attempts,
            'actual_close_completions': closed, 'expected_close_count': expected_close_count,
            'extra_replay_entries': 0, 'claim_is_close_confirmation': False,
            'observer_closed_descriptor': False, 'process_exit_cleanup_boundary': True})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ordinary', choices=ORDINARY_CASES)
    parser.add_argument('--lane', choices=('original', 'selected'))
    parser.add_argument('--path', type=Path)
    parser.add_argument('--port', choices=CLOSE_PORTS)
    parser.add_argument('--event', choices=ACK_EVENTS)
    parser.add_argument('--family', choices=FAMILIES)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    if args.ordinary is not None:
        if args.lane is None or args.path is None or args.port or args.event or args.family:
            parser.error('ordinary control arguments differ')
        ordinary(args.manifest, args.ordinary, args.lane, args.path, args.output)
    else:
        if args.port is None or args.event is None or args.family is None or args.lane or args.path:
            parser.error('lost-ACK control arguments differ')
        lost_close_ack(args.manifest, args.port, args.event, args.family, args.output)

if __name__ == '__main__':
    main()
