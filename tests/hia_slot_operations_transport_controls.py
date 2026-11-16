"""Actual-entry transport, lazy public selection and authority controls.

Each mutator first invokes the admitted real entry. No control writes a loss flag
or substitutes SQL. All intentional failures remain explicit owned observations.
"""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import struct
import sys
import threading
import traceback

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hia_slot_operations_qualification_support import canonical, pin, sha, write_json

TRANSPORT = ('return-short', 'return-long', 'request-byte', 'request-canary',
             'output-magic', 'output-reserved', 'output-canary',
             'state-checksum', 'state-reserved', 'state-canary',
             'identity', 'sequence')
FOREIGN_ERRORS = (MemoryError, RuntimeError, KeyboardInterrupt, SystemExit)


class PlainSubject:
    pass


class OrdinaryForeignFailure:
    def __init__(self, error):
        self.error = error
        self.assignments = []

    def __setattr__(self, name, value):
        if name in ('store', 'image'):
            self.assignments.append(name)
            raise self.error
        object.__setattr__(self, name, value)


def capture(operation):
    try:
        value = operation()
    except BaseException as error:
        return error, {'kind': 'raised', 'type': type(error).__module__ + '.' + type(error).__qualname__,
                       'message': str(error), 'cause': None if error.__cause__ is None else (
                           type(error.__cause__).__module__ + '.' + type(error.__cause__).__qualname__)}
    return None, {'kind': 'returned', 'value': value}


def frame(native, image, subject=None):
    return native.SlotOperationsFrame(image, 1,
        {'self': PlainSubject() if subject is None else subject,
         'store': object(), 'image': object()})


def modify(native, kind, source, size, output, capacity, state, extent, code):
    if kind == 'return-short':
        return code - 1
    if kind == 'return-long':
        return code + 1
    if kind == 'request-byte':
        ctypes.memmove(ctypes.addressof(source) + 127, b'\x01', 1)
    elif kind == 'request-canary':
        ctypes.memmove(ctypes.addressof(source) + size, b'\x00', 1)
    elif kind == 'output-canary':
        ctypes.memmove(ctypes.addressof(output) + capacity, b'\x00', 1)
    elif kind == 'state-canary':
        ctypes.memmove(ctypes.addressof(state) + extent, b'\x00', 1)
    elif kind.startswith('output-') or kind == 'identity':
        words = list(struct.unpack('<12Q', ctypes.string_at(output, capacity)))
        words[0 if kind == 'output-magic' else 7 if kind == 'output-reserved' else 8] ^= 1
        ctypes.memmove(output, struct.pack('<12Q', *words), capacity)
    elif kind.startswith('state-'):
        words = list(struct.unpack('<24Q', ctypes.string_at(state, extent)))
        words[10 if kind == 'state-checksum' else 13] ^= 1
        if kind == 'state-reserved':
            words[10] = native._checksum(words)
        ctypes.memmove(state, struct.pack('<24Q', *words), extent)
    elif kind == 'sequence':
        result = list(struct.unpack('<12Q', ctypes.string_at(output, capacity)))
        saved = list(struct.unpack('<24Q', ctypes.string_at(state, extent)))
        result[3] += 1
        saved[4] += 1
        saved[10] = native._checksum(saved)
        ctypes.memmove(output, struct.pack('<12Q', *result), capacity)
        ctypes.memmove(state, struct.pack('<24Q', *saved), extent)
    else:
        raise AssertionError('unknown transport dimension')
    return code


def transport(native, image, directory):
    result = []
    actual = image._entry
    for kind in TRANSPORT:
        calls, records = [], []
        def entry(source, size, output, capacity, state, extent):
            code = actual(source, size, output, capacity, state, extent)
            calls.append(code)
            records.append({'request_before_mutation': ctypes.string_at(source, size + 16).hex(),
                            'output_before_mutation': ctypes.string_at(output, capacity + 16).hex(),
                            'state_before_mutation': ctypes.string_at(state, extent + 16).hex(),
                            'actual_return': code})
            changed = modify(native, kind, source, size, output, capacity, state, extent, code)
            records[-1].update({'request_after_mutation': ctypes.string_at(source, size + 16).hex(),
                'output_after_mutation': ctypes.string_at(output, capacity + 16).hex(),
                'state_after_mutation': ctypes.string_at(state, extent + 16).hex(),
                'delivered_return': changed})
            return changed
        current = frame(native, image)
        image._entry = entry
        try:
            error, observed = capture(current.finish)
            assert isinstance(error, native.SlotOperationsUnknown), observed
            assert current._delivery.loss is not None and current.fenced
            assert calls == [native.OUTPUT_BYTES], calls
            old = len(calls)
            repeated, replay = capture(current.finish)
            assert isinstance(repeated, native.SlotOperationsUnknown) and len(calls) == old
            assert not hasattr(current.data.get('self'), 'store')
            result.append({'id': kind, 'result': observed, 'replay': replay,
                           'actual_entry_count': len(calls), 'raw': records,
                           'no_foreign_assignment': True, 'loss_was_actual_unconfirmed_entry': True})
        finally:
            image._entry = actual
    for error_type in FOREIGN_ERRORS:
        # Safe request preparation failure: original object, no native entry,
        # no irreversible effect and no newly retained unknown record.
        before = frame(native, image)
        error = error_type('declared pre-entry allocation/protocol refusal')
        buffer = native.ctypes.create_string_buffer
        def refusal(*args, **kwargs):
            raise error
        native.ctypes.create_string_buffer = refusal
        try:
            caught, observed = capture(before.finish)
            assert caught is error and before._delivery.loss is None
            assert before._delivery.retired
        finally:
            native.ctypes.create_string_buffer = buffer
        result.append({'id': 'pre-entry.' + error_type.__name__, 'result': observed,
                       'same_exception': caught is error, 'loss': False, 'retired': True})
        # Real image returned successfully, then delivery is withheld.
        after = frame(native, image)
        error = error_type('declared loss after actual entry returned')
        calls = []
        def withheld(source, size, output, capacity, state, extent):
            code = actual(source, size, output, capacity, state, extent)
            calls.append(code)
            raise error
        image._entry = withheld
        try:
            caught, observed = capture(after.finish)
            assert caught is error and after._delivery.loss is not None
            assert calls == [native.OUTPUT_BYTES]
        finally:
            image._entry = actual
        result.append({'id': 'post-entry.' + error_type.__name__, 'result': observed,
                       'same_exception': caught is error, 'loss': True,
                       'actual_entry_count': len(calls)})
    foreign_error = MemoryError('ordinary fully observed foreign exception')
    subject = OrdinaryForeignFailure(foreign_error)
    ordinary = frame(native, image, subject)
    caught, observed = capture(ordinary.finish)
    assert caught is foreign_error and ordinary._delivery.loss is None
    assert ordinary.finished and ordinary._delivery.retired and subject.assignments == ['store']
    result.append({'id': 'ordinary-confirmed-foreign', 'result': observed,
                   'same_exception': True, 'loss': False, 'actual_assignments': subject.assignments})
    write_json(directory / 'transport.json', {'planned': list(TRANSPORT) +
        [label + '.' + error.__name__ for error in FOREIGN_ERRORS for label in ('pre-entry', 'post-entry')] +
        ['ordinary-confirmed-foreign'], 'records': result, 'four_dimensions': ['return', 'request', 'output', 'state']})
    return result


def fork_refusal(captured):
    from hepta.hia_slot_operations_native import SlotOperationsUnknown
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            error, report = capture(lambda: captured((b'id', b'slot', b'1', b'{}')))
            report['rejected'] = type(error) is SlotOperationsUnknown
            os.write(write_fd, canonical(report))
            code = 0
        except BaseException:
            code = 1
        finally:
            os.close(write_fd)
        os._exit(code)
    os.close(write_fd)
    reaped, killed, result = False, False, None
    try:
        ready = select.select([read_fd], [], [], 5)[0]
        if not ready:
            raise TimeoutError('fork scope refusal did not terminate within 5 seconds')
        raw = os.read(read_fd, 65536)
        _, status = os.waitpid(child, 0)
        reaped = True
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise AssertionError('fork control did not exit normally')
        result = json.loads(raw)
    finally:
        os.close(read_fd)
        if not reaped:
            try:
                os.kill(child, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
    assert result['rejected'] and not killed
    return {'result': result, 'child_reaped': reaped, 'forced_stop': killed,
            'timeout_seconds': 5}


def selection_controls(native, image, manifest, directory, decision_manifest):
    from hepta.hia_slot_ledger_native import NativeSlotLedgerStore as Ledger
    from hepta import hia_slot_operations_selection as selection
    references = Ledger._hia_slot_reference_methods
    old_references = dict(references)
    old_environment = dict(os.environ)
    old_source = native.SOURCE
    actual = image._entry
    calls, retained = [], []
    def counted(*arguments):
        result = actual(*arguments)
        calls.append(result)
        return result
    def forbidden(*arguments, **keywords):
        retained.append(True)
        raise AssertionError('selected scope called retained original')
    values = (b'Sid', b'Sslot', b'S1', b'{}')
    records = []
    image._entry = counted
    try:
        for name in list(os.environ):
            if name.startswith(('HEPTA_HIA', 'PYTHON')):
                os.environ.pop(name)
        # Absence returns the exact retained descriptor with no admission.
        original = references['_lease_value'].__func__
        assert original(values) == {'id': 'id', 'slot': 'slot', 'generation': '1', 'artifact': {}}
        assert Ledger._lease_value is original
        empty_before = len(calls)
        os.environ[native.SELECTOR] = ''
        looked_up = Ledger._lease_value
        assert len(calls) == empty_before
        error, report = capture(lambda: looked_up(values))
        assert isinstance(error, ValueError) and len(calls) == empty_before
        records.append({'id': 'empty-lazy', 'result': report, 'entries': 0})
        os.environ.pop(native.SELECTOR)
        for name, method in old_references.items():
            references[name] = staticmethod(forbidden) if type(method) is staticmethod else forbidden
        image._entry = counted
        with selection.slot_operations_owner(str(manifest), image=image):
            instance = object.__new__(Ledger)
            a = Ledger._lease_value(values)
            b = instance._lease_value(values)
            assert a == b == {'id': 'id', 'slot': 'slot', 'generation': '1', 'artifact': {}}
            captured = Ledger._lease_value
            baseline = len(calls)
            errors = []
            def in_thread():
                error, report = capture(lambda: captured(values))
                errors.append((error, report))
            thread = threading.Thread(target=in_thread, daemon=True)
            thread.start()
            thread.join(5)
            assert not thread.is_alive() and len(errors) == 1
            assert isinstance(errors[0][0], native.SlotOperationsUnknown)
            assert len(calls) == baseline
            records.append({'id': 'foreign-thread', 'result': errors[0][1], 'entries': 0, 'timeout_seconds': 5})
            fork = fork_refusal(captured)
            assert len(calls) == baseline
            records.append({'id': 'foreign-pid', **fork, 'parent_entries': 0})
        error, report = capture(lambda: captured(values))
        assert isinstance(error, native.SlotOperationsUnknown) and len(calls) == baseline
        records.append({'id': 'captured-after-scope', 'result': report, 'entries': 0})
        assert retained == []
        references.clear()
        references.update(old_references)
        assert Ledger._lease_value is original
        assert Ledger._lease_value(values) == a
        # Public input evaluation still precedes manifest admission. A bad
        # selector does not map/check while only retrieving a method.
        os.environ[native.SELECTOR] = str(directory / 'missing.json')
        evaluated = []
        method = Ledger._lease_value
        def argument():
            evaluated.append('argument')
            return values
        error, report = capture(lambda: method(argument()))
        assert evaluated == ['argument'] and error is not None and len(calls) == baseline
        records.append({'id': 'lazy-after-caller-argument', 'result': report, 'events': evaluated, 'entries': 0})
        # Invalid signature binds before even the bad manifest is inspected.
        error, report = capture(lambda: method())
        assert isinstance(error, TypeError) and len(calls) == baseline
        records.append({'id': 'binding-before-admission', 'result': report, 'entries': 0})
        os.environ.pop(native.SELECTOR)
        # Owned copies permit real source/manifest/image drift without changing
        # the product checkout or the original built artifacts.
        source_raw = old_source.read_bytes()
        manifest_raw = manifest.read_bytes()
        descriptor = json.loads(manifest_raw)
        image_raw = (manifest.parent / descriptor['image_path']).read_bytes()
        for name in ('manifest', 'source', 'image'):
            folder = directory / ('drift-' + name)
            folder.mkdir()
            source = folder / 'slot_operations.hepta'
            source.write_bytes(source_raw)
            selected = folder / 'manifest.json'
            selected.write_bytes(manifest_raw)
            path = folder / descriptor['image_path']
            path.write_bytes(image_raw)
            native.SOURCE = source
            with selection.slot_operations_owner(str(selected), image=image):
                method = Ledger._lease_value
                target = selected if name == 'manifest' else source if name == 'source' else path
                previous = target.read_bytes()
                target.write_bytes(previous + b'\n')
                start = len(calls)
                error, report = capture(lambda: method(values))
                assert isinstance(error, native.SlotOperationsUnknown) and len(calls) == start
                records.append({'id': 'drift-' + name, 'result': report,
                                'before': {'bytes': len(previous)}, 'after': pin(target), 'entries': 0})
            native.SOURCE = old_source
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
        def make_bundle(path, helpers):
            write_json(path, {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
                {'selector': key, 'manifest_path': str(value),
                 'manifest_sha256': sha(value.read_bytes())} for key, value in helpers]})
            return sha(path.read_bytes())
        selected_bundle = directory / 'selected-bundle.json'
        selected_pin = make_bundle(selected_bundle, [(native.SELECTOR, manifest)])
        with native_helpers_scope(str(selected_bundle), selected_pin):
            pinned = native.installed_slot_operations(str(manifest))
            exact_entry, pinned_calls = pinned._entry, []
            def pinned_count(*args):
                code = exact_entry(*args)
                pinned_calls.append(code)
                return code
            pinned._entry = pinned_count
            references['_lease_value'] = staticmethod(forbidden)
            try:
                with selection.slot_operations_owner(str(manifest), image=pinned) as owner:
                    assert owner.image is pinned and Ledger._lease_value(values) == a
                assert pinned_calls and retained == []
                records.append({'id': 'worker-pinned-exact-image', 'entries': len(pinned_calls),
                                'exact_declared_object': True})
                descriptor = json.loads(manifest.read_bytes())
                duplicate = native.NativeSlotOperations(
                    (manifest.parent / descriptor['image_path']).read_bytes(), descriptor['image_sha256'])
                duplicate.admitted_source_sha256 = descriptor['source_sha256']
                start = len(pinned_calls)
                error, report = capture(lambda: selection.slot_operations_owner(str(manifest), image=duplicate))
                assert isinstance(error, native.SlotOperationsUnknown)
                assert len(pinned_calls) == start
                records.append({'id': 'worker-rejects-distinct-byte-identical-object',
                                'result': report, 'entries': 0})
            finally:
                pinned._entry = exact_entry
                references['_lease_value'] = old_references['_lease_value']
        excluded_bundle = directory / 'old-decision-only-bundle.json'
        excluded_pin = make_bundle(excluded_bundle, [('HEPTA_HIA_SLOT_LEDGER_MANIFEST', decision_manifest)])
        with native_helpers_scope(str(excluded_bundle), excluded_pin):
            os.environ[native.SELECTOR] = str(manifest)
            references['_lease_value'] = staticmethod(forbidden)
            start = len(calls)
            try:
                error, report = capture(lambda: Ledger._lease_value(values))
                assert isinstance(error, ValueError) and len(calls) == start and retained == []
                records.append({'id': 'old-bundle-does-not-acquire-new-controller',
                                'result': report, 'entries': 0})
            finally:
                references['_lease_value'] = old_references['_lease_value']
        os.environ.pop(native.SELECTOR, None)
        write_json(directory / 'selection.json', {'records': records,
            'actual_entries': len(calls), 'retained_calls': retained,
            'old_administrator_bundles_extended': False,
            'class_and_instance_same_actual_selected_image': True,
            'absence_uses_exact_retained_function': True})
        return records
    finally:
        image._entry = actual
        native.SOURCE = old_source
        references.clear()
        references.update(old_references)
        os.environ.clear()
        os.environ.update(old_environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--decision-manifest', type=Path)
    parser.add_argument('--group', choices=('transport', 'selection'), required=True)
    options = parser.parse_args()
    output = options.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    from hepta import hia_slot_operations_native as native
    before = pin(options.manifest)
    image = native.installed_slot_operations(str(options.manifest))
    try:
        values = (transport(native, image, output) if options.group == 'transport' else
                  selection_controls(native, image, options.manifest, output, options.decision_manifest))
        stable = pin(options.manifest) == before
        if not stable:
            raise AssertionError('original controller manifest changed')
        report = {'status': 'PASS', 'group': options.group, 'count': len(values),
                  'actual_mapped_image': image.image_sha256, 'manifest_before': before,
                  'manifest_after': pin(options.manifest), 'pid': os.getpid(), 'pgid': os.getpgrp(),
                  'ppid': os.getppid(), 'runtime': sys.version, 'actual_SQL': 0,
                  'all_failures_injected_after_actual_entry_or_explicit_safe_preentry': True}
        code = 0
    except BaseException as error:
        report = {'status': 'HOLD', 'group': options.group,
                  'error': type(error).__module__ + '.' + type(error).__qualname__,
                  'message': str(error), 'traceback': traceback.format_exc()}
        code = 1
    write_json(output / 'report.json', report)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
