"""Fresh-process complete Slot observer: immutable original or actual controller.

No expected observation is read by a candidate child. The 36-file original
observer definitions, methods, fake providers and case ordering are unchanged.
Only the supervising entry glue selects the independently frozen input file.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import traceback
import types

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hia_slot_operations_qualification_support import (
    ORACLE_SHA256, ORACLE_FREEZE_SHA256, NAMES, admit_originals, admit_cases,
    admit_product, canonical, pin, regular_bytes, sha, write_json,
)

# All fixed setup objects stay live through the declared observations. There
# is no image -> entry -> image closure and no extra gc.collect before cases.
_SETUP = []
_BACKEND = None
_OBSERVER = None


class _VMEntry:
    __slots__ = ('program', 'machine', 'owner', 'view', 'entries', 'events', 'modes')

    def __init__(self, program, machine, owner, view):
        self.program, self.machine, self.owner, self.view = program, machine, owner, view
        self.entries, self.events, self.modes = 0, Counter(), Counter()

    def __call__(self, source, size, output, capacity, state, extent):
        raw = ctypes.string_at(source, size)
        values = (raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        owners = [self.owner(index + 1, bytearray(value)) for index, value in enumerate(values)]
        # Independent interpreter limits are explicit and unchanged by cases.
        machine = self.machine(self.program, 4_000_000, 16 << 20, None, 128)
        # The Slot oracle interprets scalar and memory operations even when the
        # installed wheel supplies a default image. Bind that choice per machine.
        machine._package_integer = None
        code = machine.invoke(machine.functions['f0'],
            [self.view(owner, index != 0) for index, owner in enumerate(owners)])[0]
        if bytes(owners[0].data) != raw:
            raise AssertionError('independent VM changed immutable controller request')
        ctypes.memmove(output, bytes(owners[1].data), capacity)
        ctypes.memmove(state, bytes(owners[2].data), extent)
        words = struct.unpack('<16Q', raw)
        self.entries += 1
        self.events[str(words[1])] += 1
        self.modes[str(words[5])] += 1
        return code


class _NativeEntry:
    __slots__ = ('entry', 'entries', 'events', 'modes', 'attempts')

    def __init__(self, entry):
        self.entry = entry
        self.entries, self.attempts = 0, 0
        self.events, self.modes = Counter(), Counter()

    def __call__(self, source, size, output, capacity, state, extent):
        self.attempts += 1
        code = self.entry(source, size, output, capacity, state, extent)
        words = struct.unpack('<16Q', ctypes.string_at(source, size))
        self.entries += 1
        self.events[str(words[1])] += 1
        self.modes[str(words[5])] += 1
        return code


class _UnselectedCounter:
    entries = 0
    events = {}
    modes = {}


def forbidden_unselected_mapping(*arguments, **keywords):
    raise AssertionError('unselected public Slot mapped a controller')


class _VMSelection:
    """Component-only VM injection; it is never a native manifest authority."""
    __slots__ = ('image', 'source', 'raw')

    def __init__(self, image, source):
        self.image, self.source, self.raw = image, source, regular_bytes(source)

    def check(self):
        if regular_bytes(self.source) != self.raw:
            raise AssertionError('independent VM controller source changed')
        return self.image


def load_observer(oracle_root):
    global _OBSERVER
    path = oracle_root / 'observe_originals.py'
    raw = regular_bytes(path)
    if sha(raw) != ORACLE_SHA256:
        raise ValueError('independent observer source differs')
    tree = ast.parse(raw, filename=str(path))
    final = tree.body[-1]
    if (not isinstance(final, ast.If)
            or ast.unparse(final.test) != "__name__ == '__main__'"):
        raise ValueError('independent observer entry guard differs')
    # No definition is edited. The external driver replaces only the CLI entry
    # to select original248/derived7574 and the actual public implementation.
    admitted = ast.Module(body=tree.body[:-1], type_ignores=tree.type_ignores)
    code = compile(admitted, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    namespace = {'__name__': '__main__', '__file__': str(path), '__package__': None}
    exec(code, namespace)
    _SETUP.extend((tree, admitted, code, namespace))
    _OBSERVER = namespace
    return namespace


def prepare_backend(root, backend, manifest):
    """Product setup precedes fake-module binding and the no-provider audit."""
    global _BACKEND
    if backend == 'original':
        return None
    from hepta import hia_slot_operations_native as native
    from hepta import hia_slot_operations_selection as selection
    from hepta import hia_slot_ledger_native as ledger
    # Preload every actual mechanical dependency before the independent fake
    # hepta namespace is installed. Later provider imports resolve its fakes.
    from hepta import hia_native_helpers, hia_store_lifecycle_native
    from hepta import hia_native_delivery, hia_slot_operation_series
    from hepta import hia_emission_native, hia_json_preflight_native
    modules = (native, selection, ledger, hia_native_helpers,
               hia_store_lifecycle_native, hia_native_delivery,
               hia_slot_operation_series, hia_emission_native, hia_json_preflight_native)
    if backend == 'unselected':
        original_init = native.NativeSlotOperations.__init__
        native.NativeSlotOperations.__init__ = forbidden_unselected_mapping
        _BACKEND = {'native': native, 'selection': selection, 'ledger': ledger,
            'image': None, 'entry': _UnselectedCounter(), 'authority': None,
            'admission': {'kind': 'UNSELECTED_ORIGINAL_PUBLIC_NO_IMAGE', 'native_mapping': False},
            'references': None, 'retained_calls': [], 'unselected': True,
            'saved_native_init': original_init}
        _SETUP.extend((*modules, _BACKEND))
        return _BACKEND
    if backend == 'vm':
        if manifest is not None:
            raise ValueError('VM does not claim a compiled native manifest')
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Owner, _View
        from hepta.hia_program_runtime_arithmetic import prepare_arithmetic_runtime
        program = assemble_program(native.SOURCE.read_bytes())
        program, machine_factory = prepare_arithmetic_runtime(program)
        image = object.__new__(native.NativeSlotOperations)
        image.image_sha256 = 'INDEPENDENT_VM_NO_EXECUTABLE_MAPPING'
        image.admitted_source_sha256 = sha(regular_bytes(native.SOURCE))
        entry = _VMEntry(program, machine_factory, _Owner, _View)
        image._entry = entry
        authority = _VMSelection(image, native.SOURCE)
        admission = {'kind': 'INDEPENDENT_VM_COMPONENT_INJECTION',
                     'source': pin(native.SOURCE), 'step_limit': 4_000_000,
                     'scratch_bytes': 16 << 20, 'call_depth': 128,
                     'native_mapping': False, 'native_cold_qualification': False}
        _SETUP.append(program)
    else:
        if manifest is None:
            raise ValueError('actual Native backend needs a declared compiled manifest')
        manifest = manifest.resolve(strict=True)
        image = native.installed_slot_operations(str(manifest))
        entry = _NativeEntry(image._entry)
        image._entry = entry
        authority = selection.slot_operations_owner(str(manifest), image=image)
        value = json.loads(regular_bytes(manifest))
        image_path = manifest.parent / value['image_path']
        admission = {'kind': 'ACTUAL_MAPPED_NATIVE_CONTROLLER',
                     'manifest_path': str(manifest), 'manifest': pin(manifest),
                     'source': pin(native.SOURCE), 'image_path': str(image_path),
                     'image': pin(image_path), 'image_sha256': image.image_sha256,
                     'compiler_sha256': value['compiler_sha256'],
                     'native_mapping': True, 'native_cold_qualification': 'owned by builder and outer gate'}
    _BACKEND = {'native': native, 'selection': selection, 'ledger': ledger,
                'image': image, 'entry': entry, 'authority': authority,
                'admission': admission, 'references': None, 'retained_calls': []}
    _SETUP.extend((*modules, image, entry, authority, _BACKEND))
    return _BACKEND


def forbidden_retained(*arguments, **keywords):
    _BACKEND['retained_calls'].append('retained-original-invoked')
    raise AssertionError('selected complete Slot owner executed a retained method')


def bind_actual_public(namespace, backend):
    """Actual public descriptors, with only original declared providers fake."""
    ledger = backend['ledger']
    cls = ledger.NativeSlotLedgerStore
    original_namespace = namespace['ORIGINAL'].__init__.__globals__
    backend['original_namespace'] = original_namespace
    names = ('ctypes', 'os', 'uuid', 'struct', 'sha256', 'STATE_BYTES', 'MAX_U64',
             'REQUEST_MAGIC', '_custody', 'request_packet', '_text', '_untext',
             '_decimal', '_raise', '_SelectedRendererFailure', '_claimed_artifact_wire')
    saved_globals = {name: vars(ledger).get(name) for name in names}
    for name in names:
        setattr(ledger, name, original_namespace[name])
    references = cls._hia_slot_reference_methods
    if tuple(references) != NAMES:
        raise AssertionError('actual fifteen public retained identities differ')
    saved_references = dict(references)
    if not backend.get('unselected', False):
        for name, method in saved_references.items():
            references[name] = staticmethod(forbidden_retained) if type(method) is staticmethod else forbidden_retained
    backend['references'] = (references, saved_references, saved_globals)
    namespace['ORIGINAL'] = cls
    namespace['ORIGINAL_METHODS'] = {name: vars(cls)[name] for name in NAMES}
    # The fake package was produced by the immutable original loader. Public
    # frame default namespace resolution still reaches the actual ledger.
    sys.modules['hepta'].hia_slot_ledger_native = ledger
    if backend.get('unselected', False):
        backend['selection_token'] = None
    elif backend['admission']['native_mapping']:
        backend['authority'].__enter__()
        backend['selection_token'] = None
    else:
        backend['selection_token'] = backend['selection']._OWNER.set(backend['authority'])


def unbind_actual_public(backend):
    if backend is None:
        return
    if backend.get('unselected', False):
        backend['native'].NativeSlotOperations.__init__ = backend['saved_native_init']
    elif backend['admission']['native_mapping']:
        backend['authority'].__exit__(None, None, None)
    else:
        backend['selection']._OWNER.reset(backend['selection_token'])
    references, saved, globals_before = backend['references']
    references.clear()
    references.update(saved)
    vars(backend['ledger']).update(globals_before)


def observe_all(namespace, cases, output):
    """Same full original per-case order and declared post-seal phase."""
    worlds, started, stopped, failures = [], [], [], []
    digest = hashlib.sha256()
    original_unraisable = sys.unraisablehook

    def unraisable(value):
        active = namespace['ACTIVE']
        if active is not None:
            active.unraisable.append({'error': active.error(value.exc_value),
                'object': active.value(value.object), 'message': value.err_msg})

    sys.unraisablehook = unraisable
    try:
        with (output / 'observations.jsonl').open('xb') as stream, (
                output / 'raw-exceptions.jsonl').open('xb') as errors, (
                output / 'progress.jsonl').open('xb') as progress:
            for case in cases:
                started.append(case['id'])
                progress.write(canonical({'id': case['id'], 'event': 'started'}) + b'\n')
                progress.flush()
                world = namespace['World'](case)
                worlds.append(world)
                try:
                    if case['outer_exception']:
                        try:
                            raise KeyError('declared outer exception')
                        except KeyError as outer:
                            world.name_error(outer, 'outer')
                            record, raw = world.observe()
                    else:
                        record, raw = world.observe()
                except namespace['OracleFixtureError'] as error:
                    failures.append({'id': case['id'], 'type': type(error).__qualname__,
                                     'message': str(error)})
                    traceback.print_exc()
                    break
                payload = canonical(record) + b'\n'
                stream.write(payload)
                stream.flush()
                digest.update(payload)
                errors.write(canonical({'id': case['id'], 'traceback': raw}) + b'\n')
                errors.flush()
                stopped.append(case['id'])
                progress.write(canonical({'id': case['id'], 'event': 'stopped'}) + b'\n')
                progress.flush()
        # This is exactly the original separately declared post-seal GC phase.
        # It never changes a case, expected bytes, or a prior event.
        sealed = [getattr(world, 'sealed_event_count', len(world.events)) for world in worlds]
        for world in worlds:
            world.phase = 'post-seal-gc-diagnostic'
        collected = namespace['gc'].collect()
        late = [{'id': world.case['id'], 'events': world.events[length:],
                 'alive': world.alive(), 'unraisable': world.unraisable}
                for world, length in zip(worlds, sealed)]
        write_json(output / 'post-seal-gc.json', {'collected': collected, 'cases': late,
            'not_part_of_handler_result': True, 'no_prior_record_rewritten': True})
    finally:
        sys.unraisablehook = original_unraisable
    # Keep exactly the same World lifetime as the original entry until the
    # child has completed its source/report checks. Worlds contain weakrefs.
    _SETUP.append(worlds)
    return started, stopped, failures, digest.hexdigest(), worlds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--oracle-root', type=Path, required=True)
    parser.add_argument('--derived-inputs', type=Path, required=True)
    parser.add_argument('--group', choices=('original248', 'derived7574'), required=True)
    parser.add_argument('--backend', choices=('original', 'vm', 'native'), required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--product-freeze', type=Path, required=True)
    parser.add_argument('--product-freeze-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    root, oracle_root, output = options.root.resolve(), options.oracle_root.resolve(), options.output.resolve()
    sys.path.insert(0, str(root))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = admit_originals(oracle_root)
    product_before = admit_product(root, options.product_freeze, options.product_freeze_sha256)
    cases, manifest_pin = admit_cases(oracle_root, options.derived_inputs, options.group)
    write_json(output / 'source-before.json', before)
    write_json(output / 'product-before.json', product_before)
    write_json(output / 'planned.json', {'ordered_ids': [case['id'] for case in cases],
                                       'count': len(cases), 'input': manifest_pin})
    runtime = {'version': sys.version, 'implementation': sys.implementation.name,
               'executable': sys.executable, 'pid': os.getpid(), 'ppid': os.getppid(),
               'pgid': os.getpgrp(), 'argv': sys.argv, 'backend': options.backend}
    write_json(output / 'runtime.json', runtime)
    namespace = load_observer(oracle_root)
    backend = prepare_backend(root, options.backend, options.manifest)
    writes = namespace['install_audit'](oracle_root, output)
    namespace['load_originals'](oracle_root)
    if backend is not None:
        bind_actual_public(namespace, backend)
    try:
        started, stopped, failures, digest, worlds = observe_all(namespace, cases, output)
    finally:
        unbind_actual_public(backend)
    after = admit_originals(oracle_root)
    product_after = admit_product(root, options.product_freeze, options.product_freeze_sha256)
    write_json(output / 'source-after.json', after)
    write_json(output / 'product-after.json', product_after)
    planned = [case['id'] for case in cases]
    good = (started == stopped == planned and not failures
            and before == after and product_before == product_after
            and not any(world.unraisable for world in worlds))
    counts = None
    if backend is not None:
        entry = backend['entry']
        counts = {'returned_entries': entry.entries, 'events': dict(entry.events),
                  'modes': dict(entry.modes), 'retained_calls': backend['retained_calls']}
        good = good and not backend['retained_calls'] and entry.entries > 0
        if options.backend == 'native':
            counts['attempted_entries'] = entry.attempts
            good = good and entry.attempts == entry.entries
            admission = backend['admission']
            good = good and pin(admission['manifest_path']) == admission['manifest']
            good = good and pin(admission['image_path']) == admission['image']
        write_json(output / 'controller.json', {'admission': backend['admission'], 'counts': counts})
    report = {
        'schema': 'hepta.slot-operations.complete-observations.v1',
        'status': 'RECORDED' if good else 'HOLD', 'group': options.group,
        'backend': options.backend, 'runtime': runtime,
        'planned': len(planned), 'started': started, 'stopped': stopped, 'failures': failures,
        'input': manifest_pin, 'source_stable': before == after,
        'product_stable': product_before == product_after,
        'observations_sha256': digest, 'controller': counts,
        'actual_SQL': 0, 'native_controller': options.backend == 'native',
        'independent_VM_controller': options.backend == 'vm',
        'all_SQL_and_decision_providers_explicitly_fake': True,
        'candidate_read_any_expected_observations': False,
        'original_observer_definitions_or_cases_modified': False,
        'no_GC_before_or_between_cases_beyond_declared_inputs': True,
        'post_seal_gc_is_separate_not_handler_qualification': True,
        'audit_output_writes': writes,
    }
    write_json(output / 'report.json', report)
    return 0 if good else 1


if __name__ == '__main__':
    raise SystemExit(main())
