"""New complete comparison-trajectory controls for the HIA ELF sort owner.

STATIC authoring: this script has not been parsed or executed. It uses the
complete unchanged original writer as the oracle, an explicitly pinned old
native image/transport as a separate baseline, and the newly installed native
selection. No host sort is substituted into the candidate.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from hashlib import sha256
import importlib.util
import json
import math
import os
from pathlib import Path
import struct
import sys
import traceback
import types
from unittest.mock import patch

CASE_COUNT = 122
ORACLE_SHA = 'c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101'
BASELINE_SOURCE_SHA = '2f1ff8e728c2c0459f690ceb47db92ff40daffd762a8d19761f321127e700133'
BASELINE_HIA_SHA = 'af122cb4340ca351a07e3148e699730e4ed652f3c3c4deebdc5837dee693c6e3'
BASELINE_IMAGE_SHA = '6d1ee8d10cd39b3019ab6a643e084b6b2fed991e449d1d74d179bda27a44a12c'


def require(value, message):
    if not value:
        raise AssertionError(message)


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def create(path, raw):
    with Path(path).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def ranks(pattern, n):
    if pattern == 'ascending':
        return list(range(n))
    if pattern == 'descending':
        return list(range(n - 1, -1, -1))
    if pattern == 'equal':
        return [0] * n
    if pattern == 'alternating':
        return [i // 2 if i % 2 == 0 else n - 1 - i // 2 for i in range(n)]
    if pattern == 'zigzag':
        return [(i * 17) % n for i in range(n)]
    if pattern == 'gallop-left':
        middle = n // 2
        return list(range(middle, n)) + list(range(middle))
    if pattern == 'gallop-right':
        return list(range(n - 8, n)) + list(range(n - 8))
    if pattern == 'blocks':
        return [((i // 16) ^ 3) * 16 + i % 16 for i in range(n)]
    if pattern == 'shuffle':
        # Input construction is independent of either sorting implementation.
        result = list(range(n))
        state = 0x8d2950a1
        for index in range(n - 1, 0, -1):
            state = (state * 1664525 + 1013904223) & 0xffffffff
            other = state % (index + 1)
            result[index], result[other] = result[other], result[index]
        return result
    raise AssertionError('unknown frozen input pattern')


class ForeignStop(BaseException):
    pass


class World:
    def __init__(self, definition):
        self.definition = definition
        self.trace = []
        self.comparisons = 0
        self.result_serial = 0
        self.changed = False
        self.stop = ForeignStop('foreign-sort-stop', definition['id'])
        self.ambient = OSError('foreign-sort-ambient', definition['id'])
        self.objects = []
        self.errors = {id(self.stop): 'stop', id(self.ambient): 'ambient'}
        world = self
        behavior = definition['behavior']

        class TruthResult:
            def __init__(self, value, operation):
                self.value = value
                self.operation = operation
                self.serial = world.result_serial
                world.result_serial += 1

            def __bool__(self):
                world.trace.append(['truth', self.serial, self.operation,
                                    self.value, world.exception_tag(sys.exception())])
                if behavior.startswith('truth-stop-'):
                    target = int(behavior.rsplit('-', 1)[1])
                    if world.comparisons >= target:
                        raise world.stop
                return self.value

            def __del__(self):
                world.trace.append(['release-result', self.serial,
                                    world.exception_tag(sys.exception())])

        self.TruthResult = TruthResult

        class KeyValue:
            def __init__(self, token, value, raw_name=None):
                self.token = token
                self.value = value
                self.raw_name = raw_name

            def __repr__(self):
                return 'KeyValue(' + str(self.token) + ')'

            def __hash__(self):
                world.trace.append(['hash', self.token])
                return hash(self.raw_name) if self.raw_name is not None else hash(self.value)

            def __eq__(self, other):
                world.trace.append(['eq', self.token, world.tag(other)])
                if type(other) is str:
                    return self.raw_name == other
                if isinstance(other, KeyValue):
                    equal = self.value == other.value
                    if behavior.startswith('tuple-'):
                        return TruthResult(equal, 'eq')
                    return equal
                return NotImplemented

            def __lt__(self, other):
                world.comparisons += 1
                world.trace.append(['lt', self.token, world.tag(other),
                                    world.exception_tag(sys.exception())])
                if behavior.startswith('lt-stop-'):
                    if world.comparisons >= int(behavior.rsplit('-', 1)[1]):
                        raise world.stop
                if behavior == 'mutate-method' and not world.changed:
                    world.changed = True
                    KeyValue.__lt__ = changed_lt
                    world.trace.append(['mutate-lt'])
                if behavior == 'mutate-type-slot' and not world.changed:
                    world.changed = True
                    del KeyValue.__lt__
                    del KeyValue.__gt__
                    del KeyValue.__eq__
                    world.trace.append(['mutate-richcompare-slot'])
                if behavior == 'not-implemented':
                    return NotImplemented
                value = self.value < world.number(other)
                return world.result(value, 'lt')

            def __gt__(self, other):
                world.comparisons += 1
                world.trace.append(['gt', self.token, world.tag(other),
                                    world.exception_tag(sys.exception())])
                return world.result(self.value > world.number(other), 'gt')

            def __add__(self, other):
                world.trace.append(['add', self.token, world.tag(other)])
                return self.value + world.number(other)

            def __sub__(self, other):
                world.trace.append(['sub', self.token, world.tag(other)])
                return self.value - world.number(other)

            def __index__(self):
                world.trace.append(['index', self.token])
                return self.value

        def changed_lt(value, other):
            world.comparisons += 1
            world.trace.append(['changed-lt', value.token, world.tag(other),
                                world.exception_tag(sys.exception())])
            return value.value > world.number(other)

        class SubKey(KeyValue):
            def __gt__(self, other):
                world.comparisons += 1
                world.trace.append(['subclass-gt', self.token, world.tag(other),
                                    world.exception_tag(sys.exception())])
                return self.value > world.number(other)

        self.KeyValue = KeyValue
        self.SubKey = SubKey
        self.arguments = self.make_arguments()

    def exception_tag(self, error):
        if error is None:
            return None
        return self.errors.get(id(error), ['other', type(error).__name__, list(error.args)])

    def tag(self, value):
        if type(value) in (int, str, bool) or value is None:
            return value
        if isinstance(value, self.KeyValue):
            return ['key', value.token]
        if type(value) is float:
            return ['float', value.hex()]
        if type(value) is tuple:
            return ['tuple', [self.tag(item) for item in value]]
        return ['type', type(value).__name__]

    def number(self, value):
        if isinstance(value, self.KeyValue):
            return value.value
        return value

    def result(self, value, operation):
        behavior = self.definition['behavior']
        if behavior == 'opaque' or behavior.startswith(('truth-stop-', 'tuple-')):
            return self.TruthResult(value, operation)
        return value

    def key_value(self, token, value, raw_name=None):
        cls = (self.SubKey if self.definition['behavior'] == 'mixed-subclass'
               and token % 2 else self.KeyValue)
        result = cls(token, value, raw_name)
        self.objects.append(result)
        return result

    def name_key(self, token, rank, raw_name):
        value = self.key_value(token, rank, raw_name)
        behavior = self.definition['behavior']
        if behavior == 'tuple-first':
            return (value, token % 3)
        if behavior == 'tuple-nested':
            return ((value,), token % 3)
        if behavior == 'tuple-mixed':
            return (value,) if token % 2 else value
        if behavior == 'tuple-empty':
            return (value,) if token % 5 else ()
        if behavior == 'float-nan':
            return float('nan') if token % 3 == 0 else float(rank)
        return value

    def instrumented_row(self, fields, mutate, *, relocation=False):
        world = self
        state = {'armed': False, 'name': 0, 'size': 0, 'done': False}
        keys = {}
        row = {}

        class Field:
            def __init__(self, name):
                self.name = name

            def __hash__(self):
                return hash(self.name)

            def __eq__(self, other):
                equal = self.name == other
                if not equal or type(other) is not str:
                    return equal
                arming = 'symbol' if relocation else 'name'
                if self.name == arming:
                    state['name'] += 1
                    if state['name'] == 2:
                        state['armed'] = True
                target = 'offset' if relocation else 'size'
                if state['armed'] and self.name == target and not state['done']:
                    state['size'] += 1
                    if state['size'] == (1 if relocation else 2):
                        state['done'] = True
                        mutate(row, keys)
                        world.trace.append(['inject', fields.get('name', fields.get('symbol'))])
                return equal

        for name, value in fields.items():
            key = Field(name)
            keys[name] = key
            row[key] = value
        return row, state

    def make_arguments(self):
        definition = self.definition
        n = definition['n']
        values = ranks(definition['pattern'], n)
        require(len(values) == n and all(type(x) is int and 0 <= x < n for x in values),
                'frozen rank construction exceeded its extent')
        family = definition['family']
        symbols, relocations, states = [], [], []
        if family == 'relocation':
            code = b'\xe8\0\0\0\0' * (n + 1) + b'\xc3'
            symbols = [{'name': 'entry', 'offset': 0, 'size': len(code), 'global': True}]
            for token, rank in enumerate(values):
                offset = 5 * rank + 1
                foreign = self.key_value(token, offset)
                def mutate(row, keys, foreign=foreign):
                    row[keys['offset']] = foreign
                row, state = self.instrumented_row(
                    {'offset': offset, 'symbol': 'entry', 'type': 4, 'addend': -4},
                    mutate, relocation=True)
                relocations.append(row)
                states.append(state)
        else:
            code = b'\xc3' * (n * 2 + 1)
            for token, rank in enumerate(values):
                raw_name = 'f' + str(token).zfill(5)
                offset = 2 * rank if family == 'span' else token
                foreign = (self.key_value(token, offset) if family == 'span'
                           else self.name_key(token, rank, raw_name))
                field = 'offset' if family == 'span' else 'name'
                def mutate(row, keys, foreign=foreign, field=field):
                    row[keys[field]] = foreign
                row, state = self.instrumented_row(
                    {'name': raw_name, 'offset': offset, 'size': 1,
                     'global': definition['global']},
                    mutate)
                symbols.append(row)
                states.append(state)
        self.injection_states = states
        # Construction itself is outside the original call and must not
        # contaminate its observed effect sequence.
        self.trace.clear()
        return code, symbols, relocations

    def outcome(self, writer):
        observed = {}
        def call():
            try:
                value = writer(*self.arguments, text_alignment=16)
            except BaseException as error:
                frames = traceback.extract_tb(error.__traceback__)
                observed.update(
                    kind='exception', type=type(error).__qualname__,
                    args=[self.tag(item) for item in error.args],
                    is_issued_foreign_stop=error is self.stop,
                    context=self.exception_tag(error.__context__),
                    cause=self.exception_tag(error.__cause__),
                    foreign_traceback_tail=[[frame.name, frame.lineno] for frame in frames
                        if frame.filename == __file__ and frame.name in
                           ('__lt__', '__gt__', '__bool__', 'changed_lt')]
                        if error is self.stop else None)
            else:
                observed.update(kind='bytes', bytes=len(value),
                                sha256=sha256(value).hexdigest(), hex=value.hex())
        if self.definition['ambient']:
            try:
                raise self.ambient
            except OSError:
                call()
        else:
            call()
        return {'outcome': observed, 'trace': list(self.trace),
                'comparison_callbacks': self.comparisons,
                'injections': [bool(item['done']) for item in self.injection_states]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--baseline-transport', type=Path, required=True)
    parser.add_argument('--baseline-hia', type=Path, required=True)
    parser.add_argument('--baseline-image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    report = {'schema': 'hepta.hia.machine-elf-comparison-trajectories.v1',
              'status': 'HOLD', 'scope': 'NEW_DEVELOPMENT_ORIGINAL_AND_TWO_NATIVE_IMAGES',
              'expected_count': CASE_COUNT, 'executed': [], 'cases': [],
              'foreign_timsort_schedule_closed': False,
              'matching_current_cold': False, 'whole_native_delivery_qualified': False}
    failed = None
    try:
        sys.path.insert(0, str(args.source.resolve(strict=True)))
        from hepta import hia_machine_elf as public
        from hepta.hia_machine_elf_native import installed_machine_elf
        original_raw = args.oracle.read_bytes()
        require(sha256(original_raw).hexdigest() == ORACLE_SHA, 'complete original writer differs')
        original_module = types.ModuleType('elf_complete_original')
        exec(compile(original_raw, str(args.oracle), 'exec'), original_module.__dict__)
        original_module.MachineObjectError = public.MachineObjectError
        baseline_raw = args.baseline_transport.read_bytes()
        baseline_hia = args.baseline_hia.read_bytes()
        baseline_image = args.baseline_image.read_bytes()
        require(sha256(baseline_raw).hexdigest() == BASELINE_SOURCE_SHA
                and sha256(baseline_hia).hexdigest() == BASELINE_HIA_SHA
                and sha256(baseline_image).hexdigest() == BASELINE_IMAGE_SHA,
                'separate actual previous native source/image binding differs')
        baseline_module = types.ModuleType('hepta._elf_timsort_previous_transport')
        baseline_module.__package__ = 'hepta'
        baseline_module.__file__ = str(args.baseline_transport)
        exec(compile(baseline_raw, str(args.baseline_transport), 'exec'), baseline_module.__dict__)
        baseline = baseline_module.NativeMachineElf(baseline_image, BASELINE_IMAGE_SHA)
        native = installed_machine_elf(str(args.manifest.resolve(strict=True)))
        cases_raw = args.cases.read_bytes()
        document = json.loads(cases_raw)
        cases = document['cases']
        loaded = [case['id'] for case in cases]
        require(len(cases) == CASE_COUNT and len(set(loaded)) == CASE_COUNT,
                'complete frozen comparison trajectory denominator differs')
        report['inputs'] = {str(path): {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
            for path, raw in ((args.oracle, original_raw),
                              (args.baseline_transport, baseline_raw),
                              (args.baseline_hia, baseline_hia),
                              (args.baseline_image, baseline_image),
                              (args.cases, cases_raw),
                              (args.manifest, args.manifest.read_bytes()))}
        report['loaded'] = loaded
        old_mismatches, new_mismatches = [], []
        for index, definition in enumerate(cases):
            # Each complete writer gets a fresh graph with the same frozen
            # input definition; no mutated graph is passed into another call.
            original = World(definition).outcome(original_module.write_elf_object)
            previous = World(definition).outcome(baseline.write)
            before = native.calls.copy()
            with patch.dict(os.environ, {'HEPTA_HIA_MACHINE_ELF_MANIFEST': str(args.manifest.resolve())}), \
                 patch.object(public, '_reference_write_elf_object',
                              side_effect=AssertionError('retained writer entered selected trace')):
                actual = World(definition).outcome(public.write_elf_object)
            counts = dict(native.calls - before)
            row = {'case': definition, 'original': original, 'previous_native': previous,
                   'selected_native': actual, 'native_operation_counts': counts,
                   'previous_equal': previous == original, 'selected_equal': actual == original}
            pin = create(args.output / ('case-' + str(index).zfill(3) + '.json'), wire(row))
            report['executed'].append(definition['id'])
            report['cases'].append({'id': definition['id'], 'record': pin,
                                   'previous_equal': row['previous_equal'],
                                   'selected_equal': row['selected_equal']})
            require(original['injections'] and all(original['injections'])
                    and original['injections'] == actual['injections'],
                    'case did not reach its documented post-admission object injection')
            require(counts.get(17, 0) > 0 and any(counts.get(op, 0) > 0 for op in (19, 21, 22, 24)),
                    'actual HIA comparator selection/foreign observation was not reached')
            if not row['previous_equal']:
                old_mismatches.append(definition['id'])
            if not row['selected_equal']:
                new_mismatches.append(definition['id'])
        report['previous_mismatches'] = old_mismatches
        report['selected_mismatches'] = new_mismatches
        require(report['executed'] == loaded and old_mismatches and not new_mismatches,
                'complete original/previous/selected comparison conjunction failed')
        report['status'] = 'ALL_122_COMPLETE_COMPARISON_TRAJECTORIES_MATCH'
    except BaseException as error:
        failed = error
        report['error'] = traceback.format_exc()
    finally:
        create(args.output / 'report.json', wire(report))
    print(json.dumps({'status': report['status'], 'loaded': len(report.get('loaded', [])),
                      'executed': len(report['executed'])}), flush=True)
    if failed is not None:
        raise failed


if __name__ == '__main__':
    main()
