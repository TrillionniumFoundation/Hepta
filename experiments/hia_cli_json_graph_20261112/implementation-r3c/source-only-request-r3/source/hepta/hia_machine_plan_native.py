"""Private native machine-plan sessions and mechanical Core/text observations.

The HIA image owns schemas, choices, permutations, function/SSA membership,
leaf admission, inclusive lifetimes, conflict priority and witness ordering.
This bridge retains immutable Core custody, exact built-in observations, the
public witness hook and construction of Python objects selected by HIA.
"""
from __future__ import annotations

import ctypes
import struct

from hepta.hia_instruction_policy_native import transport
from hepta.hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path)

SOURCE = _source_resource_path('examples/hia_bootstrap/machine_plan.hiaasm')
SCHEMA = 'hepta.hia.machine-plan-native.v1'
SELECTOR = 'HEPTA_HIA_MACHINE_PLAN_MANIFEST'

REGISTERS = ('rbx', 'r12', 'r13', 'r14', 'r15', 'r8', 'r9')
LEAF_OPS = tuple(sorted((
    'const', 'int.add.wrap', 'int.add.checked', 'int.sub.wrap', 'int.sub.checked',
    'int.mul.wrap', 'int.mul.checked', 'int.div.checked', 'int.rem.checked',
    'int.shl.checked', 'int.shr.checked', 'int.neg.checked', 'int.cast',
    'bit.and', 'bit.or', 'bit.xor', 'bit.not', 'compare.eq', 'compare.ne',
    'compare.lt', 'compare.le', 'compare.gt', 'compare.ge', 'bool.and',
    'bool.or', 'bool.not', 'select', 'buffer.len', 'buffer.load', 'buffer.store')))
RULE = 'closed-block inclusive lifetimes; all edge sources staged before target writes'
MESSAGES = {
    1: 'plan must be an object',
    2: 'plan requires bounded plain JSON data',
    3: 'unknown plan schema',
    4: 'plan has missing or unreviewed fields',
    5: 'plan belongs to a different Core',
    6: 'invalid block order map',
    7: 'unknown function in block order',
    8: 'block order must name every member exactly once',
    9: 'function order must name every member exactly once',
    10: 'scratch assignment must bijectively rename only r10 and r11',
    11: 'instruction choices must be explicit and complete',
    12: 'unreviewed immediate move encoding',
    13: 'unreviewed immediate arithmetic encoding',
    14: 'unreviewed function alignment',
    15: 'unreviewed scalar select encoding',
    16: 'value_registers must be a function map',
    17: 'unknown function in value register assignment',
    18: 'value registers must be explicit assignments admitted by this plan version',
    19: 'caller-clobbered value registers require a leaf opcode whitelist; no calls, swap or allocation/bulk helpers',
    20: 'leaf registers require scalar/borrowed parameters and scalar returns',
    21: 'register assignment requires an existing integer or boolean SSA value',
}


def _kind(value):
    typ = type(value)
    return 6 if typ is dict else 4 if typ is str else 7


def _text_fact(value):
    # No traversal, conversion hook, hashing, equality or policy lookup. Every
    # legal Core identifier is at most 128 ASCII characters. HIA sees the full
    # character length as well, so truncation cannot admit a different name.
    if type(value) is str:
        return transport(value[:128]), len(value)
    return struct.pack('<QQ', 7, 0), 0


class _Session:
    def __init__(self, image):
        self.image = image
        self.state = ctypes.create_string_buffer(8192)
        self.output = ctypes.create_string_buffer(128)
        self.function_objects = None
        self.function_name = None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.state = self.output = self.image = None
        self.function_objects = self.function_name = None

    def grow(self, length):
        if length <= len(self.state):
            return
        fresh = ctypes.create_string_buffer(length)
        ctypes.memmove(fresh, self.state, len(self.state))
        self.state = fresh

    def word(self, at):
        return struct.unpack_from('<Q', self.state, at)[0]

    def text(self, at):
        end = self.word(104)
        if not 8192 <= at <= end - 16:
            raise RuntimeError('native machine-plan text offset outside captured Core')
        kind, size = struct.unpack_from('<QQ', self.state, at)
        if kind != 4 or size > end - at - 16:
            raise RuntimeError('native machine-plan text identity differs')
        return ctypes.string_at(ctypes.addressof(self.state) + at + 16, size).decode('utf-8')

    def result_words(self, count):
        return struct.unpack_from('<' + 'Q' * count, self.output)

    def step(self, command, payload=b'', *numbers):
        from hepta.hia_machine_plan import MachinePlanRejected
        if type(payload) is not bytes or len(numbers) > 6:
            raise TypeError('exact native machine-plan protocol bytes required')
        struct.pack_into('<7Q', self.state, 0, command, *numbers, *([0] * (6 - len(numbers))))
        source = ctypes.create_string_buffer(payload, max(1, len(payload)))
        result = self.image._entry(source, len(payload), self.output, len(self.output),
                                   self.state, len(self.state))
        if result == 0x80000000 + 22:
            fn, block, left, right, reg = self.result_words(5)
            if not 1 <= reg <= len(REGISTERS):
                raise RuntimeError('invalid native machine-plan conflict register')
            self.text(fn)  # Validate the HIA-selected immutable function pointer.
            message = ('interfering values ' + f'{self.function_name}' + '/' + self.text(block) + ': '
                       + self.text(left) + ' and ' + self.text(right) + ' share ' + REGISTERS[reg - 1])
            raise MachinePlanRejected('E_HIA_MACHINE_PLAN: ' + message)
        if result - 0x80000000 in MESSAGES:
            raise MachinePlanRejected('E_HIA_MACHINE_PLAN: ' + MESSAGES[result - 0x80000000])
        if result not in (1, 3, 4, 6, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18,
                          25, 26, 27, 28, 30, 31, 99, 118, 119):
            raise RuntimeError('native machine-plan protocol/ABI refusal: ' + hex(result))
        return result

    @staticmethod
    def expect(actual, expected):
        if actual != expected:
            raise RuntimeError('native machine-plan continuation differs')

    def program(self, checked):
        document = checked.as_dict()
        self.function_objects = {fn['name']: fn for fn in document['functions']}
        wire = transport(document)
        # Exact Core has <=262144 nodes and <=8MiB canonical bytes. Each SSA
        # definition occupies >=80 transport bytes; all native rows and four
        # N-entry merge arrays use 96N bytes. Binary search avoids a hash
        # collision-dependent bound; plan permutations use <=24N bytes.
        # Five times this actual wire size leaves ample space without imposing
        # a new semantic limit on any verified Core document.
        self.grow(self.word(104) + 5 * len(wire) + 16384)
        return self.step(4, wire)


class NativeMachinePlan(NativeHiaJsonImage):
    def validate(self, checked, plan, witness):
        from hepta.hia_program import HIAProgramRejected, _decode
        with _Session(self) as session:
            session.expect(session.step(0, b'', 0, _kind(plan)), 1)
            try:
                frozen, _ = _decode(plan)
            except HIAProgramRejected as exc:
                try:
                    session.step(2)
                except ValueError as translated:
                    raise translated from exc
                raise RuntimeError('native machine-plan failed to reject a failed capture')
            wire = transport(frozen)
            session.grow(8192 + len(wire) + 16384)
            session.expect(session.step(1, wire), 3)
            core_identity = transport(checked.sha256)
            session.grow(session.word(104) + len(core_identity) + 16384)
            session.expect(session.step(3, core_identity), 4)
            action = session.program(checked)
            if action == 15:
                # This public call boundary is intentionally retained: callers
                # may observe it while mutating their original plan. The only
                # plan returned below remains the already captured snapshot.
                if session.word(96) == 4:
                    witness(checked, frozen['value_registers'], allow_leaf_registers=True)
                else:
                    witness(checked, frozen['value_registers'])
                session.expect(session.step(5), 99)
            else:
                session.expect(action, 99)
            return frozen

    def witness(self, checked, assignments, *, allow_leaf_registers=False):
        with _Session(self) as session:
            session.expect(session.step(0, b'', 1, _kind(assignments)), 4)
            session.expect(session.program(checked), 6)
            for name in assignments:
                wire, length = _text_fact(name)
                session.expect(session.step(6, wire, length), 6)
            session.expect(session.step(7), 8)
            session.expect(session.step(8, b'', int(bool(allow_leaf_registers))), 9)
            allowed_count, = session.result_words(1)
            if allowed_count not in (5, 7):
                raise RuntimeError('invalid native machine-plan register dictionary')
            # These ordinary dictionaries expose foreign __hash__/__eq__ at
            # HIA-requested lookup boundaries. HIA selects their finite keys
            # and owns all normal exact-string membership/admission decisions.
            register_indices = {reg: i for i, reg in enumerate(REGISTERS[:allowed_count], 1)}
            functions = {}
            for name, mapping in assignments.items():
                session.function_name = name
                session.expect(session.step(9, b'', _kind(mapping)), 10)
                for value, register in mapping.items():
                    left, left_length = _text_fact(value)
                    right, right_length = _text_fact(register)
                    children = left + right
                    wire = struct.pack('<QQQ', 5, 8 + len(children), 2) + children
                    session.expect(session.step(10, wire, left_length, right_length), 10)
                session.expect(session.step(11), 16)
                function = session.function_objects[name]
                action = session.step(16, transport(function['name']))
                while action == 17:
                    register, = session.result_words(1)
                    if register not in (6, 7):
                        raise RuntimeError('invalid native leaf-register observation')
                    action = session.step(17, b'', int(REGISTERS[register - 1] in mapping.values()))
                session.expect(action, 18)
                definitions = {p['name']: p['type'] for block in function['blocks']
                    for p in block['params'] + [p for op in block['ops'] for p in op['out']]}
                names = {value: value for value in definitions}
                for value in mapping:
                    wire, length = _text_fact(value)
                    action = session.step(18, wire, length)
                    if action == 118:
                        session.expect(session.step(118, b'', int(value in definitions)), 119)
                        action = session.step(119, transport(definitions[value]))
                    session.expect(action, 18)
                foreign_registers = [None]
                action = session.step(20)
                while action == 25:
                    value = names[session.text(session.result_words(1)[0])]
                    action = session.step(25, b'', int(value in mapping))
                    if action == 26:
                        foreign_registers.append(mapping[value])
                        session.expect(session.step(26, b'', len(foreign_registers) - 1), 27)
                        # The original row value and bucket lookup are two
                        # distinct dictionary reads; foreign equality may
                        # mutate the map between them. Do not merge them.
                        action = session.step(27, b'', register_indices[mapping[value]])
                while action == 28:
                    register, = session.result_words(1)
                    if not 1 <= register <= 5:
                        raise RuntimeError('invalid native callee-register observation')
                    action = session.step(28, b'', int(REGISTERS[register - 1] in mapping.values()))
                session.expect(action, 13)
                function_pointer, used, leaf_mask, opcodes, count = session.result_words(5)
                session.text(function_pointer)
                if used >> 5 or leaf_mask & ~96 or opcodes >> len(LEAF_OPS):
                    raise RuntimeError('native machine-plan witness masks differ')
                result = {'callee_saved_registers': [reg for i, reg in enumerate(REGISTERS[:5]) if used & (1 << i)],
                          'intervals': []}
                for _ in range(count):
                    session.expect(session.step(13), 14)
                    block, value, typ, handle, first, last = session.result_words(6)
                    if not 1 <= handle < len(foreign_registers):
                        raise RuntimeError('native machine-plan witness register handle differs')
                    result['intervals'].append({'block': session.text(block), 'value': session.text(value),
                        'type': session.text(typ), 'register': foreign_registers[handle], 'first': first, 'last': last})
                session.expect(session.step(13), 30)
                functions[name] = result
                session.expect(session.step(30), 12)
                action = session.step(12, b'', int(bool(allow_leaf_registers)))
                if action == 31:
                    # This lookup deliberately occurs after the second truth
                    # conversion, exactly as the ordinary foreign API does.
                    functions[name].update(
                        caller_clobbered_leaf_registers=[reg for i, reg in enumerate(REGISTERS[5:], 5) if leaf_mask & (1 << i)],
                        leaf_opcode_inventory=[op for i, op in enumerate(LEAF_OPS) if opcodes & (1 << i)])
                    action = session.step(31)
                session.expect(action, 9)
            session.expect(session.step(14), 99)
            return {'rule': RULE, 'functions': functions}


def installed_machine_plan(manifest_path):
    """Select immutable local code while checking its package-owned source."""
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeMachinePlan)
