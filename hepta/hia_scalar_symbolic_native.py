"""Transport closed HIA scalar expression recipes to the pinned SMT engine."""
from __future__ import annotations

import ctypes
from functools import lru_cache
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_opcodes import WIDTHS
from .hia_scalar_reference_native import OPCODES, WORD_MASK

SOURCE = _source_resource_path('examples/hia_bootstrap/scalar_symbolic.hepta')
SCHEMA = 'hepta.hia.scalar-symbolic-native.v1'
SELECTOR = 'HEPTA_HIA_SCALAR_SYMBOLIC_MANIFEST'
MAGIC = int.from_bytes(b'HIASMT01', 'little')
RESULT = int.from_bytes(b'HIASMR01', 'little')
ORDER_MAGIC = int.from_bytes(b'HIASMO01', 'little')
CONTROL_MAGIC = int.from_bytes(b'HIASMC01', 'little')
MAX_BLOCKS, MAX_OPERATIONS, MAX_PARAMETERS, MAX_RETURNS = 128, 2048, 32, 16
PROFILE_REFUSALS = ('symbolic_program_budget_exceeded', 'symbolic_signature_budget_exceeded',
                    'resource_effects_outside_scalar_profile', 'resource_types_outside_scalar_profile',
                    'operation_outside_scalar_profile', 'cyclic_cfg_outside_profile')
HEADER = struct.Struct('<8Q')
NODE = struct.Struct('<4Q')
MAX_NODES = 24
MAX_EDGES = 2 * MAX_BLOCKS
CONTROL_KINDS = {name: index for index, name in enumerate(('join', 'phi', 'split', 'observe'), 1)}
OPERATIONS = {name: index for index, name in enumerate((
    'literal', 'boolean', 'add', 'sub', 'mul', 'sdiv', 'srem', 'udiv', 'urem', 'shl', 'ashr', 'lshr',
    'neg', 'bvand', 'bvor', 'bvxor', 'bvnot', 'eq', 'ne', 'slt', 'sle', 'sgt', 'sge', 'ult', 'ule',
    'ugt', 'uge', 'not', 'and', 'or', 'select', 'sext', 'zext', 'extract', 'bv2int', 'or_inputs',
), 1)}
NAMES = {value: name for name, value in OPERATIONS.items()}
TRAPS = ('overflow', 'division_by_zero')


class SymbolicRecipeRejected(ValueError):
    """The selected HIA image did not produce an admitted expression graph."""


class NativeScalarSymbolic(NativeHiaJsonImage):
    @lru_cache(maxsize=256)
    def recipe(self, opcode, result, source, constant, translation):
        code = 0 if opcode == 'const' else OPCODES[opcode]
        width = {'bool': 1, 'unit': 0, **WIDTHS}
        wire = HEADER.pack(MAGIC, code, width[result], result.startswith('i'), width[source],
                           source.startswith('i'), int(constant or 0) & WORD_MASK, translation)
        request = ctypes.create_string_buffer(wire)
        output = ctypes.create_string_buffer(HEADER.size + MAX_NODES * NODE.size)
        unused = ctypes.create_string_buffer(1)
        size = self._entry(request, len(wire), output, len(output), unused, 0)
        mark, count, value, trap_count, tag1, cond1, tag2, cond2 = HEADER.unpack_from(output)
        if (mark != RESULT or count > MAX_NODES or size != HEADER.size + count * NODE.size
                or value >= count + 3 or trap_count > 2):
            raise SymbolicRecipeRejected('invalid HIA symbolic expression header')
        graph = tuple(NODE.iter_unpack(output.raw[HEADER.size:size]))
        traps = ((tag1, cond1), (tag2, cond2))[:trap_count]
        if any(tag not in (1, 2) or condition >= count + 3 for tag, condition in traps):
            raise SymbolicRecipeRejected('invalid HIA symbolic trap expression')
        return graph, value, tuple((TRAPS[tag - 1], condition) for tag, condition in traps)

    def function_order(self, names, successors, operations, parameters, returns, flags):
        count = len(names)
        encoded = struct.pack('<7Q', ORDER_MAGIC, count, operations, parameters, returns, flags, 0)
        if count <= MAX_BLOCKS:
            ranks = {name: position + 1 for position, name in enumerate(names)}
            encoded += b''.join(struct.pack('<2Q', *(ranks[target] for target in edges),
                                            *([0] * (2 - len(edges)))) for edges in successors)
        source = ctypes.create_string_buffer(encoded)
        output = ctypes.create_string_buffer(24 + 8 * MAX_BLOCKS)
        scratch = ctypes.create_string_buffer(8 * MAX_BLOCKS)
        size = self._entry(source, len(encoded), output, len(output), scratch, len(scratch))
        identity, refusal, observed = struct.unpack_from('<3Q', output)
        if identity != RESULT or refusal > len(PROFILE_REFUSALS):
            raise SymbolicRecipeRejected('invalid HIA acyclic-order reply')
        if refusal:
            if size != 24 or observed:
                raise SymbolicRecipeRejected('invalid HIA acyclic-order refusal')
            return (), PROFILE_REFUSALS[refusal - 1]
        if observed != count or size != 24 + 8 * count:
            raise SymbolicRecipeRejected('invalid HIA acyclic-order extent')
        indexes = struct.unpack_from(f'<{count}Q', output, 24)
        if set(indexes) != set(range(1, count + 1)):
            raise SymbolicRecipeRejected('invalid HIA acyclic-order permutation')
        return tuple(names[index - 1] for index in indexes), None

    def operation(self, z3, context, name, attrs, result, source, operands, *, translation=False):
        if translation and result == 'unit':
            return None, ()
        opcode = 'cast.' + attrs['mode'] if name == 'int.cast' else name
        graph, value, traps = self.recipe(opcode, result, source, attrs.get('value'), translation)
        terms = self._terms(z3, context, graph, list(operands) + [None] * (3 - len(operands)))
        return terms[value], tuple((tag, terms[index]) for tag, index in traps)

    @lru_cache(maxsize=256)
    def _control_recipe(self, kind, edges):
        wire = struct.pack('<3Q', CONTROL_MAGIC, CONTROL_KINDS[kind], edges)
        request = ctypes.create_string_buffer(wire)
        output = ctypes.create_string_buffer(HEADER.size + MAX_EDGES * NODE.size)
        unused = ctypes.create_string_buffer(1)
        size = self._entry(request, len(wire), output, len(output), unused, 0)
        mark, count, first, results, second, _, _, inputs = HEADER.unpack_from(output)
        expected_inputs = {'join': edges, 'phi': 2 * edges + 1, 'split': 2, 'observe': 3}
        expected_results = 2 if kind == 'split' else 1
        indexes = (first, second)[:results]
        if (mark != RESULT or count > MAX_EDGES or size != HEADER.size + count * NODE.size
                or results != expected_results or inputs != expected_inputs[kind]
                or any(index >= inputs + count for index in indexes)):
            raise SymbolicRecipeRejected('invalid HIA symbolic control reply')
        return tuple(NODE.iter_unpack(output.raw[HEADER.size:size])), indexes

    def control(self, z3, context, kind, operands, *, edges=0):
        graph, results = self._control_recipe(kind, edges)
        terms = self._terms(z3, context, graph, list(operands))
        return tuple(terms[index] for index in results)

    @staticmethod
    def _terms(z3, context, graph, terms):
        operations = _solver_operations(z3)
        for code, a, b, c in graph:
            primitive = NAMES.get(code)
            try:
                if primitive == 'literal':
                    number = a - (1 << 64) if c and a >> 63 else a
                    term = z3.BitVecVal(number, b, context)
                elif primitive == 'boolean':
                    term = z3.BoolVal(bool(a), context)
                elif primitive in ('sext', 'zext'):
                    constructor = z3.SignExt if primitive == 'sext' else z3.ZeroExt
                    term = constructor(b, terms[a])
                elif primitive == 'extract':
                    term = z3.Extract(b, c, terms[a])
                elif primitive == 'bv2int':
                    term = z3.BV2Int(terms[a], is_signed=bool(b))
                elif primitive == 'or_inputs':
                    if not 0 < a <= len(terms):
                        raise IndexError(a)
                    term = z3.Or(*terms[:a])
                else:
                    arity, operation = operations[primitive]
                    term = operation(*(terms[index] for index in (a, b, c)[:arity]))
            except (IndexError, KeyError, TypeError) as error:
                raise SymbolicRecipeRejected('invalid HIA symbolic expression operand') from error
            terms.append(term)
        return terms


@lru_cache(maxsize=1)
def _solver_operations(z3):
    from operator import add, and_, eq, ge, gt, invert, le, lshift, lt, mul, ne, neg, or_, rshift, sub, truediv, xor

    return {'add': (2, add), 'sub': (2, sub), 'mul': (2, mul), 'sdiv': (2, truediv),
            'srem': (2, z3.SRem), 'udiv': (2, z3.UDiv), 'urem': (2, z3.URem),
            'shl': (2, lshift), 'ashr': (2, rshift), 'lshr': (2, z3.LShR), 'neg': (1, neg),
            'bvand': (2, and_), 'bvor': (2, or_), 'bvxor': (2, xor), 'bvnot': (1, invert),
            'eq': (2, eq), 'ne': (2, ne), 'slt': (2, lt), 'sle': (2, le), 'sgt': (2, gt),
            'sge': (2, ge), 'ult': (2, z3.ULT), 'ule': (2, z3.ULE), 'ugt': (2, z3.UGT),
            'uge': (2, z3.UGE), 'not': (1, z3.Not), 'and': (2, z3.And),
            'or': (2, z3.Or), 'select': (3, z3.If)}


def selected_scalar_symbolic():
    selected = os.environ.get(SELECTOR)
    return None if selected is None else _installed_json_image(selected, SOURCE, SCHEMA, NativeScalarSymbolic)
