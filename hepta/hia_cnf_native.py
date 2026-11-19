"""Transport Boolean clauses to the selected bounded HIA solver."""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path


SOURCE = _source_resource_path('examples/hia_bootstrap/cnf.hepta')
SCHEMA = 'hepta.hia.cnf-native.v1'
SELECTOR = 'HEPTA_HIA_CNF_MANIFEST'
REQUEST = int.from_bytes(b'HIACNF01', 'little')
REPLY = int.from_bytes(b'HIACNR01', 'little')
CLAUSE_LIMIT = 8192
STEP_LIMIT = 10_000_000
WORKSPACE = 1024
UNKNOWN, SAT, UNSAT = range(3)


class NativeCnf(NativeHiaJsonImage):
    def solve(self, variables, clauses, *, steps):
        if (type(variables) is not int or not 0 <= variables <= 64
                or len(clauses) > CLAUSE_LIMIT or type(steps) is not int or not 0 <= steps <= STEP_LIMIT):
            raise ValueError('formula or work budget exceeds the HIA Boolean profile')
        frame = struct.pack('<4Q', REQUEST, variables, len(clauses), steps)
        frame += b''.join(struct.pack('<2Q', positive, negative) for positive, negative in clauses)
        source = ctypes.create_string_buffer(frame, len(frame))
        reply = ctypes.create_string_buffer(32)
        scratch = ctypes.create_string_buffer(WORKSPACE)
        if self._entry(source, len(frame), reply, len(reply), scratch, len(scratch)) != len(reply):
            raise ValueError('HIA refused the Boolean formula')
        magic, verdict, model, cost = struct.unpack('<4Q', reply.raw)
        if (magic != REPLY or verdict not in (UNKNOWN, SAT, UNSAT)
                or model >= 1 << variables or verdict != SAT and model or cost > steps
                or verdict == UNKNOWN and cost != steps):
            raise RuntimeError('invalid HIA Boolean solver reply')
        return verdict, model, cost


def selected_cnf():
    manifest = os.environ.get(SELECTOR)
    return None if not manifest else _installed_json_image(manifest, SOURCE, SCHEMA, NativeCnf)


def bitblast_clauses(z3, expression, *, timeout_ms):
    """Accept only the precise tactic result of one closed Boolean subgoal."""
    context = expression.ctx
    goal = z3.Goal(ctx=context)
    goal.add(expression)
    plan = z3.Then(*(z3.Tactic(name, ctx=context) for name in ('simplify', 'bit-blast', 'tseitin-cnf')))
    try:
        reduced = z3.TryFor(plan, timeout_ms)(goal)
    except z3.Z3Exception:
        return None
    if len(reduced) != 1:
        return None
    goal = reduced[0]
    if goal.precision() != z3.Z3_GOAL_PRECISE or len(goal) > CLAUSE_LIMIT:
        return None
    variables = {}
    clauses = []
    for clause in goal:
        masks = [0, 0]
        literals = clause.children() if z3.is_or(clause) else (clause,)
        satisfied = False
        for literal in literals:
            negated = z3.is_not(literal)
            atom = literal.arg(0) if negated else literal
            if z3.is_true(atom) or z3.is_false(atom):
                satisfied |= z3.is_true(atom) != negated
                continue
            if not (z3.is_const(atom) and z3.is_bool(atom)
                    and atom.decl().kind() == z3.Z3_OP_UNINTERPRETED):
                return None
            index = variables.setdefault(atom.get_id(), len(variables))
            if index >= 64:
                return None
            masks[int(negated)] |= 1 << index
        if not satisfied:
            clauses.append(tuple(masks))
    return len(variables), clauses
