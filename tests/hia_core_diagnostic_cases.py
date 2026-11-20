"""Independent complete-message witnesses for whole native Core admission."""
from copy import deepcopy
from functools import lru_cache

from hepta.hia_opcodes import OPCODES
from tests.test_hia_program import b, f, i, m, ret, branch


def closure_before_join():
    # The first resource changes its original formal, while a later resource
    # loses an external parent. The whole edge must close before any join
    # comparison, so missing-parent is the first refusal.
    params = [('q', 'bool'), ('a', 'readbuf'), ('z', 'readbuf')]
    function = f('ordered', params, ['readbuf'], [], [
        b('entry', params, [i('borrow.read', ['a'], [('v', 'readbuf')])],
          branch('q', ('joined', 'a', 'v'), ('joined', 'z', 'v'))),
        b('joined', [('p', 'readbuf'), ('r', 'readbuf')],
          [i('loan.end', ['r'])], ret('p')),
    ])
    function['return_loans'] = ['a']
    value = m(function)
    value['schema'] = 'hepta.hia.program.v8'
    return value


def structured_mutations(document):
    replacements = (None, False, 0, 'invalid', [], {}, ['invalid'])
    paths = []

    def visit(node, path):
        if type(node) is dict:
            for key, value in node.items():
                paths.append(path + (key,))
                visit(value, path + (key,))
        elif type(node) is list:
            for index, value in enumerate(node):
                paths.append(path + (index,))
                visit(value, path + (index,))

    visit(document, ())
    for path in paths:
        for replacement in replacements:
            value = deepcopy(document)
            parent = value
            for part in path[:-1]:
                parent = parent[part]
            parent[path[-1]] = deepcopy(replacement)
            yield ('replace', path, replacement), value
        if type(path[-1]) is str:
            value = deepcopy(document)
            parent = value
            for part in path[:-1]:
                parent = parent[part]
            del parent[path[-1]]
            yield ('delete', path), value


def opcode_documents():
    """Each catalog row, every local check family, and older version refusal."""
    groups = {'integer': 'u32', 'scalar': 'u32', 'equality': 'u32',
              'owner': 'buffer', 'bytes': 'buffer', 'view': 'readbuf',
              'mutable_source': 'buffer'}

    def resolve(rule, operands):
        if rule.startswith('='):
            return operands[int(rule[1:])]
        rule = rule.removeprefix('declared:')
        return groups.get(rule, rule)

    for spec in OPCODES.values():
        types = []
        for rule in spec.operands or ():
            types.append(resolve(rule, types))
        params = [('arg' + str(index), typ) for index, typ in enumerate(types)]
        out = [('out' + str(index), resolve(rule, types))
               for index, rule in enumerate(spec.results or ())]
        attrs = {name: {'value': 0, 'mode': 'wrap', 'function': 'callee'}[name]
                 for name in spec.attributes}
        value = m(f('caller', params, [], ['alloc', 'read', 'write', 'trap'], [
            b('entry', params, [i(spec.name, [name for name, _ in params], out, **attrs)],
              {'op': 'trap', 'code': 'user'})]))
        value['schema'] = 'hepta.hia.program.v8'
        if spec.name == 'call':
            value['functions'].append(f('callee', [], [], [], [b('entry', [], [], ret())]))
        yield (spec.name, 'complete'), value
        for version in range(1, spec.since):
            changed = deepcopy(value)
            changed['schema'] = 'hepta.hia.program.v' + str(version)
            yield (spec.name, 'version', version), changed
        for mutation in ('attrs', 'operand_count', 'output_count', 'operand_type', 'output_type'):
            changed = deepcopy(value)
            fn = changed['functions'][0]
            instruction = fn['blocks'][0]['ops'][0]
            if mutation == 'attrs':
                instruction['attrs'] = {'unexpected': 0}
            elif mutation == 'operand_count':
                # Every name remains live, so operand arity wins over liveness.
                fn['params'].append({'name': 'spare', 'type': 'u32'})
                fn['blocks'][0]['params'].append({'name': 'spare', 'type': 'u32'})
                instruction['args'].append('spare')
            elif mutation == 'output_count':
                instruction['out'].append({'name': 'spare', 'type': 'u32'})
            elif mutation == 'operand_type':
                if not params:
                    continue
                fn['params'][0]['type'] = fn['blocks'][0]['params'][0]['type'] = 'unit'
            elif mutation == 'output_type':
                if not out:
                    continue
                instruction['out'][0]['type'] = 'unit'
            yield (spec.name, mutation), changed


def long_return_interface(count):
    callee = f('callee', [], ['u8'] * count, ['trap'], [
        b('entry', [], [], {'op': 'trap', 'code': 'user'})])
    caller = f('caller', [], [], ['trap'], [
        b('entry', [], [i('call', [], [], function='callee')], ret())])
    value = m(callee, caller)
    value['schema'] = 'hepta.hia.program.v8'
    return value


@lru_cache(maxsize=1)
def _checked(source):
    from hepta.hia_agent_assembly import assemble_program
    return assemble_program(source)


def vm_buffers(raw):
    from hepta.hia_core_admission_native import SOURCE, scratch_sizes
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    program = _checked(SOURCE.read_bytes())
    state, arena = scratch_sizes(len(raw))
    machine = _Machine(program, 3000000, 16 << 20, None, 256)
    owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(state)),
              _Owner(-3, bytearray(arena))]
    entry = next(fn for fn in program.as_dict()['functions'] if fn['name'] == 'f0')
    status = machine.invoke(entry, [_View(owners[0], False), _View(owners[1], True),
                                   _View(owners[2], True)])[0]
    return status, tuple(bytes(owner.data) for owner in owners), machine.steps
