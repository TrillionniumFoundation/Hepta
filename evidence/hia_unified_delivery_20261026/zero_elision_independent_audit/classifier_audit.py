from copy import deepcopy
from hepta.hia_program_llvm import _can_elide_zero_initialization
from tools.qualify_hia_program import function, block, constant, operation, ret, jump
base = function('candidate', [('n', 'usize')], ['usize'], ['alloc'], [
    block('entry', [('n', 'usize')], [operation('buffer.try_new', ['n'], [('b', 'buffer'), ('ok', 'bool')])], jump('later', 'b')),
    block('later', [('lb', 'buffer')], [operation('borrow.read', ['lb'], [('lr', 'readbuf')]), operation('buffer.len', ['lr'], [('length', 'usize')]), operation('loan.end', ['lr']), operation('owner.drop', ['lb'])], ret('length'))])
assert _can_elide_zero_initialization(base)
checks = 1
for index in range(len(base['blocks'])):
    for opcode in ('call','buffer.load','buffer.store','buffer.copy','buffer.hash','buffer.address','foreign.call','future.op'):
        altered = deepcopy(base)
        altered['blocks'][index]['ops'].append(operation(opcode))
        assert _can_elide_zero_initialization(altered) is False, (index, opcode)
        checks += 1
    for opcode in ('invoke','tailcall','yield','switch','future.term'):
        altered = deepcopy(base)
        altered['blocks'][index]['term']['op'] = opcode
        assert _can_elide_zero_initialization(altered) is False, (index, opcode)
        checks += 1
for typ in ('buffer','readbuf','mutbuf','future_resource','ptr','record_with_buffer'):
    for place in ('parameter','return'):
        altered = deepcopy(base)
        if place == 'parameter': altered['params'][0]['type'] = typ
        else: altered['returns'] = [typ]
        assert _can_elide_zero_initialization(altered) is False, (typ, place)
        checks += 1
print({'predicate_checks': checks, 'all_passed': True, 'mutation_scope': 'private optimization classifier only; malformed future cases are not claimed as verified programs'})
