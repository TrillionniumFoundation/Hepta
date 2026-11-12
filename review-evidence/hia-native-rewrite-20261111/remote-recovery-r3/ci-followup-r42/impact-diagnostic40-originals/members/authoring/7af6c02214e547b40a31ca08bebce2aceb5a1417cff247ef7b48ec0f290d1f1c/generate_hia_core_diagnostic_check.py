"""Add exact failure context to the complete existing primitive Core owner.

The admitted language, passes, branch ordering, resource transitions and quotas
stay in the same HIA functions. A direct failure records a message identity and
at most three arena references/scalars. No hosted semantic decision is called.
"""
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.core_diagnostic_messages import IDS, MAGIC, CONTEXT_BYTES
from tools.core_diagnostic_authoring import write

NONE = (1 << 64) - 1
ABI = 0xfffffffd
BASE_SOURCE = ROOT / 'dependencies/core_admission.authoring.py'


def expr(text):
    return ast.parse(str(text), mode='eval').body


def statements(text):
    return ast.parse(text).body


def choice(condition, left, right):
    return f'choose({condition}, {IDS[left]}, {IDS[right]})'


def spec(name, a='0', b='0', c='0'):
    return (str(IDS[name]) if name in IDS else name, a, b, c)


SITES = {
    'program_shape': [
        spec(choice('exports != 18446744073709551615', 'PROGRAM_EXPORT_KEYS', 'PROGRAM_KEYS')),
        spec('SCHEMA'), spec('MODULE_IDENT'), spec('FUNCTION_INVENTORY'),
        spec('DUPLICATE_FUNCTION'), spec('DUPLICATE_EXPORT'), spec('EXPORT_MISSING'),
        spec('EXPORT_RESOURCE'), spec('EXPORT_RESOURCE')],
    'check_function': [
        spec(choice('(fields & 1024) != 0', 'FUNCTION_LOAN_KEYS', 'FUNCTION_KEYS')),
        spec(choice('identifier(w, name) == 0', 'FUNCTION_IDENT', 'RUNTIME_NAME')),
        spec('RETURNS_LIST'), spec('TYPE'), spec('LOAN_VERSION'), spec('ORIGIN_ARITY'),
        spec('ORIGIN_NONLOAN'), spec('ORIGIN_PERMISSION'), spec('ORIGIN_PERMISSION'), spec('ORIGIN_PERMISSION'),
        spec('EFFECTS'), spec('EFFECTS'), spec('ENTRY_IDENT'), spec('BLOCK_INVENTORY'),
        spec('BLOCK_KEYS'), spec('BLOCK_IDENT'), spec('DUPLICATE_BLOCK'), spec('OPERATIONS_LIST'),
        spec('INSTRUCTION_KEYS'), spec('OPCODE_TEXT'), spec('ATTRIBUTES_OBJECT'),
        spec('ENTRY_SIGNATURE'), spec('ENTRY_SIGNATURE'), spec('UNREACHABLE'), spec('CHAIN_VERSION')],
    'parameters': [spec('PARAMETER_LIST', 'where'), spec('PARAMETER_KEYS', 'where'),
        spec('WHERE_IDENT', 'where'), spec('TYPE'), spec('DUPLICATE_PARAMETER', 'where', 'name')],
    'definitions': [spec('DUPLICATE_SSA', 'field(w, item, 16)')],
    'names': [spec('VALUE_LIST', 'where'), spec('WHERE_IDENT', 'where')],
    'edge': [spec('EDGE_KEYS'), spec('EDGE_TARGET_IDENT')],
    'terminator': [spec('MISSING_TERMINATOR'), spec('RETURN_KEYS'), spec('JUMP_KEYS'),
        spec('EDGE_TARGET_IDENT'), spec('BRANCH_KEYS'), spec('BRANCH_CONDITION_IDENT'),
        spec('TRAP_KEYS'), spec('TRAP_CODE'),
        spec(choice('kind(w, op) != 4', 'MISSING_TERMINATOR', 'UNKNOWN_TERMINATOR'))],
    'connect': [spec(choice('target == 18446744073709551615', 'MISSING_BLOCK', 'ENTRY_INCOMING')),
        spec('EDGE_ARITY')],
    'value': [spec('UNDEFINED_VALUE', 'name', 'get(o, 80)', 'get(o, 56) - 1'),
        spec('UNDEFINED_VALUE', 'name', 'get(o, 80)', 'get(o, 56) - 1'), spec('CONSUMED_RESOURCE', 'name')],
    'owner_free': [spec('OWNER_REQUIRED'), spec('OWNER_BORROWED')],
    'access': [spec('VIEW_REQUIRED'), spec('PARENT_SUSPENDED')],
    'borrow': [spec('BORROW_PERMISSION'), spec('BORROW_GRAPH'), spec('BORROW_GRAPH'), spec('BORROW_CONFLICT')],
    'local_types': [spec('OPCODE_ATTRIBUTES', 'field(w, ins, 16384)'), spec('OPCODE_ATTRIBUTES', 'field(w, ins, 16384)'),
        spec('OPERAND_COUNT', 'field(w, ins, 16384)'), spec('OPERAND_TYPES', 'field(w, ins, 16384)'),
        spec('OUTPUT_COUNT', 'field(w, ins, 16384)'), spec('OUTPUT_TYPES', 'field(w, ins, 16384)'),
        spec('CONSTANT'), spec('CAST')],
    'guards': [spec(choice('cap(o, name, 32) != 0', 'END_CALLER_LOAN', 'END_CHILD_LOANS')),
        spec('DISTINCT_OWNER', 'field(w, ins, 16384)')],
    'callee': [spec('CALLEE_IDENT'), spec('UNKNOWN_CALLEE')],
    'call_instruction': [spec('CALL_ARITY'), spec('CALL_ARGUMENT_TYPE'), spec('CALL_DUPLICATE_OWNER'),
        spec('CALL_ALIAS_VIEWS'), spec('CALL_RETURN_TYPES', 'returns'), spec('CALL_RETURN_TYPES', 'returns')],
    'finish': [spec('BRANCH_BOOL'), spec('MISSING_EFFECTS', 'get(o, 72) & (15 ^ mask)')],
    'finish_return': [spec('RETURN_TYPES'), spec('RETURN_TYPES'), spec('DUPLICATE_RETURN_LOAN'),
        spec('RETURN_ORIGIN'), spec('RETURN_ORIGIN'), spec('DUPLICATE_RETURN_OWNER'), spec('RETURN_LIVE')],
    'function_body': [spec('BLOCKS_CHECKED')],
    'transfer': [spec('EDGE_TYPES'), spec('EDGE_DUPLICATE'), spec('EDGE_DROPS'),
        spec('EDGE_PARENT'), spec('EDGE_PARENT'), spec('EDGE_PREDECESSOR')],
}


def failures(fn):
    found = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Return) and isinstance(node.value, ast.Constant)
                and type(node.value.value) is int and 0xffffffee <= node.value.value <= 0xffffffff
                and node.value.value != ABI):
            found.append(node)
        elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name) and node.value.func.id == 'put'
                and ast.unparse(node.value.args[0]) == 'o' and ast.unparse(node.value.args[1]) == '0'
                and ast.unparse(node.value.args[2]) != '0'):
            found.append(node)
    return sorted(found, key=lambda node: node.lineno)


def source_program():
    original = BASE_SOURCE.read_bytes()
    frozen = json.loads((ROOT / 'checkpoints/contract-r1/inventory.json').read_bytes())
    assert sha256(original).hexdigest() == frozen['expanded_native_authoring']['sha256']
    tree = ast.parse(original)
    by_name = {fn.name: fn for fn in tree.body}
    ledger = []
    for name, specs in SITES.items():
        nodes = failures(by_name[name])
        assert len(nodes) == len(specs), (name, len(nodes), len(specs))
        for node, (diagnostic, a, b, c) in zip(nodes, specs):
            before = ast.unparse(node)
            code = node.value if isinstance(node, ast.Return) else node.value.args[2]
            call = ast.Call(func=ast.Name(id='diagnose', ctx=ast.Load()), args=[expr('o'),
                copy.deepcopy(code), expr(diagnostic), expr(a), expr(b), expr(c)], keywords=[])
            if isinstance(node, ast.Return):
                node.value = call
            else:
                node.value.args[2] = call
            ledger.append({'function': name, 'line': node.lineno, 'before': before, 'after': ast.unparse(node)})

    # The catalog dispatcher has one original version failure per known opcode
    # and one unknown-opcode failure. The original branch order is unchanged.
    instruction = by_name['instruction']
    assigned = set()
    for branch in instruction.body:
        if not isinstance(branch, ast.If):
            continue
        guard = branch.body[0]
        assert isinstance(guard, ast.If) and isinstance(guard.test, ast.Compare)
        since = guard.test.comparators[0]
        assert isinstance(since, ast.Constant) and 1 <= since.value <= 8
        failure = guard.body[0]
        assert failure in failures(instruction)
        before = ast.unparse(failure)
        failure.value.args[2] = expr(f'diagnose(o, 4294967280, {IDS["OPCODE_VERSION"]}, op, {since.value}, 0)')
        assigned.add(id(failure))
        ledger.append({'function': 'instruction', 'line': failure.lineno, 'before': before, 'after': ast.unparse(failure)})
    unknown = instruction.body[-2]
    assert isinstance(unknown, ast.Expr) and ast.unparse(unknown) == 'put(o, 0, 4294967280)'
    unknown.value.args[2] = expr(f'diagnose(o, 4294967280, {IDS["UNKNOWN_OPCODE"]}, op, 0, 0)')
    ledger.append({'function': 'instruction', 'line': unknown.lineno, 'before': 'put(o, 0, 4294967280)', 'after': ast.unparse(unknown)})

    # Add only the source-position label required by the old _parameters/_names
    # messages. The actual parameter/name checks remain the existing functions.
    for name in ('parameters', 'names'):
        fn = by_name[name]
        if name == 'names':
            fn.args.args.insert(1, ast.arg(arg='o', annotation=expr('mutbuf')))
        fn.args.args.append(ast.arg(arg='where', annotation=expr('u64')))
    for name in ('edge', 'terminator'):
        by_name[name].args.args.insert(1, ast.arg(arg='o', annotation=expr('mutbuf')))
    for fn in tree.body:
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            name = call.func.id
            if name == 'parameters':
                assert fn.name == 'check_function'
                arg = ast.unparse(call.args[2])
                where = {'params': 1, 'field(w, block, 32)': 2, 'field(w, ins, 65536)': 3}[arg]
                call.args.append(expr(where))
            elif name == 'names':
                arg = ast.unparse(call.args[1])
                where = {('program_shape', 'exports'): 4, ('check_function', 'field(w, ins, 32768)'): 5,
                         ('edge', 'field(w, node, 32768)'): 6, ('terminator', 'field(w, node, 32768)'): 6,
                         ('terminator', 'field(w, node, 262144)'): 7}[(fn.name, arg)]
                call.args.insert(1, expr('o'))
                call.args.append(expr(where))
            elif name in ('edge', 'terminator'):
                call.args.insert(1, expr('o'))

    # Reserve a fixed 512-byte diagnostic tail beyond all original checker
    # tables. It is not an input or language quota. ABI capacity failure stays
    # an ABI failure, and no successful prior admission is cached.
    program = by_name['program_shape']
    changed = 0
    for node in ast.walk(program):
        if isinstance(node, ast.Compare) and ast.unparse(node) == 'length(o) < base + 4096 * 40':
            node.comparators[0] = expr('base + 4096 * 40 + 512')
            changed += 1
    assert changed == 1
    insertion = next(i for i, n in enumerate(program.body) if isinstance(n, ast.Expr)
                     and ast.unparse(n) == 'put(o, 16, slots)')
    program.body[insertion:insertion] = statements('diagnostic_begin(o, length(s), get(w, 8), get(w, 24))')
    core = by_name['core_admission']
    changed = 0
    for node in ast.walk(core):
        if isinstance(node, ast.Compare) and ast.unparse(node) == 'length(o) < state + nodes * 120':
            node.comparators[0] = expr('state + nodes * 120 + 512')
            changed += 1
    assert changed == 1 and isinstance(core.body[-1], ast.Return)
    core.body[-1:-1] = statements('put(o, length(o) - 512 + 80, 1)')
    helpers = f'''
def diagnostic_begin(o:mutbuf, source_bytes:u64, nodes:u64, extent:u64) -> u64:
    base = length(o) - {CONTEXT_BYTES}
    at = base
    while at < length(o):
        put(o, at, 0)
        at = at + 8
    put(o, base, {MAGIC})
    put(o, base + 8, 1)
    put(o, base + 56, source_bytes)
    put(o, base + 64, nodes)
    put(o, base + 72, extent)
    return 0

def diagnose(o:mutbuf, code:u64, message:u64, a:u64, b:u64, c:u64) -> u64:
    base = length(o) - {CONTEXT_BYTES}
    put(o, base + 16, code)
    put(o, base + 24, message)
    put(o, base + 32, a)
    put(o, base + 40, b)
    put(o, base + 48, c)
    return code
'''
    tree.body += ast.parse(helpers).body
    tree = ast.fix_missing_locations(tree)
    text = ast.unparse(tree) + '\n'
    (ROOT / 'development/failure-site-transform.json').write_text(json.dumps({
        'scope': 'EXACT_BASELINE_FAILURE_POINT_ANNOTATION', 'original_authoring_sha256': sha256(original).hexdigest(),
        'generated_authoring_sha256': sha256(text.encode()).hexdigest(), 'sites': ledger,
        'original_language_limits_unchanged': True}, indent=2, sort_keys=True) + '\n')
    return text


if __name__ == '__main__':
    write(source_program(), 'core_diagnostic_check')
