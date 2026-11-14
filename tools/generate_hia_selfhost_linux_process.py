"""Independent, explicitly selected flat Linux process compiler.

The ordinary compiler and Linux stdio v1 remain unchanged. This compiler rejects
the two historical ELF/CLI output modes and exports before function emission;
an independent HIA entry packer supplies ELF and the kernel-startup capability.
Only branches dominated by that rejection are projected out. All admission,
type, effect, loan, source and output limits within the remaining domain stay.
"""
from pathlib import Path
import ast
import copy
import hashlib
import json
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import generate_hia_selfhost as original
from tools.generate_hia_selfhost_linux_stdio import build, strict

PROFILE = 'selfhost_linux_process'
IO_EFFECT = 'linux_io'
STARTUP_EFFECT = 'linux_startup'
IO = ('linux.stdin.read', 'linux.stdout.write', 'linux.stderr.write')
STARTUP = ('linux.argv.count', 'linux.env.count', 'linux.argv.length',
           'linux.env.length', 'linux.argv.copy', 'linux.env.copy')
CAP = 0x600000
CAP_MAGIC = int.from_bytes(b'HIALPRC1', 'little')

HELPERS = r'''
def process_stdio(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    loan_access(w, a)
    if get(w, 232) != 4 or n != 3 or t != 11 or bt != 2:
        return fail(w, 91)
    c = get(w, ARGS + 16)
    if variable(w, c) != 2:
        return fail(w, 91)
    number = op - @linux.stdin.read@
    if number == 0:
        if at != 7:
            return fail(w, 91)
    else:
        if at != 6 and at != 7:
            return fail(w, 91)
    bulk_range_guard(o, w, a, b, c)
    load_var(o, w, 6, a, 0)
    load_var(o, w, 0, b, 0)
    # add rsi,rax, after both borrowed extent checks.
    emit_bytes(o, w, 0xc60148, 3)
    load_var(o, w, 2, c, 0)
    syscall = 1
    if number == 0:
        syscall = 0
    emit_bytes(o, w, 184 + (syscall << 8), 5)
    emit_bytes(o, w, 191 + (number << 8), 5)
    # syscall: only read(0)/write(1); descriptors exactly 0/1/2.
    emit_bytes(o, w, 0x050f, 2)
    return 0

def process_startup(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if get(w, 232) != 4 or t != 2:
        return fail(w, 92)
    command = (op - @linux.argv.count@) >> 1
    family = (op - @linux.argv.count@) & 1
    index = a
    c = 0
    d = 0
    e = 0
    if command == 0:
        if n != 0:
            return fail(w, 92)
    else:
        if command == 1:
            if n != 1 or at != 2:
                return fail(w, 92)
        else:
            c = get(w, ARGS + 16)
            d = get(w, ARGS + 24)
            e = get(w, ARGS + 32)
            if n != 5 or at != 7 or bt != 2 or variable(w, c) != 2 or variable(w, d) != 2 or variable(w, e) != 2:
                return fail(w, 92)
            loan_access(w, a)
            index = c
    # Fixed read-only capability page. No program integer is used as an address.
    # movabs rdx,CAP_MAGIC; cmp [absolute CAP],rdx; je +2; ud2.
    emit_bytes(o, w, 0xba48, 2)
    emit8(o, w, CAP_MAGIC)
    emit_bytes(o, w, 0x25143948, 4)
    emit4(o, w, CAP)
    emit_bytes(o, w, 0x0b0f0274, 4)
    if command == 0:
        # mov rax,[absolute count]; argv count16, environment count32.
        emit_bytes(o, w, 0x25048b48, 4)
        emit4(o, w, CAP + 16 + family * 16)
        return 0
    load_var(o, w, 0, index, 0)
    emit_bytes(o, w, 0x25148b48, 4)
    emit4(o, w, CAP + 16 + family * 16)
    # cmp rax,rdx; jb +2; ud2. Index must precede every pointer read.
    emit_bytes(o, w, 0x0b0f0272d03948, 7)
    emit_bytes(o, w, 0x25148b48, 4)
    emit4(o, w, CAP + 24 + family * 16)
    # mov rsi,[rdx+rax*8]; xor edx,edx.
    emit_bytes(o, w, 0xd231c2348b48, 6)
    # Read the kernel NUL terminator inside the sealed startup storage.
    # cmp byte[rsi+rdx],0; je +5; inc rdx; jmp -11.
    emit_bytes(o, w, 0xff48057400163c80, 8)
    emit_bytes(o, w, 0xf5ebc2, 3)
    if command == 1:
        emit_bytes(o, w, 0xd08948, 3)
        return 0
    load_var(o, w, 0, d, 0)
    # Source offset <= length, then count <= length-offset, without overflow.
    emit_bytes(o, w, 0x0b0f0276d03948, 7)
    emit_bytes(o, w, 0xc60148c22948, 6)
    load_var(o, w, 0, e, 0)
    emit_bytes(o, w, 0x0b0f0276d03948, 7)
    bulk_range_guard(o, w, a, b, e)
    load_var(o, w, 7, a, 0)
    load_var(o, w, 0, b, 0)
    emit_bytes(o, w, 0xc70148, 3)
    load_var(o, w, 1, e, 0)
    # cld; rep movsb. Even a zero copy has already checked both boundaries.
    emit_bytes(o, w, 0xa4f3fc, 3)
    load_var(o, w, 0, e, 0)
    return 0
'''.replace('CAP_MAGIC', str(CAP_MAGIC)).replace('CAP +', str(CAP) + ' +').replace('w, CAP)', 'w, ' + str(CAP) + ')')


class ClosedOutputDomain(ast.NodeTransformer):
    """Only private profile232 can be 0 or 4 after explicit admission.

    No other call/value is constant-folded. Keeping the before/after expressions
    and the complete reachable graph makes this small projection reviewable.
    """
    def __init__(self):
        self.replacements = []

    def visit_Compare(self, node):
        node = self.generic_visit(node)
        if (len(node.ops) == 1 and len(node.comparators) == 1
                and isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name)
                and node.left.func.id == 'byte'
                and ast.dump(node.left, include_attributes=False) == ast.dump(
                    ast.parse('byte(w,232)', mode='eval').body, include_attributes=False)
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value in (1, 2)
                and isinstance(node.ops[0], (ast.Eq, ast.NotEq))):
            value = isinstance(node.ops[0], ast.NotEq)
            self.replacements.append({'before': ast.unparse(node), 'after': value,
                                      'line': node.lineno})
            return ast.copy_location(ast.Constant(value=value), node)
        return node

    def visit_BoolOp(self, node):
        node = self.generic_visit(node)
        if all(isinstance(x, ast.Constant) and type(x.value) is bool for x in node.values):
            return ast.copy_location(ast.Constant(value=(all if isinstance(node.op, ast.And) else any)(
                x.value for x in node.values)), node)
        # A leading constant can eliminate only the original short-circuit tail.
        if isinstance(node.values[0], ast.Constant) and type(node.values[0].value) is bool:
            first = node.values[0].value
            if isinstance(node.op, ast.Or) and first or isinstance(node.op, ast.And) and not first:
                return ast.copy_location(ast.Constant(value=first), node)
            if len(node.values) == 2:
                return node.values[1]
            node.values = node.values[1:]
        return node

    def visit_If(self, node):
        node = self.generic_visit(node)
        if isinstance(node.test, ast.Constant) and type(node.test.value) is bool:
            return node.body if node.test.value else node.orelse
        return node

    def visit_FunctionDef(self, node):
        node = self.generic_visit(node)
        # The selected owned-instruction rejection ends its original function.
        for index, statement in enumerate(node.body):
            if isinstance(statement, ast.Return):
                node.body = node.body[:index + 1]
                break
        return node


def extension_source():
    words = dict(original.W)
    for name in (PROFILE, IO_EFFECT, STARTUP_EFFECT, *IO, *STARTUP):
        assert name not in words
        words[name] = 300 + len(words)
    source = original.SOURCE
    start = source.index('        if get(w, 8) == @selfhost_elf@:')
    stop = source.index('        expect(s, w, 10)\n        read_exports(s, w)', start)
    before = source[start:stop]
    after = '''        if get(w, 8) == @selfhost_elf@ or get(w, 8) == @selfhost_exec@:
            fail(w, 93)
            return 4294967295
        if get(w, 8) == @selfhost_linux_process@:
            put(w, 232, 4)
        next_token(s, w)
'''
    source = strict(source, before, after)
    source = strict(source, '        read_exports(s, w)\n', '''        put(w, 640, 0)
        put(w, 648, 0)
        if get(w, 8) == @exports@:
            fail(w, 93)
            return 4294967295
''')
    source = strict(source, '        validate_exports(s, w)\n', '')
    source = strict(source, '''        flag = 1
        if token != @alloc@:
            if token < @read@ or token > @trap@:
                return fail(w, 65)
            flag = 2 << (token - @read@)
''', '''        flag = 1
        if token == @linux_io@ or token == @linux_startup@:
            if get(w, 232) != 4:
                return fail(w, 65)
            flag = 16 << (token - @linux_io@)
        else:
            if token != @alloc@:
                if token < @read@ or token > @trap@:
                    return fail(w, 65)
                flag = 2 << (token - @read@)
''')
    source = strict(source, 'def instruction_effects(op:u64) -> u64:\n', '''def instruction_effects(op:u64) -> u64:
    if op == @linux.stdin.read@:
        return 28
    if op == @linux.stdout.write@ or op == @linux.stderr.write@:
        return 26
    if op >= @linux.argv.count@ and op <= @linux.env.copy@:
        if op >= @linux.argv.copy@:
            return 46
        return 42
''')
    source = strict(source, 'def operation_dispatch(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:\n', '''def operation_dispatch(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if op >= @linux.stdin.read@ and op <= @linux.stderr.write@:
        return process_stdio(o, w, op, n, a, b, at, bt, t)
    if op >= @linux.argv.count@ and op <= @linux.env.copy@:
        return process_startup(o, w, op, n, a, b, at, bt, t)
''')
    source += HELPERS
    globals_ = dict(vars(original)); globals_['SOURCE'] = source; globals_['W'] = words
    expanded = types.FunctionType(original.source_program.__code__, globals_)()
    tree = ast.parse(expanded)
    transform = ClosedOutputDomain()
    tree = transform.visit(tree)
    ast.fix_missing_locations(tree)
    functions = {n.name: n for n in tree.body}
    calls = {name: sorted({c.func.id for c in ast.walk(fn) if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Name) and c.func.id in functions}) for name, fn in functions.items()}
    reached = {'compile'}
    while True:
        next_ = reached | {callee for name in reached for callee in calls[name]}
        if next_ == reached:
            break
        reached = next_
    omitted = sorted(set(functions) - reached)
    tree.body = [fn for fn in tree.body if fn.name in reached]
    # No surviving function can set profile232 to a legacy output mode.
    writes = [n for fn in tree.body for n in ast.walk(fn) if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Name) and n.func.id in ('put', 'store')
              and len(n.args) == 3 and isinstance(n.args[1], ast.Constant) and n.args[1].value == 232]
    assert len(writes) == 1 and ast.literal_eval(writes[0].args[2]) == 4
    evidence = {'rejected_before_functions': ['selfhost_elf', 'selfhost_exec', 'exports'],
                'profile_header_clear_each_pass': 'fill_range(w, 0, 256, 0)',
                'only_profile_write': ast.unparse(writes[0]), 'profile_values': [0, 4],
                'folded_comparisons': transform.replacements, 'call_graph': calls,
                'retained_functions': [n.name for n in tree.body], 'unreachable_functions': omitted,
                'admission_before': before, 'admission_after': after}
    return ast.unparse(tree) + '\n', words, evidence


def generated():
    text, _, _ = extension_source()
    return build(text, True)[0]


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    text, words, projection = extension_source()
    rendered, author, report = build(text, True)
    target = ROOT / 'examples/hia_bootstrap/selfhost_linux_process.hepta'
    if args.check:
        if target.read_text() != rendered:
            raise SystemExit('Linux process compiler source differs')
    else:
        target.write_text(rendered)
    report.update(projection=projection, profile=PROFILE, words=words,
                  source_sha256=hashlib.sha256(rendered.encode()).hexdigest(),
                  source_bytes=len(rendered.encode()), matching_cold=False, whole=False)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: report[k] for k in ('counts','source_sha256','source_bytes','matching_cold','whole')}, sort_keys=True))


if __name__ == '__main__':
    main()
