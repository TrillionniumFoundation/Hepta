"""HIA process controller for the frozen ordinary capabilities/catalog CLI.

The new process ABI uses native byte-result handles, not the former Python
dictionary handles. Frozen control still owns parse/step/claim/ACK and frozen
format/discovery programs own all presentation. This author emits HIA only.
"""
from pathlib import Path
import ast
import hashlib
import inspect
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.generate_hia_selfhost import Builder, total_scalar_functions, compact_authoring_cfg
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_linux_cli_process import PROFILE, MODULE

SOURCE = r'''
def run(a:mutbuf, b:mutbuf, w:mutbuf) -> u32:
    if length(a) != 1048576 or length(b) != 1048576 or length(w) != 1048576:
        return 126
    raw = arguments(a, b)
    if raw == 18446744073709551615:
        return 126
    count = uint(a, 16, 8)
    needed = 65536 + count * 80 + raw
    if needed > 1048576:
        return 126
    fill_range(w, 0, 131072, 0)
    write(w, 0, OBSERVE_MAGIC, 8)
    observed = cli_format(a, 0, raw, b, 0, 1048576, w, 0, 131072)
    observed_size = uint(w, 1024, 8)
    observed_split = uint(w, 1032, 8)
    observed_tty = uint(w, 1064, 8)
    if observed != 3 or observed_size != 0 or observed_split != 0 or observed_tty > 1:
        return 126
    # This explicit process presentation profile is the fixed non-TTY,
    # ordinary 3.12 UTF-8 case. It does not claim the terminal/locale domain.
    write(a, 32, 0, 8)
    write(a, 80, 1, 8)
    fill_range(w, 0, needed, 0)
    code = cli_control(a, 0, raw, b, 0, 128, w, 0, needed)
    magic = uint(w, 0, 8)
    if code != 0 or magic != RESULT_MAGIC:
        return 126
    kind = uint(w, 8, 8)
    exit_code = uint(w, 112, 8)
    if kind > 3 or (exit_code != 0 and exit_code != 2):
        return 126
    if kind != 0:
        return presentation(a, b, w, raw, count, kind, exit_code)
    action = uint(w, 16, 8)
    if action != 1 and action != 2:
        return 126
    return drive(a, b, w, needed, action)

def arguments(a:mutbuf, b:mutbuf) -> u64:
    count = argc()
    if count != 0:
        count = count - 1
    if count > 65524:
        return 18446744073709551615
    cursor = 192 + count * 16
    fill_range(a, 0, cursor, 0)
    write(a, 0, ARGV_MAGIC, 8)
    write(a, 8, 4, 8)
    write(a, 16, count, 8)
    write(a, 24, 312, 8)
    write(a, 32, 80, 8)
    write(a, 56, 4300, 8)
    write(a, 72, 1, 8)
    version(b)
    write(a, 96, cursor, 8)
    end = decode(a, cursor, b, 0, 9)
    if end == 18446744073709551615:
        return end
    write(a, 104, (end - cursor) >> 2, 8)
    cursor = end
    kind = 1
    while kind < 6:
        write(a, 96 + kind * 16, cursor, 8)
        selected = 18446744073709551615
        envs = envc()
        i = 0
        while i < envs:
            n = envlen(i)
            prefix = n
            if prefix > 14:
                prefix = 14
            got = envcopy(b, 0, i, 0, prefix)
            if got != prefix:
                return 18446744073709551615
            if environment_kind(b, prefix) == kind:
                selected = i
                i = envs
            else:
                i = i + 1
        if selected != 18446744073709551615:
            n = envlen(selected)
            # kind is dominated by the loop's exact 1..5 range. Each byte
            # is the length of the corresponding literal key, in that order.
            start = (PREFIX_LENGTHS >> ((kind - 1) * 8)) & 255
            if n < start or n - start > 1048576:
                return 18446744073709551615
            n = n - start
            got = envcopy(b, 0, selected, start, n)
            if got != n:
                return 18446744073709551615
            end = decode(a, cursor, b, 0, n)
            if end == 18446744073709551615:
                return end
            write(a, 104 + kind * 16, (end - cursor) >> 2, 8)
            write(a, 72, uint(a, 72, 8) | (1 << kind), 8)
            cursor = end
        kind = kind + 1
    i = 0
    while i < count:
        n = arglen(i + 1)
        if n > 1048576:
            return 18446744073709551615
        got = argcopy(b, 0, i + 1, 0, n)
        if got != n:
            return 18446744073709551615
        write(a, 192 + i * 16, cursor, 8)
        end = decode(a, cursor, b, 0, n)
        if end == 18446744073709551615:
            return end
        write(a, 200 + i * 16, (end - cursor) >> 2, 8)
        cursor = end
        i = i + 1
    return cursor

def decode(a:mutbuf, cursor:u64, b:mutbuf, at:u64, n:u64) -> u64:
    end = at + n
    while at < end:
        x = byte(b, at)
        cp = x
        take = 1
        if x >= 128:
            cp = 56320 + x
            if x >= 194 and x <= 223 and end - at >= 2:
                y = byte(b, at + 1)
                if y >= 128 and y <= 191:
                    cp = ((x & 31) << 6) | (y & 63)
                    take = 2
            if x >= 224 and x <= 239 and end - at >= 3:
                y = byte(b, at + 1)
                z = byte(b, at + 2)
                if y >= 128 and y <= 191 and z >= 128 and z <= 191:
                    if (x != 224 or y >= 160) and (x != 237 or y < 160):
                        cp = ((x & 15) << 12) | ((y & 63) << 6) | (z & 63)
                        take = 3
            if x >= 240 and x <= 244 and end - at >= 4:
                y = byte(b, at + 1)
                z = byte(b, at + 2)
                q = byte(b, at + 3)
                if y >= 128 and y <= 191 and z >= 128 and z <= 191 and q >= 128 and q <= 191:
                    if (x != 240 or y >= 144) and (x != 244 or y < 144):
                        cp = ((x & 7) << 18) | ((y & 63) << 12) | ((z & 63) << 6) | (q & 63)
                        take = 4
        if cursor > 1048572:
            return 18446744073709551615
        write(a, cursor, cp, 4)
        cursor = cursor + 4
        at = at + take
    return cursor

def encode(a:mutbuf, at:u64, b:mutbuf, source:u64, count:u64, errors:u64) -> u64:
    i = 0
    while i < count:
        cp = uint(b, source + i * 4, 4)
        at = encode_point(a, at, cp, errors)
        if at == 18446744073709551615:
            return at
        i = i + 1
    return at

def encode_point(a:mutbuf, at:u64, cp:u64, errors:u64) -> u64:
    if cp > 1114111:
        return 18446744073709551615
    size = 1
    if cp >= 128:
        size = 2
    if cp >= 2048:
        size = 3
    if cp >= 65536:
        size = 4
    if cp >= 55296 and cp <= 57343:
        if errors == 1:
            size = 6
        else:
            if cp < 56448 or cp > 56575:
                return 18446744073709551615
            size = 1
    if at > 1048576 - size:
        return 18446744073709551615
    if size == 6:
        store(a, at, 92)
        store(a, at + 1, 117)
        i = 0
        while i < 4:
            digit = (cp >> ((3 - i) * 4)) & 15
            store(a, at + 2 + i, choose(digit < 10, 48 + digit, 87 + digit))
            i = i + 1
        return at + 6
    if size == 1:
        if cp >= 56448 and cp <= 56575:
            cp = cp - 56320
        store(a, at, cp)
    else:
        if size == 2:
            store(a, at, 192 | (cp >> 6))
            store(a, at + 1, 128 | (cp & 63))
        else:
            if size == 3:
                store(a, at, 224 | (cp >> 12))
                store(a, at + 1, 128 | ((cp >> 6) & 63))
                store(a, at + 2, 128 | (cp & 63))
            else:
                store(a, at, 240 | (cp >> 18))
                store(a, at + 1, 128 | ((cp >> 12) & 63))
                store(a, at + 2, 128 | ((cp >> 6) & 63))
                store(a, at + 3, 128 | (cp & 63))
    return at + size

def presentation(a:mutbuf, b:mutbuf, w:mutbuf, raw:u64, count:u64, kind:u64, exit_code:u64) -> u32:
    extras = uint(w, 80, 8)
    if extras > count or 131072 + count * 24 > 1048576:
        return 126
    copy_exact(b, w, 0, 0, 1024)
    copy_exact(b, w, 1024, 32768 + count * 48, extras * 24)
    needed = 131072 + count * 24
    fill_range(w, 0, needed, 0)
    copy_exact(w, b, 0, 0, 1024)
    copy_exact(w, b, 131072, 1024, extras * 24)
    code = cli_format(a, 0, raw, b, 0, 1048576, w, 0, needed)
    size = uint(w, 1024, 8)
    split = uint(w, 1032, 8)
    if code != 0 or size > 262144 or split > size:
        return 126
    if kind == 3:
        end = encode(a, 0, b, 0, split, 1)
        if end == 18446744073709551615:
            return 126
        ignored = send(a, 0, end, 2)
        end = encode(a, 0, b, split * 4, size - split, 1)
        if end == 18446744073709551615:
            return 126
        ignored = send(a, 0, end, 2)
    else:
        end = encode(a, 0, b, 0, size, 0)
        if end == 18446744073709551615:
            return 126
        ignored = send(a, 0, end, 1)
    return exit_code

def packet(a:mutbuf, sequence:u64, operation:u64, value:u64) -> u64:
    fill_range(a, 0, 96, 0)
    write(a, 0, STEP_MAGIC, 8)
    write(a, 8, 4, 8)
    write(a, 16, sequence, 8)
    write(a, 24, operation, 8)
    write(a, 40, value, 8)
    write(a, 88, 1, 8)
    return 0

def command(b:mutbuf, sequence:u64, code:u64) -> u64:
    # The entire 128-byte reply was just written to our private bounded buffer.
    # Reading its fixed fields first is total and has no external observation.
    # This avoids duplicating control-flow parameter moves for each field read.
    magic = uint(b, 0, 8)
    op = uint(b, 8, 8)
    seq = uint(b, 16, 8)
    catching = uint(b, 24, 8)
    first = uint(b, 32, 8)
    second = uint(b, 40, 8)
    third = uint(b, 48, 8)
    fourth = uint(b, 56, 8)
    consumes = uint(b, 64, 8)
    location = uint(b, 72, 8)
    if magic != COMMAND_MAGIC:
        return 0
    i = 80
    while i < 128:
        if uint(b, i, 8) != 0:
            return 0
        i = i + 8
    if code == 2:
        if op != 0 or seq != sequence or catching != 0 or first != 0:
            return 0
        if second != 0 or third != 0 or fourth != 0 or consumes != 0 or location != 2816:
            return 0
        return 2
    if code != 1 or seq != sequence + 1 or catching != 1 or location != 0:
        return 0
    if third != 0 or fourth != 0:
        return 0
    if op == 1 or op == 35:
        if first != 0 or second != 0 or consumes != 0:
            return 0
    else:
        if op == 2:
            if first != 1 or second != 2 or consumes != 0:
                return 0
        else:
            if op != 22 or first != 2 or second != 0 or consumes != 1:
                return 0
    return 1

def drive(a:mutbuf, b:mutbuf, w:mutbuf, needed:u64, action:u64) -> u32:
    packet(a, 0, 0, 1)
    sequence = 0
    live = 0
    size = 0
    done = 0
    while done == 0:
        code = cli_control(a, 0, 96, b, 0, 128, w, 0, needed)
        status = command(b, sequence, code)
        if status == 0:
            return 126
        if status == 2:
            if live != 0:
                return 126
            return 0
        op = uint(b, 8, 8)
        sequence = uint(b, 16, 8)
        fill_range(a, 0, 96, 0)
        write(a, 0, CLAIM_MAGIC, 8)
        write(a, 8, 4, 8)
        write(a, 16, sequence, 8)
        write(a, 24, op, 8)
        write(a, 32, 1, 8)
        code = cli_control(a, 0, 96, b, 0, 128, w, 0, needed)
        if code != 3:
            return 126
        i = 0
        while i < 128:
            if byte(b, i) != byte(w, 2304 + i):
                return 126
            i = i + 1
        actual_op = uint(b, 8, 8)
        actual_sequence = uint(b, 16, 8)
        if actual_op != op or actual_sequence != sequence:
            return 126
        value = 0
        if op == 1 or op == 2:
            if live != 0 or op != action:
                return 126
            size = discovery(a, b, w, needed, action)
            if size > 65536:
                return 126
            live = 1
            value = 2
        else:
            if op == 22:
                if live != 1:
                    return 126
                # The pending result is spent before any physical write. A
                # failed write cannot re-enter or ask for the same permission.
                live = 0
                failed = send(a, 128, size, 1)
                if failed != 0:
                    return 120
            else:
                if op != 35 or action != 2:
                    return 126
        packet(a, sequence, op, value)
    return 126

def discovery(a:mutbuf, b:mutbuf, w:mutbuf, needed:u64, action:u64) -> u64:
    if needed > 1048544:
        return 18446744073709551615
    # Preserve the real claimed continuation across the separate JSON program.
    # No foreign callback can see a fabricated dict or alter its namespace.
    copy_exact(a, w, 0, 0, needed)
    kind = uint(w, 320, 8)
    begin = uint(w, 328, 8)
    count = uint(w, 336, 8)
    present = 0
    size = 0
    if action == 2:
        if kind == 2:
            base = uint(w, 152, 8) + begin
            if count > 1048544 - needed:
                return 18446744073709551615
            while size < count:
                cp = uint(w, base + size * 4, 4)
                if cp > 127:
                    return 18446744073709551615
                store(a, needed + 32 + size, cp)
                size = size + 1
            present = 1
        else:
            if kind == 3:
                if count > 1048544 - needed:
                    return 18446744073709551615
                copy_exact(a, w, needed + 32, begin, count)
                size = count
                present = 1
            else:
                if kind != 1:
                    return 18446744073709551615
    write(a, needed, JSON_MAGIC, 8)
    write(a, needed + 8, action, 8)
    write(a, needed + 16, present, 8)
    write(a, needed + 24, size, 8)
    fill_range(w, 0, 131072, 0)
    result = cli_discovery(a, needed, 32 + size, b, 0, 65536, w, 0, 131072)
    copy_exact(w, a, 0, 0, needed)
    if result > 65536:
        return 18446744073709551615
    copy_exact(a, b, 128, 0, raw_word(result))
    return raw_word(result)

def send(a:mutbuf, start:u64, size:u64, fd:u64) -> u64:
    at = 0
    while at < size:
        result = signed_zero()
        if fd == 1:
            result = write_io(a, start + at, size - at)
        else:
            result = stderr_io(a, start + at, size - at)
        if result != eintr():
            if result <= signed_zero():
                return 1
            at = at + raw_word(result)
    return 0
'''


def author_source():
    text = SOURCE
    for name, value in {
        'ARGV_MAGIC': b'HCLIARG4', 'RESULT_MAGIC': b'HCLIRES4',
        'STEP_MAGIC': b'HCLISTP4', 'CLAIM_MAGIC': b'HCLICLM5',
        'COMMAND_MAGIC': b'HCLICMD4', 'JSON_MAGIC': b'HCLJSON1',
        'OBSERVE_MAGIC': b'HCLIOBS4',
    }.items():
        text = text.replace(name, str(int.from_bytes(value, 'little')))
    version_bytes = b'hia 0.3.0'
    version = ('def version(b:mutbuf) -> u64:\n'
               f'    write(b, 0, {int.from_bytes(version_bytes[:8], "little")}, 8)\n'
               f'    store(b, 8, {version_bytes[8]})\n'
               '    return 0\n')
    keys = (b'PYTHON_COLORS=', b'NO_COLOR=', b'FORCE_COLOR=', b'TERM=', b'COLUMNS=')
    lengths = bytes(len(key) for key in keys)
    assert tuple(lengths) == (14, 9, 12, 5, 8)
    text = text.replace('PREFIX_LENGTHS', str(int.from_bytes(lengths, 'little')))
    # This helper is dominated by run's exact 1MiB scratch admission. Reading
    # its first fourteen private bytes is total; n still guards every logical
    # prefix match, so stale bytes outside a short source cannot select a key.
    match = ('def environment_kind(b:mutbuf, n:u64) -> u64:\n'
             '    first = uint(b, 0, 8)\n'
             '    second = uint(b, 8, 6)\n')
    for kind, key in enumerate(keys, 1):
        conditions = [f'n >= {len(key)}']
        for at in range(0, len(key), 8):
            part = key[at:at + 8]
            word = 'first' if at == 0 else 'second'
            mask = (1 << (8 * len(part))) - 1
            conditions.append(f'({word} & {mask}) == {int.from_bytes(part, "little")}')
        match += '    if ' + ' and '.join(conditions) + f':\n        return {kind}\n'
    match += '    return 0\n'
    helpers = []
    for node in ast.parse(LINK_SOURCE).body:
        if isinstance(node, ast.FunctionDef) and node.name in ('uint', 'write'):
            if node.name == 'uint':
                node.args.args[0].annotation.id = 'mutbuf'
            helpers.append(ast.unparse(node))
    return text + '\n' + version + '\n' + match + '\n' + '\n\n'.join(helpers) + '\n'


class CliProcessBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name == 'copy_exact':
                args = [self.expr(v) for v in node.args]
                borrowed = self.op('borrow.read', [args[1]], 'readbuf')
                self.op('buffer.copy_range', [args[0], borrowed] + [self.cast(v, 'usize') for v in args[2:]])
                return self.op('loan.end', [borrowed])
            if name in ('cli_control', 'cli_format', 'cli_discovery'):
                args = [self.expr(v) for v in node.args]
                assert len(args) == 9 and not node.keywords
                operation = {'cli_control': 'linux.cli.control', 'cli_format': 'linux.cli.format',
                             'cli_discovery': 'linux.cli.discovery'}[name]
                return self.cast(self.op(operation, [v if i % 3 == 0 else self.cast(v, 'usize')
                    for i, v in enumerate(args)], 'u32'), 'u64')
            if name in ('write_io', 'stderr_io'):
                args = [self.expr(v) for v in node.args]
                return self.op('linux.stdout.write' if name == 'write_io' else 'linux.stderr.write',
                    args[:1] + [self.cast(v, 'usize') for v in args[1:]], 'i64')
            if name in ('argc', 'envc'):
                return self.cast(self.op('linux.argv.count' if name == 'argc' else 'linux.env.count', [], 'usize'), 'u64')
            if name in ('arglen', 'envlen'):
                return self.cast(self.op('linux.argv.length' if name == 'arglen' else 'linux.env.length',
                    [self.cast(self.expr(node.args[0]), 'usize')], 'usize'), 'u64')
            if name in ('argcopy', 'envcopy'):
                args = [self.expr(v) for v in node.args]
                return self.cast(self.op('linux.argv.copy' if name == 'argcopy' else 'linux.env.copy',
                    args[:1] + [self.cast(v, 'usize') for v in args[1:]], 'usize'), 'u64')
            if name == 'raw_word':
                return self.cast(self.expr(node.args[0]), 'u64')
            if name in ('signed_zero', 'eintr'):
                return self.c(0 if name == 'signed_zero' else -4, 'i64')
        return super().expr(node)


def compact_cli_document(document):
    """Use the existing total CFG pass with this profile's actual verifier.

    Only the verifier import is rebound. Every other AST field in the original
    pass is retained. The pass removes no operation, speculates no effect, and
    admits both input and result with the explicit new profile.
    """
    tree = ast.parse(inspect.getsource(compact_authoring_cfg))
    changed = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == 'hepta.hia_program':
            assert [(x.name, x.asname) for x in node.names] == [('verify_program', None)]
            node.module = 'hepta.hia_linux_cli_process'
            node.names = [ast.alias(name='verify_linux_cli_process_program', asname='verify_program')]
            changed += 1
    assert changed == 1
    ast.fix_missing_locations(tree)
    namespace = {'TYPES': __import__('tools.generate_hia_selfhost', fromlist=['TYPES']).TYPES}
    exec(compile(tree, '<reviewed-explicit-profile-author-CFG>', 'exec'), namespace)
    result = namespace['compact_authoring_cfg'](document)
    for before, after in zip(document['functions'], result['functions'], strict=True):
        before_ops = [op for block in before['blocks'] for op in block['ops']]
        after_ops = [op for block in after['blocks'] for op in block['ops']]
        assert before_ops == after_ops
    return result


def document():
    nodes = ast.parse(author_source()).body
    names = {n.name: 'f' + str(i) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = CliProcessBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap', 'linux_io', 'linux_startup', 'linux_cli'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_cli_document({'schema': 'hepta.hia.program.v8', 'module': MODULE, 'functions': functions})


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Generate explicit native CLI process HIA')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    doc = document()
    raw = render_assembly(doc, profile=PROFILE).encode()
    target = ROOT / 'examples/hia_bootstrap/native_cli_process.hepta'
    if args.check:
        if target.read_bytes() != raw:
            raise SystemExit('native CLI process HIA differs')
    else:
        target.write_bytes(raw)
    print(json.dumps({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
        'functions': len(doc['functions']), 'blocks': sum(len(f['blocks']) for f in doc['functions']),
        'ops': sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),
        'matching_cold': False, 'whole': False, 'native_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
