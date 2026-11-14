"""HIA test programs for the explicit process profile, with no host I/O policy."""
from __future__ import annotations

import ast

from tools.generate_hia_selfhost import Builder, total_scalar_functions
from hepta.hia_linux_process import PROFILE, MODULE
from hepta.hia_agent_assembly import render_assembly, assemble_program


class ProcessBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in ('read_io', 'write_io', 'stderr_io'):
                assert not node.keywords and len(node.args) == 3
                args = [self.expr(v) for v in node.args]
                operation = {'read_io': 'linux.stdin.read', 'write_io': 'linux.stdout.write',
                             'stderr_io': 'linux.stderr.write'}[name]
                return self.op(operation, [args[0], self.cast(args[1], 'usize'),
                                           self.cast(args[2], 'usize')], 'i64')
            if name in ('argc', 'envc'):
                assert not node.args and not node.keywords
                return self.cast(self.op('linux.argv.count' if name == 'argc' else 'linux.env.count',
                                        [], 'usize'), 'u64')
            if name in ('arglen', 'envlen'):
                assert not node.keywords and len(node.args) == 1
                return self.cast(self.op('linux.argv.length' if name == 'arglen' else 'linux.env.length',
                    [self.cast(self.expr(node.args[0]), 'usize')], 'usize'), 'u64')
            if name in ('argcopy', 'envcopy'):
                assert not node.keywords and len(node.args) == 5
                args = [self.expr(v) for v in node.args]
                return self.cast(self.op('linux.argv.copy' if name == 'argcopy' else 'linux.env.copy',
                    args[:1] + [self.cast(v, 'usize') for v in args[1:]], 'usize'), 'u64')
            if name in ('raw_word', 'exit_word'):
                assert not node.keywords and len(node.args) == 1
                return self.cast(self.expr(node.args[0]), 'u64' if name == 'raw_word' else 'u32')
            if name in ('signed_zero', 'ebadf', 'epipe'):
                assert not node.args and not node.keywords
                return self.c({'signed_zero': 0, 'ebadf': -9, 'epipe': -32}[name], 'i64')
        return super().expr(node)


WRITE_WORD = '''
def word(o:mutbuf, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, i, value >> (i * 8))
        i = i + 1
    return 8

def send(o:mutbuf, count:u64) -> u32:
    at = 0
    while at < count:
        result = write_io(o, at, count - at)
        if result < signed_zero():
            return exit_word(result)
        if result == signed_zero():
            return 4
        at = at + raw_word(result)
    return 0
'''

COUNTS = '''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    word(o, argc())
    status = raw_word(send(o, 8))
    if status != 0:
        return status
    word(o, envc())
    return send(o, 8)
''' + WRITE_WORD

INSPECT = '''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    word(o, 3546416430321002824)
    status = raw_word(send(o, 8))
    if status != 0:
        return status
    count = argc()
    word(o, count)
    status = raw_word(send(o, 8))
    if status != 0:
        return status
    count_env = envc()
    word(o, count_env)
    status = raw_word(send(o, 8))
    if status != 0:
        return status
    i = 0
    while i < count:
        n = arglen(i)
        word(o, n)
        status = raw_word(send(o, 8))
        if status != 0:
            return status
        at = 0
        while at < n:
            size = n - at
            if size > 65536:
                size = 65536
            copied = argcopy(o, 0, i, at, size)
            if copied != size:
                return 5
            status = raw_word(send(o, size))
            if status != 0:
                return status
            at = at + size
        i = i + 1
    i = 0
    while i < count_env:
        n = envlen(i)
        word(o, n)
        status = raw_word(send(o, 8))
        if status != 0:
            return status
        at = 0
        while at < n:
            size = n - at
            if size > 65536:
                size = 65536
            copied = envcopy(o, 0, i, at, size)
            if copied != size:
                return 5
            status = raw_word(send(o, size))
            if status != 0:
                return status
            at = at + size
        i = i + 1
    store(w, 0, 255)
    store(w, 1, 0)
    store(w, 2, 10)
    result = stderr_io(w, 0, 3)
    if result < signed_zero():
        return exit_word(result)
    if raw_word(result) != 3:
        return 6
    return 0
''' + WRITE_WORD

STDERR = '''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    store(o, 0, 255)
    store(o, 1, 0)
    store(o, 2, 10)
    result = stderr_io(o, 0, 3)
    if result == ebadf():
        return 93
    if result == epipe():
        return 94
    if result < signed_zero():
        return 97
    if raw_word(result) != 3:
        return 95
    return 0
'''

STDERR_SHORT = '''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    fill_range(o, 0, 1048576, 90)
    result = stderr_io(o, 0, 1048576)
    if result == ebadf():
        return 93
    if result == epipe():
        return 94
    if result < signed_zero():
        return 97
    if raw_word(result) != 1048576:
        return 95
    return 0
'''

STDERR_ZERO = '''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    result = stderr_io(o, 1048576, 0)
    if result == ebadf():
        return 93
    return exit_word(result)
'''

BOUNDARY_TEMPLATE = '''
def run(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    n = OP
    return 0
'''

PROGRAMS = {
    'counts': COUNTS, 'inspect': INSPECT, 'stderr': STDERR,
    'stderr-short': STDERR_SHORT, 'stderr-zero': STDERR_ZERO,
    'invalid-argv-index': BOUNDARY_TEMPLATE.replace('OP', 'arglen(argc())'),
    'invalid-env-index': BOUNDARY_TEMPLATE.replace('OP', 'envlen(envc())'),
    'copy-zero-end': BOUNDARY_TEMPLATE.replace('OP', 'argcopy(o, 1048576, 0, arglen(0), 0)'),
    'copy-invalid-source': BOUNDARY_TEMPLATE.replace('OP', 'argcopy(o, 0, 0, arglen(0) + 1, 0)'),
    'copy-invalid-destination': BOUNDARY_TEMPLATE.replace('OP', 'argcopy(o, 1048577, 0, 0, 0)'),
    'copy-source-overflow': BOUNDARY_TEMPLATE.replace('OP', 'argcopy(o, 0, 0, 18446744073709551615, 1)'),
    'copy-destination-overflow': BOUNDARY_TEMPLATE.replace('OP', 'argcopy(o, 18446744073709551615, 0, 0, 1)'),
}


def document(source):
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    functions = []
    for node in nodes:
        builder = ProcessBuilder(node, names, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap', 'linux_io', 'linux_startup'],
            'entry': 'b0', 'blocks': builder.blocks})
    return {'schema': 'hepta.hia.program.v8', 'module': MODULE, 'functions': functions}


def program(name):
    rendered = render_assembly(document(PROGRAMS[name]), profile=PROFILE)
    return assemble_program(rendered, profile=PROFILE), rendered.encode()
