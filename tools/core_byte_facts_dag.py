"""Independent, bounded reader for original structured List Nat declarations.

This is a source-only proposal reader, not a Lean checker or acceptance oracle.
The caller must separately authenticate the complete original preparation. No
source emitter or existing expression parser is imported here.
"""
from hashlib import sha256
import json
import re
from types import MappingProxyType

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 32
MAX_TOKENS = 4096
MAX_VERTICES = 4096
MAX_EDGES = 8192
MAX_BYTES = 32768
_IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_]*')
_NAMESPACE = re.compile(r'HiaCoreSyntaxSlice(?:\.[A-Za-z][A-Za-z0-9_]*)*')
_DEFINITION = re.compile(r'def ([A-Za-z][A-Za-z0-9_]*) : (Raw|List Nat|List Raw|List \(List Nat × Raw\)) := (.+)')
_THEOREM = re.compile(r'theorem ([A-Za-z][A-Za-z0-9_]*) .+ := .+')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


class _Parser:
    def __init__(self, rhs):
        self.rhs, self.pos, self.tokens = rhs, 0, 0

    def take(self, text):
        if not self.rhs.startswith(text, self.pos):
            return False
        self.pos += len(text)
        self.tokens += 1
        _require(self.tokens <= MAX_TOKENS, 'RHS syntax token limit')
        return True

    def natural(self):
        start = self.pos
        while self.pos < len(self.rhs) and '0' <= self.rhs[self.pos] <= '9':
            self.pos += 1
        word = self.rhs[start:self.pos]
        _require(0 < len(word) <= 3 and (word == '0' or word[0] != '0'),
                 'noncanonical or oversized byte numeral')
        self.tokens += 1
        _require(self.tokens <= MAX_TOKENS, 'RHS syntax token limit')
        value = int(word)
        _require(value <= 255, 'byte literal out of range')
        return value

    def atom(self, depth):
        if self.take('('):
            node = self.expression(depth + 1)
            _require(self.take(')'), 'missing closing parenthesis')
            return node
        if self.take('['):
            values = []
            if not self.take(']'):
                values.append(self.natural())
                while self.take(','):
                    values.append(self.natural())
                _require(self.take(']'), 'noncanonical list literal')
            return ('literal', tuple(values))
        match = _IDENT.match(self.rhs, self.pos)
        _require(match is not None, 'expected local identifier, literal or parenthesis')
        name = match[0]
        _require(self.take(name), 'identifier token')
        return ('ref', name)

    def expression(self, depth=0):
        _require(depth <= MAX_DEPTH, 'RHS parenthesis depth limit')
        if self.pos < len(self.rhs) and '0' <= self.rhs[self.pos] <= '9':
            byte = self.natural()
            _require(self.take(' :: '), 'bare Nat is not a List Nat expression')
            return ('cons', byte, self.atom(depth))
        left = self.atom(depth)
        if self.take(' ++ '):
            return ('append', left, self.atom(depth))
        return left


def parse_rhs(rhs):
    """Read exactly the frozen expression grammar, including emitted spacing."""
    _require(type(rhs) is str and len(rhs.encode('utf-8')) <= MAX_SOURCE_BYTES,
             'RHS input type or source limit')
    parser = _Parser(rhs)
    ast = parser.expression()
    _require(parser.pos == len(rhs), 'trailing, mixed or repeated expression syntax')
    return ast


def _dependencies(ast):
    result, pending = [], [ast]
    while pending:
        node = pending.pop()
        if node[0] == 'ref':
            result.append(node[1])
        elif node[0] == 'cons':
            pending.append(node[2])
        elif node[0] == 'append':
            pending.extend((node[2], node[1]))
    return tuple(result)


def _evaluate(ast, env):
    kind = ast[0]
    if kind == 'literal':
        result = ast[1]
    elif kind == 'ref':
        _require(ast[1] in env, 'unknown, non-byte, cyclic or forward reference: ' + ast[1])
        result = env[ast[1]]['value']
    elif kind == 'cons':
        child = _evaluate(ast[2], env)
        _require(len(child) < MAX_BYTES, 'expanded byte length limit')
        result = (ast[1],) + child
    else:
        left, right = _evaluate(ast[1], env), _evaluate(ast[2], env)
        _require(len(left) + len(right) <= MAX_BYTES, 'expanded byte length limit')
        result = left + right
    _require(len(result) <= MAX_BYTES, 'expanded byte length limit')
    return result


def analyze(source, namespace, stem, expected_bytes):
    """Return an immutable topological plan rooted at the actual stemBytes alias.

    ASTs and reconstructed values are tuples. Row offsets bind complete original
    declaration lines in UTF-8 bytes, including their final newline. All byte
    declarations (including unreachable ones) are parsed and checked; only the
    root-reachable ones are returned. No t0 convention or fixed count is assumed.
    """
    _require(type(source) is str and len(source.encode('utf-8')) <= MAX_SOURCE_BYTES,
             'original source type or byte limit')
    _require(type(namespace) is str and _NAMESPACE.fullmatch(namespace) is not None,
             'exact supported namespace')
    _require(type(stem) is str and _IDENT.fullmatch(stem) is not None, 'local stem required')
    _require(type(expected_bytes) is bytes and len(expected_bytes) <= MAX_BYTES,
             'complete expected byte stream type or size')
    opening, closing = 'namespace ' + namespace + '\n', 'end ' + namespace + '\n'
    _require(source.startswith(opening) and source.endswith(closing), 'exact namespace wrapper')
    # Comments, quoted identifiers and strings can disguise declaration boundaries.
    # None occur in the original emitted source language.
    _require(not any(x in source for x in ('/-', '-/', '--', '"', '«', '»', '\r', '\t')),
             'unsupported source lexical wrapper')
    body = source[len(opening):-len(closing)]
    env, names, edge_count = {}, set(), 0
    offset, theorem_continuation = len(opening.encode()), False
    for line in body.splitlines(keepends=True):
        _require(line.endswith('\n'), 'unterminated declaration line')
        text = line[:-1]
        end = offset + len(line.encode())
        definition = _DEFINITION.fullmatch(text)
        theorem = _THEOREM.fullmatch(text)
        if definition or theorem:
            name = (definition or theorem)[1]
            _require(name not in names, 'duplicate declaration: ' + name)
            names.add(name)
            theorem_continuation = theorem is not None and text.endswith(' := by')
            if definition and definition[2] == 'List Nat':
                _require(len(env) < MAX_VERTICES, 'byte DAG vertex limit')
                rhs = definition[3]
                ast = parse_rhs(rhs)
                deps = _dependencies(ast)
                edge_count += len(deps)
                _require(edge_count <= MAX_EDGES, 'byte DAG reference edge limit')
                value = _evaluate(ast, env)
                env[name] = MappingProxyType(dict(name=name, rhs=rhs, ast=ast, value=value,
                    length=len(value), dependencies=deps, source_start=offset, source_end=end))
        elif theorem_continuation and text.startswith('  simpa only [') and text.endswith(')'):
            # The only multiline proof shape in the original source. It has no
            # scope effect; acceptance of its proof remains the old oracle's job.
            _require(re.fullmatch(r'  simpa only \[[A-Za-z0-9_., ]*\] using \(.+\)', text) is not None,
                     'unsupported theorem continuation')
            theorem_continuation = False
        else:
            raise ValueError('unsupported declaration or namespace/scoping command')
        offset = end
    root = stem + 'Bytes'
    _require(root in env, 'missing actual Bytes root')
    _require(bytes(env[root]['value']) == expected_bytes, 'complete original root bytes differ')
    reachable, pending = set(), [root]
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(env[name]['dependencies'])
    rows = tuple(row for name, row in env.items() if name in reachable)
    # Digest is evidence of the independently reconstructed graph, never a
    # replacement for reconstruction or the original independent byte oracle.
    graph = [(r['name'], r['rhs'], r['ast'], r['length'], r['dependencies'],
              r['source_start'], r['source_end']) for r in rows]
    encoded = json.dumps(graph, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return MappingProxyType(dict(namespace=namespace, root=root, rows=rows,
        source_sha256=sha256(source.encode()).hexdigest(), graph_digest=sha256(encoded).hexdigest()))
