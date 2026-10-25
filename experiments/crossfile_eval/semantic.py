"""Equal study tools over a deliberately narrow declaration/body intersection.

Hepta uses its parser. Rust uses a bounded lexer and balanced delimiter index for
the documented top-level fixture subset, never presented as a Rust AST. Neither
index establishes typing, borrow correctness, or behavior; native validation is
mandatory before an update becomes the session's current snapshot.
"""
from __future__ import annotations

from dataclasses import dataclass

from hepta.parser import parse
from hepta.ast import HeptaError

from .tasks import canonical, digest, validate_files


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


def rust_tokens(source):
    if not isinstance(source, str) or len(source.encode()) > 128 * 1024:
        raise ValueError('E_RUST_INDEX: source exceeds bounded profile')
    result, i, n = [], 0, len(source)
    while i < n:
        if source[i].isspace():
            i += 1
            continue
        if source.startswith('//', i):
            end = source.find('\n', i + 2)
            i = n if end < 0 else end + 1
            continue
        if source.startswith('/*', i):
            depth, i = 1, i + 2
            while i < n and depth:
                if source.startswith('/*', i): depth, i = depth + 1, i + 2
                elif source.startswith('*/', i): depth, i = depth - 1, i + 2
                else: i += 1
                if depth > 64: raise ValueError('E_RUST_INDEX: excessive comment nesting')
            if depth: raise ValueError('E_RUST_INDEX: unterminated comment')
            continue
        start = i
        raw = i + 1 if source[i:i+1] in {'b', 'c'} and source[i+1:i+2] == 'r' else i
        if source[raw:raw+1] == 'r':
            end = raw + 1
            while source[end:end+1] == '#': end += 1
            if source[end:end+1] == '"':
                marker = '"' + '#' * (end - raw - 1)
                finish = source.find(marker, end + 1)
                if finish < 0: raise ValueError('E_RUST_INDEX: unterminated raw literal')
                i = finish + len(marker)
                result.append(Token(source[start:i], start, i))
                continue
        if source[i] == '"':
            i += 1
            while i < n and source[i] != '"': i += 2 if source[i] == '\\' else 1
            if i >= n: raise ValueError('E_RUST_INDEX: unterminated string')
            i += 1
        elif source[i] == "'":
            # A character has a closing quote; a lifetime remains two tokens.
            end = i + 1
            if source[end:end+1] == '\\':
                end += 2
                if source[i+2:i+3] == 'u' and source[end:end+1] == '{':
                    finish = source.find('}', end + 1)
                    if finish < 0: raise ValueError('E_RUST_INDEX: unterminated character escape')
                    end = finish + 1
            else: end += 1
            i = end + 1 if source[end:end+1] == "'" else i + 1
        elif source[i].isalpha() or source[i] == '_':
            i += 1
            while i < n and (source[i].isalnum() or source[i] == '_'): i += 1
        elif source[i].isdigit():
            i += 1
            while i < n and (source[i].isalnum() or source[i] in '_.'): i += 1
        else:
            i += 1
        result.append(Token(source[start:i], start, i))
        if len(result) > 50000: raise ValueError('E_RUST_INDEX: too many tokens')
    stack, pairs = [], {}
    closing = {')': '(', ']': '[', '}': '{'}
    for index, token in enumerate(result):
        if token.text in {'(', '[', '{'}:
            stack.append((token.text, index))
            if len(stack) > 64: raise ValueError('E_RUST_INDEX: excessive delimiter nesting')
        elif token.text in closing:
            if not stack or stack[-1][0] != closing[token.text]:
                raise ValueError('E_RUST_INDEX: mismatched delimiter')
            _, opening = stack.pop()
            pairs[opening] = index
    if stack: raise ValueError('E_RUST_INDEX: unterminated delimiter')
    return result, pairs


def _rust_spans(source):
    tokens, pairs = rust_tokens(source)
    spans, i = [], 0
    while i < len(tokens):
        start = tokens[i].start
        while i < len(tokens) and tokens[i].text == '#':
            if i + 1 >= len(tokens) or tokens[i + 1].text != '[':
                raise ValueError('E_RUST_INDEX: only outer attributes are in this profile')
            i = pairs[i + 1] + 1
        if i < len(tokens) and tokens[i].text == 'pub':
            i += 1
            if i < len(tokens) and tokens[i].text == '(':
                raise ValueError('E_RUST_INDEX: scoped visibility is outside this profile')
        if i >= len(tokens): raise ValueError('E_RUST_INDEX: incomplete declaration')
        kind = tokens[i].text
        if kind in {'use', 'mod'}:
            i += 1
            while i < len(tokens) and tokens[i].text != ';':
                if tokens[i].text in {'(', '[', '{'}:
                    if kind == 'mod': raise ValueError('E_RUST_INDEX: inline modules are outside this profile')
                    i = pairs[i] + 1
                else: i += 1
            if i == len(tokens): raise ValueError('E_RUST_INDEX: unterminated import')
            i += 1
            continue
        if kind == 'extern':
            if i + 2 >= len(tokens) or tokens[i + 1].text != '"C"' or tokens[i + 2].text != '{':
                raise ValueError('E_RUST_INDEX: only extern "C" blocks are in this profile')
            # Foreign declarations are read-only support in these tasks. Do not
            # pretend their contents are indexed Rust function definitions.
            i = pairs[i + 2] + 1
            continue
        if kind not in {'fn', 'struct', 'enum'}:
            raise ValueError('E_RUST_INDEX: unsupported top-level item: ' + kind)
        if i + 1 >= len(tokens) or not tokens[i + 1].text.isidentifier():
            raise ValueError('E_RUST_INDEX: declaration name is missing')
        symbol, cursor = tokens[i + 1].text, i + 2
        while cursor < len(tokens) and tokens[cursor].text not in {'{', ';'}:
            if tokens[cursor].text in {'const', 'where'}:
                raise ValueError('E_RUST_INDEX: const generics/where clauses are outside this profile')
            if tokens[cursor].text in {'(', '['}: cursor = pairs[cursor] + 1
            else: cursor += 1
        if cursor >= len(tokens): raise ValueError('E_RUST_INDEX: incomplete item')
        has_body = tokens[cursor].text == '{'
        end_index = pairs[cursor] if has_body else cursor
        end = tokens[end_index].end
        item_kind = 'function' if kind == 'fn' else kind
        spans.append(('declaration', item_kind, symbol, start, end))
        if kind == 'fn':
            spans.append(('function', item_kind, symbol, start, end))
            if has_body: spans.append(('body', item_kind, symbol, tokens[cursor].start, end))
        i = end_index + 1
        if i < len(tokens) and tokens[i].text == ';': i += 1
    return spans


def nodes(language, source, path):
    if language == 'rust':
        spans = _rust_spans(source)
    elif language == 'hepta':
        if len(source.encode()) > 128 * 1024:
            raise ValueError('E_HEPTA_INDEX: source exceeds bounded profile')
        try:
            program = parse(source, path)
        except (HeptaError, RecursionError) as exc:
            raise ValueError('E_HEPTA_INDEX: ' + str(exc)) from exc
        spans = []
        for kind, declarations in (('struct', program.structs), ('enum', program.enums), ('function', program.functions)):
            for declaration in declarations:
                spans.append(('declaration', kind, declaration.name, declaration.span.start, declaration.span.end))
                if kind == 'function':
                    spans.append(('function', kind, declaration.name, declaration.span.start, declaration.span.end))
                    if declaration.body is not None:
                        spans.append(('body', kind, declaration.name, declaration.body_span.start, declaration.body_span.end))
    else:
        raise ValueError('E_LANGUAGE: unsupported language')
    result, source_hash = [], digest(source.encode())
    for kind, declaration_kind, symbol, start, end in sorted(spans, key=lambda v: (v[3], v[4], v[0])):
        identity = {'language': language, 'path': path, 'source_sha256': source_hash,
                    'kind': kind, 'start': start, 'end': end}
        result.append({**identity, 'id': digest(canonical(identity)), 'symbol': symbol,
                       'declaration_kind': declaration_kind, 'text': source[start:end],
                       'text_sha256': digest(source[start:end].encode())})
    return result


def inspect(request, files):
    return {'ok': True, 'coverage': 'hepta_parser' if request['language'] == 'hepta' else 'bounded_rust_tokens_not_full_ast',
            'nodes': {path: nodes(request['language'], files[path], path) for path in request['editable']},
            'operations': ['replace_function', 'replace_body', 'replace_declaration']}


def replace_nodes(request, current, edits):
    kinds = {'replace_function': 'function', 'replace_body': 'body', 'replace_declaration': 'declaration'}
    if not isinstance(edits, list) or not 1 <= len(edits) <= 128:
        raise ValueError('E_PATCH_SCHEMA: require 1..128 semantic edits')
    grouped = {}
    for edit in edits:
        if (not isinstance(edit, dict) or set(edit) != {'op', 'target', 'node', 'replacement'}
                or any(not isinstance(v, str) for v in edit.values()) or edit['op'] not in kinds):
            raise ValueError('E_PATCH_SCHEMA: malformed semantic edit')
        path = edit['target']
        if path not in request['editable']: raise ValueError('E_PATCH_SCOPE: target is not editable')
        matches = [node for node in nodes(request['language'], current[path], path)
                   if node['id'] == edit['node'] and node['kind'] == kinds[edit['op']]]
        if len(matches) != 1: raise ValueError('E_PATCH_NODE: stale or incorrect node')
        grouped.setdefault(path, []).append((matches[0], edit['replacement']))
    result = dict(current)
    for path, changes in grouped.items():
        ordered = sorted(changes, key=lambda value: value[0]['start'])
        if any(a[0]['end'] > b[0]['start'] for a, b in zip(ordered, ordered[1:])):
            raise ValueError('E_PATCH_OVERLAP: edits overlap')
        source = current[path]
        for node, replacement in reversed(ordered):
            source = source[:node['start']] + replacement + source[node['end']:]
        actual, delta = nodes(request['language'], source, path), 0
        for node, replacement in ordered:
            start, end = node['start'] + delta, node['start'] + delta + len(replacement)
            matches = [value for value in actual if value['kind'] == node['kind']
                       and value['start'] == start and value['end'] == end
                       and (node['kind'] != 'declaration' or value['declaration_kind'] == node['declaration_kind'])]
            if len(matches) != 1:
                raise ValueError('E_PATCH_SCOPE: replacement is not exactly the selected node kind')
            delta += len(replacement) - (node['end'] - node['start'])
        result[path] = source
    return validate_files(request, result)
