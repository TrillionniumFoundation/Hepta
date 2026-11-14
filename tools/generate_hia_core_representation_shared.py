"""Share JSON scanner execution with explicit source/scratch layout parameters.

All three original policies remain fixed. The scanner receives two genuinely
distinct mutable buffer parameters. A scalar selector directs key accesses to
one buffer or a private range of the state buffer; no aliased mutable arguments
or host pointers are created. Attributes retain the original 2048/16 limits.
"""
from __future__ import annotations
import ast
import copy
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_core_representation as fixed
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/core_representation_shared.hepta'
EXTRA = {
    'preflight': ['begin', 'extent', 'state_base', 'state_size', 'key_base', 'key_size', 'key_owner', 'mode'],
    'whitespace': ['begin', 'extent'],
    'atom': ['begin', 'extent'],
    'string_token': ['begin', 'extent', 'state_base', 'mode'],
    'insert_key': ['begin', 'extent', 'state_base', 'key_base', 'key_owner'],
    'same_key': ['begin', 'extent'],
    'hex4': ['begin', 'extent'],
    'decoded': ['begin', 'extent'],
}
REASONS = {12: 3, 9: 4, 10: 5, 13: 19, 15: 19, 14: 6,
           16: 7, 17: 8, 19: 19, 18: 9}


def expr(text):
    return ast.parse(text, mode='eval').body


def statements(text):
    return ast.parse(text).body


def unified_preflight():
    originals = {node.name: node for node in ast.parse(PREFLIGHT).body}
    node = copy.deepcopy(originals['preflight'])
    changes = {'abi_returns': 0, 'error_pairs': {}, 'string_returns': 0, 'duplicate_return': 0,
               'node_count_return': 0, 'initial_reason': 0}

    def alter(items):
        result = []
        i = 0
        while i < len(items):
            current = copy.deepcopy(items[i])
            # Exact normal reason write + refusal pairs become a choice of the
            # unchanged normal state effect or the original diagnostic code.
            if (i + 1 < len(items) and isinstance(current, ast.Expr)
                    and isinstance(current.value, ast.Call)
                    and isinstance(current.value.func, ast.Name)
                    and current.value.func.id == 'put'
                    and ast.unparse(current.value.args[0]) == 'w'
                    and isinstance(current.value.args[1], ast.Constant)
                    and current.value.args[1].value == 32
                    and isinstance(current.value.args[2], ast.Constant)
                    and current.value.args[2].value in REASONS
                    and isinstance(items[i + 1], ast.Return)
                    and isinstance(items[i + 1].value, ast.Constant)
                    and items[i + 1].value.value == 1):
                reason = current.value.args[2].value
                changes['error_pairs'][reason] = changes['error_pairs'].get(reason, 0) + 1
                result += statements(f'if mode == 2:\n    return {REASONS[reason]}\n')
                result += [current, copy.deepcopy(items[i + 1])]
                i += 2
                continue
            if isinstance(current, ast.If):
                test = ast.unparse(current.test)
                if test == 'index == length(s)' and len(current.body) == 1 and ast.unparse(current.body[0]) == 'return 0':
                    current.body = statements('if mode != 0:\n    put(w, 64, nodes)\nreturn 0')
                    changes['node_count_return'] += 1
                elif test == 'result != 0' and len(current.body) == 1 and ast.unparse(current.body[0]) == 'return 1':
                    current.body = statements('return result')
                    changes['string_returns'] += 1
                elif test == 'result != 0' and len(current.body) == 1 and ast.unparse(current.body[0]) == 'return result':
                    current.body = statements('if mode == 2:\n    return choose(result == 4, 10, 19)\nreturn result')
                    changes['duplicate_return'] += 1
                else:
                    current.body = alter(current.body)
                current.orelse = alter(current.orelse)
            elif isinstance(current, ast.While):
                current.body = alter(current.body)
                current.orelse = alter(current.orelse)
            elif isinstance(current, ast.Return) and isinstance(current.value, ast.Constant) and current.value.value == 3:
                current.value = expr('choose(mode == 2, 19, 3)')
                changes['abi_returns'] += 1
            elif isinstance(current, ast.Expr) and ast.unparse(current) == 'put(w, 32, 0)':
                current = ast.If(test=expr('mode != 2'), body=[current], orelse=[])
                changes['initial_reason'] += 1
            result.append(current)
            i += 1
        return result
    node.body = alter(node.body)
    assert changes['abi_returns'] == 4, changes
    assert changes['initial_reason'] == changes['node_count_return'] == changes['duplicate_return'] == 1
    assert changes['string_returns'] == 2
    assert changes['error_pairs'] == {12: 1, 9: 1, 10: 1, 13: 2, 15: 1, 14: 1, 16: 1, 17: 1, 19: 1, 18: 1}
    originals['preflight'] = node
    string = copy.deepcopy(originals['string_token'])
    bad = [child for child in ast.walk(string) if isinstance(child, ast.If)
           and ast.unparse(child.test) == 'cp == 1114113']
    assert len(bad) == 1
    assert [ast.unparse(x) for x in bad[0].body] == ['put(w, 32, unit >> 32)', 'return 1']
    bad[0].body = statements('if mode == 2:\n    return shared_string_reason(unit >> 32)') + bad[0].body
    originals['string_token'] = string

    class Layout(ast.NodeTransformer):
        def visit_Call(self, value):
            original = copy.deepcopy(value)
            name = value.func.id if isinstance(value.func, ast.Name) else None
            value = self.generic_visit(value)
            if name in EXTRA:
                value.func.id = 'shared_' + name
                value.args += [ast.Name(arg, ast.Load()) for arg in EXTRA[name]]
            elif name in ('get', 'put'):
                owner = original.args[0].id
                if owner == 'w':
                    value.func.id = 'render_' + name
                    value.args[1] = ast.BinOp(ast.Name('state_base', ast.Load()), ast.Add(), value.args[1])
                elif owner == 'o':
                    value.func.id = 'shared_key_' + name
                    value.args = [ast.Name('o', ast.Load()), ast.Name('w', ast.Load()),
                                  ast.Name('key_base', ast.Load()), *value.args[1:],
                                  ast.Name('key_owner', ast.Load())]
                else:
                    raise AssertionError(ast.unparse(original))
            elif name == 'length':
                owner = original.args[0].id
                if owner in ('s', 'w', 'o'):
                    return ast.copy_location(ast.Name({'s': 'extent', 'w': 'state_size', 'o': 'key_size'}[owner], ast.Load()), value)
            elif name == 'byte' and original.args[0].id == 's':
                value.args[1] = ast.BinOp(ast.Name('begin', ast.Load()), ast.Add(), value.args[1])
            return value

    nodes = []
    for name, extras in EXTRA.items():
        node = Layout().visit(copy.deepcopy(originals[name]))
        node.name = 'shared_' + name
        node.args.args += [ast.arg(arg, ast.Name('u64', ast.Load())) for arg in extras]
        nodes.append(node)
    helpers = ast.parse('''
def shared_key_get(o:mutbuf, w:mutbuf, base:u64, index:u64, owner:u64) -> u64:
    if owner == 0:
        return render_get(o, base + index)
    return render_get(w, base + index)

def shared_key_put(o:mutbuf, w:mutbuf, base:u64, index:u64, value:u64, owner:u64) -> u64:
    if owner == 0:
        return render_put(o, base + index, value)
    return render_put(w, base + index, value)

def shared_string_reason(reason:u64) -> u64:
    if reason >= 2 and reason <= 8:
        return reason + 10
    return 19
''').body
    return nodes + helpers, changes


def source_program():
    original, original_report = fixed.source_program()
    prior = {node.name: node for node in original.body}
    shared, changes = unified_preflight()
    removed = {'render_preflight', 'render_whitespace', 'render_atom', 'render_string_token',
               'render_insert_key', 'render_same_key', 'render_hex4', 'render_decoded',
               'canonical_cj_preflight', 'canonical_cj_string', 'canonical_cj_four_characters'}
    removed |= {name for name in prior if name.startswith('reparse_aj_')}
    assert removed <= set(prior), removed - set(prior)
    call_changes = {}

    class Ports(ast.NodeTransformer):
        def visit_Call(self, value):
            value = self.generic_visit(value)
            name = value.func.id if isinstance(value.func, ast.Name) else None
            if name in {'render_preflight', 'canonical_cj_preflight'}:
                assert len(value.args) == 3
                s, o, w = copy.deepcopy(value.args)
                value.func.id = 'shared_preflight'
                value.args += [ast.Constant(0), ast.Call(ast.Name('length', ast.Load()), [s], []),
                               ast.Constant(0), ast.Call(ast.Name('length', ast.Load()), [w], []),
                               ast.Constant(0), ast.Call(ast.Name('length', ast.Load()), [o], []),
                               ast.Constant(0), ast.Constant(2 if name.startswith('canonical_') else 1)]
            elif name in {'render_whitespace', 'render_atom', 'render_hex4', 'render_decoded'}:
                assert len(value.args) == 2
                value.func.id = 'shared_' + name.removeprefix('render_')
                value.args += [ast.Constant(0), ast.Call(ast.Name('length', ast.Load()), [copy.deepcopy(value.args[0])], [])]
            elif name == 'reparse_aj_preflight':
                assert len(value.args) == 4 and ast.unparse(value.args[0]) == 's' and ast.unparse(value.args[1]) == 'w'
                value.func.id = 'shared_preflight'
                value.args = [value.args[0], ast.Name('o', ast.Load()), value.args[1], value.args[2], value.args[3],
                              ast.Constant(69888), ast.Constant(672), ast.Constant(70560), ast.Constant(32768),
                              ast.Constant(1), ast.Constant(0)]
            else:
                return value
            call_changes[name] = call_changes.get(name, 0) + 1
            return value

    result = [Ports().visit(copy.deepcopy(node)) for node in original.body if node.name not in removed]
    result += shared
    names = {node.name for node in result}
    for node in result:
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                assert call.func.id not in removed, (node.name, call.func.id)
    report = {'scope': 'shared explicit-layout scanner successor; frozen exact-AST-only revision retained',
              'before': original_report, 'preflight_projection': changes,
              'removed_duplicated_helpers': sorted(removed), 'explicit_call_projections': call_changes,
              'attrs_max_nodes': 2048, 'attrs_max_depth': 16,
              'attrs_state_region': [69888, 70560], 'attrs_key_region': [70560, 103328],
              'normal_and_diagnostic_first_error_mappings_retained': True,
              'mutable_alias_parameters_created': False,
              'source_slice_representation': 'relative indices with explicit begin/extent, never a raw pointer',
              'runtime_shape_tests_executed': False, 'aggregate_fits': False}
    return ast.fix_missing_locations(ast.Module(body=result, type_ignores=[])), report


def document():
    source, report = source_program()
    nodes = source.body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    assert len(names) == len(nodes)
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        assert len(node.args.args) <= 16
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    doc = compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'core_representation_shared', 'functions': functions})
    report.update(functions=len(doc['functions']), blocks=sum(len(fn['blocks']) for fn in doc['functions']),
                  operations=sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']),
                  source_function_names=names)
    assert report['functions'] <= 128 and report['blocks'] <= 1536 and report['operations'] <= 8192
    return doc, report


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc, report = document()
    raw = render_assembly(doc).encode()
    assert len(raw) <= 1048576
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    if args.check:
        assert target.read_bytes() == raw
    else:
        target.open('xb').write(raw)
    report['source_bytes'] = len(raw)
    args.report.open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('functions', 'blocks', 'operations', 'source_bytes')}))


if __name__ == '__main__':
    main()
