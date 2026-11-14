"""Fixed private scanner context, keeping original B3 block/argument limits.

The context is an internal scalar packed into state-buffer word 8 for exactly
one preflight call. That word is unused by all three original scanner state
layouts. The wrapper saves and restores its bytes on every ordinary return.
Source-only helpers receive a packed span and keep indices relative to it.
No mutable alias, raw pointer, callback or widened budget is introduced.
"""
from __future__ import annotations
import ast
import copy
import hashlib
import inspect
import json
from pathlib import Path
import types

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_core_representation as fixed
from tools import generate_hia_core_representation_shared as previous

SOURCE_PATH = 'examples/hia_bootstrap/core_representation_context.hepta'
PURE = {'whitespace', 'atom', 'same_key', 'hex4', 'decoded'}
STATE = {'preflight', 'string_token', 'insert_key'}
MASK = (1 << 24) - 1


def merged_originals():
    # Reuse the previous revision's exact checked grammar/reason projection,
    # stopping before its unsuccessful scalar-parameter layout transformation.
    source = inspect.getsource(previous.unified_preflight)
    marker = '    class Layout(ast.NodeTransformer):\n'
    assert source.count(marker) == 1
    prefix = source.split(marker)[0] + '    return originals, changes\n'
    namespace = dict(vars(previous))
    exec(compile(prefix, '<fixed-shared-preflight-grammar-projection>', 'exec'), namespace)
    nodes, changes = namespace['unified_preflight']()
    return nodes, changes, hashlib.sha256(source.encode()).hexdigest()


def shared_nodes():
    originals, changes, projection_sha = merged_originals()
    names = PURE | STATE
    all_calls = {'state_reads': 0, 'state_writes': 0, 'key_reads': 0, 'key_writes': 0}
    result = []
    for name in previous.EXTRA:
        current = name
        pure = current in PURE

        def span():
            return ast.Name('span', ast.Load()) if pure else previous.expr('render_get(w, 8)')

        def extent():
            return ast.BinOp(ast.BinOp(span(), ast.RShift(), ast.Constant(24)), ast.BitAnd(), ast.Constant(MASK))

        class Layout(ast.NodeTransformer):
            def visit_Name(self, value):
                if isinstance(value.ctx, ast.Load) and value.id == 'mode':
                    return previous.expr('(render_get(w, 8) >> 48) & 3')
                if pure and isinstance(value.ctx, ast.Load) and value.id == 'size' and current in {'atom', 'decoded'}:
                    return extent()
                return value

            def visit_Assign(self, value):
                if (pure and current in {'atom', 'decoded'} and len(value.targets) == 1
                        and isinstance(value.targets[0], ast.Name) and value.targets[0].id == 'size'):
                    assert ast.unparse(value.value) == 'length(s)'
                    return None
                return self.generic_visit(value)

            def visit_Call(self, value):
                original = copy.deepcopy(value)
                target = value.func.id if isinstance(value.func, ast.Name) else None
                value = self.generic_visit(value)
                if target in names:
                    value.func.id = 'shared_' + target
                    if target in PURE:
                        value.args.append(span())
                elif target in ('get', 'put'):
                    owner = original.args[0].id
                    if owner == 'w':
                        value.func.id = 'shared_state_' + target
                        all_calls['state_reads' if target == 'get' else 'state_writes'] += 1
                    elif owner == 'o':
                        value.func.id = 'shared_key_' + target
                        value.args.insert(1, ast.Name('w', ast.Load()))
                        all_calls['key_reads' if target == 'get' else 'key_writes'] += 1
                    else:
                        raise AssertionError(ast.unparse(original))
                elif target == 'length':
                    owner = original.args[0].id
                    if owner == 's':
                        return extent()
                    if owner == 'w':
                        return previous.expr('choose(((render_get(w, 8) >> 48) & 3) == 0, 672, length(w))')
                    if owner == 'o':
                        return previous.expr('choose(((render_get(w, 8) >> 48) & 3) == 0, 32768, length(o))')
                elif target == 'byte' and original.args[0].id == 's':
                    value.args[1] = ast.BinOp(ast.BinOp(span(), ast.BitAnd(), ast.Constant(MASK)), ast.Add(), value.args[1])
                return value

        node = Layout().visit(copy.deepcopy(originals[name]))
        node.name = 'shared_' + name
        if pure:
            node.args.args.append(ast.arg('span', ast.Name('u64', ast.Load())))
        result.append(node)
    helpers = ast.parse('''
def shared_preflight_entry(s:readbuf, o:mutbuf, w:mutbuf, context:u64) -> u32:
    saved = render_get(w, 8)
    render_put(w, 8, context)
    status = shared_preflight(s, o, w)
    render_put(w, 8, saved)
    return status

def shared_state_get(w:mutbuf, index:u64) -> u64:
    base = choose(((render_get(w, 8) >> 48) & 3) == 0, 69888, 0)
    return render_get(w, base + index)

def shared_state_put(w:mutbuf, index:u64, value:u64) -> u64:
    base = choose(((render_get(w, 8) >> 48) & 3) == 0, 69888, 0)
    return render_put(w, base + index, value)

def shared_key_get(o:mutbuf, w:mutbuf, index:u64) -> u64:
    if ((render_get(w, 8) >> 48) & 3) == 0:
        return render_get(w, 70560 + index)
    return render_get(o, index)

def shared_key_put(o:mutbuf, w:mutbuf, index:u64, value:u64) -> u64:
    if ((render_get(w, 8) >> 48) & 3) == 0:
        return render_put(w, 70560 + index, value)
    return render_put(o, index, value)

def shared_string_reason(reason:u64) -> u64:
    if reason >= 2 and reason <= 8:
        return reason + 10
    return 19
''').body
    report = {'grammar_projection': changes, 'grammar_projection_function_sha256': projection_sha,
              'memory_call_projection': all_calls,
              'packed_context': {'begin': [0, 24], 'extent': [24, 48], 'layout': [48, 50]},
              'layouts': {'0': 'attributes state69888/key70560, 2048 nodes and16depth',
                          '1': 'normal decoder, separate original key/state buffers with node count',
                          '2': 'diagnostic, separate original key/state buffers and original detailed reasons'},
              'temporary_context_word': 8, 'ordinary_return_restores_original_word': True,
              'context_may_remain_on_trap_or_VM_fuel_exhaustion': True,
              'byte_span_bounds': 'all original callers already admit begin/extent; each fits24bits',
              'public_shared_entry': False}
    return result + helpers, report


def source_program():
    original, original_report = fixed.source_program()
    prior = {node.name: node for node in original.body}
    shared, shared_report = shared_nodes()
    removed = {'render_preflight', 'render_whitespace', 'render_atom', 'render_string_token',
               'render_insert_key', 'render_same_key', 'render_hex4', 'render_decoded',
               'canonical_cj_preflight', 'canonical_cj_string', 'canonical_cj_four_characters'}
    removed |= {name for name in prior if name.startswith('reparse_aj_')}
    assert removed <= set(prior)
    call_changes = {}

    class Ports(ast.NodeTransformer):
        def visit_Call(self, value):
            value = self.generic_visit(value)
            name = value.func.id if isinstance(value.func, ast.Name) else None
            if name in {'render_preflight', 'canonical_cj_preflight'}:
                assert len(value.args) == 3
                s = copy.deepcopy(value.args[0])
                context = ast.BinOp(ast.BinOp(ast.Call(ast.Name('length', ast.Load()), [s], []), ast.LShift(), ast.Constant(24)),
                                   ast.BitOr(), ast.Constant((2 if name.startswith('canonical_') else 1) << 48))
                value.func.id = 'shared_preflight_entry'
                value.args.append(context)
            elif name in {'render_whitespace', 'render_atom', 'render_hex4', 'render_decoded'}:
                assert len(value.args) == 2
                value.func.id = 'shared_' + name.removeprefix('render_')
                value.args.append(ast.BinOp(ast.Call(ast.Name('length', ast.Load()), [copy.deepcopy(value.args[0])], []), ast.LShift(), ast.Constant(24)))
            elif name == 'reparse_aj_preflight':
                assert len(value.args) == 4
                value.func.id = 'shared_preflight_entry'
                value.args = [value.args[0], ast.Name('o', ast.Load()), value.args[1],
                              ast.BinOp(value.args[2], ast.BitOr(), ast.BinOp(value.args[3], ast.LShift(), ast.Constant(24)))]
            else:
                return value
            call_changes[name] = call_changes.get(name, 0) + 1
            return value

    nodes = [Ports().visit(copy.deepcopy(node)) for node in original.body if node.name not in removed] + shared
    for node in nodes:
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                assert call.func.id not in removed
    report = {'scope': 'fixed packed source/scratch context; no original B3 scalar/block limit change',
              'before': original_report, 'shared_scanner': shared_report,
              'removed_duplicated_helpers': sorted(removed), 'explicit_call_projections': call_changes,
              'normal_and_diagnostic_first_error_mappings_retained': True,
              'mutable_alias_parameters_created': False,
              'runtime_shape_tests_executed': False, 'aggregate_fits': False}
    return ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), report


def document():
    namespace = dict(vars(previous), source_program=source_program)
    doc, report = types.FunctionType(previous.document.__code__, namespace)()
    doc['module'] = 'core_representation_context'
    return doc, report


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    doc, report = document()
    raw = render_assembly(doc).encode()
    assert len(raw) <= 1048576
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    if args.check:
        assert path.read_bytes() == raw
    else:
        path.open('xb').write(raw)
    report['source_bytes'] = len(raw)
    report['max_block_parameters'] = max(len(b['params']) for f in doc['functions'] for b in f['blocks'])
    args.report.open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('functions', 'blocks', 'operations', 'source_bytes', 'max_block_parameters')}))


if __name__ == '__main__':
    main()
