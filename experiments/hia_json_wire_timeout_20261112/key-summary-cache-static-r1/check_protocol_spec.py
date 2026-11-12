"""Independent, fixed protocol facts and cache-proof checks; AST only.

This audit reads the retained baseline observer and normalization, as well as
the candidate. It does not import either generator or reuse the test helper.
"""
from pathlib import Path
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parent
checks = []


def require(value, message):
    if not value:
        raise AssertionError(message)
    checks.append(message)


def literal(module, name):
    values = [node.value for node in module.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    require(len(values) == 1, 'unique literal ' + name)
    return ast.literal_eval(values[0])


def body(source, name):
    nodes = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == name]
    require(len(nodes) == 1, 'unique HIA function ' + name)
    return ast.get_source_segment(source, nodes[0]), nodes[0]


def normalized(source):
    return ast.dump(ast.parse(source), include_attributes=False)


before_raw = (ROOT / 'baseline/tools/generate_hia_json_wire.py').read_bytes()
after_raw = (ROOT / 'inputs/tools/generate_hia_json_wire.py').read_bytes()
before_tree, after_tree = ast.parse(before_raw), ast.parse(after_raw)
before = literal(before_tree, 'SOURCE') + literal(before_tree, 'ENCODER')
after = literal(after_tree, 'SOURCE') + literal(after_tree, 'ENCODER')
magic = []
for node in after_tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
        and target.id in ('MAGIC', 'CACHED_MAGIC', 'KEY_SUMMARY_MAGIC') for target in node.targets):
        require(isinstance(node.value, ast.Call) and len(node.value.args) == 2
                and ast.unparse(node.value.func) == 'int.from_bytes'
                and ast.literal_eval(node.value.args[1]) == 'little', 'mechanical wire magic binding')
        magic.append((node.targets[0].id, ast.literal_eval(node.value.args[0]).decode('ascii')))
require(magic == [('MAGIC', 'HIAWIR02'), ('CACHED_MAGIC', 'HIAWIR03'), ('KEY_SUMMARY_MAGIC', 'HIAWIR04')],
        'only 02/03/04 are declared accepted magic; no 01 binding')
key_source, key_node = body(after, 'key_summary')
require(len(key_node.body) == 2 and isinstance(key_node.body[0], ast.If)
        and ast.unparse(key_node.body[0].test) == 'get(w, 0) == KEY_SUMMARY_MAGIC',
        'all new cache-field writes are guarded by magic04')
require(ast.unparse(key_node.body[-1]) == 'return ask(w, 1, handle, 0, 0, 0, next)',
        'every miss and both legacy protocols use original summary request')
expected_tests = {
    'get(w, 0) == KEY_SUMMARY_MAGIC', 'base != 0 and handle != 0', 'get(w, slot) == handle',
    'size <= 32 and count <= 128 and (width >= 2) and (width <= get(w, MAX))',
}
observed_tests = {ast.unparse(node.test) for node in ast.walk(key_node) if isinstance(node, ast.If)}
require(observed_tests == expected_tests, 'fixed independent exact-key cache permission conjunction')
calls = [ast.unparse(node) for node in ast.walk(key_node) if isinstance(node, ast.Call)]
require(not any(call.startswith(('read64(', 'byte(', 'text_begin(', 'norm_begin(')) for call in calls),
        'cache lookup cannot inspect the previous foreign packet or pre-observe a value')
for field in ('AWAIT', 'SEQ', 'REQ_H', 'REQ_INDEX', 'REQ_COUNT', 'REQ_PART'):
    require(not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == 'put' and len(node.args) == 3
                    and isinstance(node.args[1], ast.Name) and node.args[1].id == field
                    for node in ast.walk(key_node)), 'hit does not forge external request field ' + field)
expected_sites = [('read64(s, 24)', '12'), ('handle', '15'),
                  ('get(w, record)', '114'), ('get(w, record)', '143'),
                  ('get(w, frame + 48)', '143')]
sites = []
for name in ('preflight', 'encode'):
    _, node = body(after, name)
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == 'key_summary':
            sites.append((ast.unparse(child.args[1]), ast.unparse(child.args[2])))
require(sorted(sites) == sorted(expected_sites), 'exact five key-only request sites with fixed next phase')

for name in ('ask', 'text_begin', 'key_cache_save', 'key_cache_restore', 'normalize', 'norm_begin'):
    require(body(before, name)[0] == body(after, name)[0], 'entire retained admission/cache body unchanged: ' + name)
normalize = body(before, 'normalize')[0]
require('if get(w, CACHE_BASE) != 0 and get(w, T_MODE) == 1 and get(w, T_SIZE) <= 32:' in normalize,
        'original cache writer requires key validation mode and at most32 codepoints')
require('if phase == 30:\n        remaining = get(w, T_SIZE) - get(w, T_POS)\n        if remaining == 0:' in normalize,
        'cache write is after complete original codepoint consumption')
require('if kind == 4:\n            return text_begin(w, get(w, N_H), get(w, N_SIZE), choose(role == 0, 1, 2), target, 29)' in normalize,
        'original mode1 producer is only original string kind4 key role0')
writer = body(before, 'key_cache_save')[0]
require(writer.index('put(w, slot + 8, get(w, T_SIZE))') < writer.index('put(w, slot, get(w, T_H))')
        and 'if get(w, slot) != 0:\n        return 0' in writer,
        'only completed entries publish handle; occupied slots never overwritten')
old_bridge = (ROOT / 'baseline/hepta/hia_json_wire_native.py').read_text()
new_bridge = (ROOT / 'inputs/hepta/hia_json_wire_native.py').read_text()
old_nodes = {node.name: node for node in ast.parse(old_bridge).body if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
new_nodes = {node.name: node for node in ast.parse(new_bridge).body if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
observer = ast.get_source_segment(old_bridge, old_nodes['ForeignGraphObserver'])
require(observer == ast.get_source_segment(new_bridge, new_nodes['ForeignGraphObserver']),
        'actual original observer whole class is byte identical')
require('if kind is str:\n            return STRING, len(value), 0, 0' in observer,
        'actual observer string fact uses exact type and immutable length only')
require('self._objects[handle] = value' in observer and 'self._identities[identity] = handle' in observer,
        'existing registration retains object and per-session identity handle')
for name in ('_immutable_key_capability', '_private_zeroed_buffer', 'installed_json_wire'):
    require(ast.get_source_segment(old_bridge, old_nodes[name]) == ast.get_source_segment(new_bridge, new_nodes[name]),
            'existing capability/allocation/admission raw unchanged: ' + name)
ordinary = next(node for node in new_nodes['NativeJsonWire'].body
                if isinstance(node, ast.FunctionDef) and node.name == 'encode_ordinary')
ordinary_calls = [ast.unparse(node.func) for node in ast.walk(ordinary) if isinstance(node, ast.Call)]
require(ordinary_calls.count('ForeignGraphObserver') == 1 and ordinary_calls.count('WireSession') == 1,
        'ordinary entry constructs exactly one fresh observer and one fresh session')
require('self.workspace = _private_zeroed_buffer(workspace_size)' in new_bridge
        and 'self.key_summary_cache = self.key_cache and _builtin_key_summaries is True' in new_bridge,
        'facts remain operation-local and gated by existing exact observer capability')
inputs = []
for path in sorted((ROOT / 'inputs').rglob('*.py')):
    raw = path.read_bytes()
    ast.parse(raw)
    inputs.append({'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
report = {'schema': 'hepta.hia.json-wire-key-summary.independent-static-spec.v1',
          'status': 'STATIC_SPEC_CHECKS_PASS_ONLY', 'checks': checks, 'input_files': inputs,
          'protocols': {'01': 'REFUSED', '02': 'UNCHANGED_104_BYTES', '03': 'UNCHANGED_112_TEXT_CACHE',
                        '04': '112_BYTES_SAME_CACHE_EXACT_KEY_FACT_REUSE'},
          'native_or_generation_or_core_vm_executed': False}
path = ROOT / 'STATIC-PROTOCOL-SPEC.json'
require(not path.exists(), 'fresh spec receipt only')
path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'checks': len(checks)}))
