"""Check the frozen Emitter inputs and finite IR, without generating HIA."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha1, sha256
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'

def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def require(condition, message):
    if not condition:
        raise AssertionError(message)

def save(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with (ROOT / 'evidence' / name).open('xb') as stream:
        stream.write(raw)
    return identity(raw)

def nodes(raw):
    return ast.parse(raw, type_comments=True)

def find(tree, cls, name):
    return next(n for n in tree.body if isinstance(n, cls) and n.name == name)

def normalized(node):
    return ast.dump(node, include_attributes=False)

def snapshot(inputs):
    observed = []
    for row in inputs['files']:
        path = SOURCE / row['path']
        require(path.is_file() and not path.is_symlink(), 'missing regular input: ' + row['path'])
        value = identity(path.read_bytes())
        require(value == {key: row[key] for key in value}, 'canonical input differs: ' + row['path'])
        observed.append({'path': row['path'], **value})
    return observed

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--control-sha256', required=True)
    args = parser.parse_args()
    control = Path(__file__).read_bytes()
    input_raw = (ROOT / 'INPUTS.json').read_bytes()
    require(sha256(control).hexdigest() == args.control_sha256, 'control identity differs')
    require(sha256(input_raw).hexdigest() == args.inputs_sha256, 'frozen input manifest differs')
    inputs = json.loads(input_raw)
    require(inputs['schema'] == 'hia.core-emitter-cloud-static-inputs.v1'
            and inputs['source_commit'] == '80ec04ae7489209b122c874531d194c67b30dfed'
            and inputs['source_tree'] == '963e980c2486e1f7c74fa42bc8132ef6b1b8b690',
            'authoring input identity differs')
    (ROOT / 'evidence').mkdir(mode=0o700)
    started = time.monotonic()
    report = {
        'schema': 'hia.core-emitter-cloud-static-observation.v1',
        'status': 'HOLD', 'scope': 'SEVEN_FROZEN_INPUTS_AND_FINITE_IR_ONLY',
        'source_commit': inputs['source_commit'], 'source_tree': inputs['source_tree'],
        'complete_source_checkout_materialized': False,
        'public_Core_verifier_executed': False, 'HIA_assembly_generated': False,
        'native_compiler_executed': False, 'Core_VM_executed': False,
        'product_tests_executed': False, 'cold_qualified': False,
        'old_v1_results_inherited': False, 'source_preserved': False,
        'control_identity': identity(control), 'input_manifest_identity': identity(input_raw),
        'python': {'executable': sys.executable, 'resolved': str(Path(sys.executable).resolve()),
                   'version': sys.version,
                   'sha256': sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()},
    }
    before = None
    try:
        before = snapshot(inputs)
        report['source_before'] = before
        for row in inputs['files']:
            if row['path'].endswith('.py'):
                compile((SOURCE / row['path']).read_bytes(), row['path'], 'exec')
        report['compiled_python_inputs'] = [row['path'] for row in inputs['files']
                                            if row['path'].endswith('.py')]
        original = nodes((SOURCE / 'tests/fixtures/hia_program_native_608.py.txt').read_bytes())
        policy = nodes((SOURCE / 'tools/hia_core_lowering_policy.py').read_bytes())
        backend = nodes((SOURCE / 'hepta/hia_program_native.py').read_bytes())
        classes = {}
        for name, count in (('_Function', 22), ('_Emitter', 6)):
            old, authored, retained = (find(t, ast.ClassDef, name)
                                      for t in (original, policy, backend))
            methods = [n.name for n in old.body if isinstance(n, ast.FunctionDef)]
            require(len(methods) == count, 'original class denominator differs: ' + name)
            require(normalized(old) == normalized(authored), 'authoring class AST differs: ' + name)
            additions = [n for n in retained.body if isinstance(n, ast.FunctionDef) and n.name == '__new__']
            require(len(additions) == 1, 'exact selector addition required: ' + name)
            retained.body = [n for n in retained.body if n not in additions]
            require(normalized(old) == normalized(retained), 'retained class AST differs: ' + name)
            classes[name] = methods
        helper_names = ('_reject', '_words', '_bounds', '_normalize', '_prologue')
        for name in helper_names:
            old = find(original, ast.FunctionDef, name)
            authored = find(policy, ast.FunctionDef, name)
            retained = find(backend, ast.FunctionDef, '_reference' + name)
            retained.name = name
            require(normalized(old) == normalized(authored) == normalized(retained),
                    'full original helper AST differs: ' + name)
        report['original_AST'] = {'classes': classes, 'helpers': list(helper_names),
                                  'complete_original_bodies': 33, 'all_exact': True}
        path = SOURCE / 'tools/hia_core_lowering_ir.py'
        spec = importlib.util.spec_from_file_location('_hia_emitter_ir_frozen', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        literals, functions, entries, instructions = module.compile_policy(
            (SOURCE / 'tools/hia_core_lowering_policy.py').read_text())
        selection = nodes((SOURCE / 'hepta/hia_core_lowering_selection.py').read_bytes())
        definitions = {}
        for node in selection.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ('_MODE_ARITIES', '_GENERATOR_MODES'):
                        definitions[target.id] = ast.literal_eval(node.value)
        modes = definitions['_MODE_ARITIES']
        require(len(modes) == len(entries) == len(functions) == 36, 'complete v2 mode denominator differs')
        require(list(entries) == [name for name, _ in modes], 'finite mode order differs')
        for number, (name, arity) in enumerate(modes, 1):
            require(entries[name]['mode'] == number and len(entries[name]['parameters']) == arity,
                    'finite mode binding differs: ' + name)
        generators = [function.name for function in functions if getattr(function, 'is_generator', False)]
        require(generators == list(definitions['_GENERATOR_MODES'])
                == ['_native_generator_0', '_native_generator_1'],
                'exact two lazy generator modes required')
        require(sum(item['kind'] == 'yield' for item in instructions) == 2,
                'each reviewed generator needs one HIA yield instruction')
        report['finite_IR'] = {
            'functions': len(functions), 'literal_count': len(literals.values),
            'instructions': len(instructions), 'maximum_slots': max(f.slot_count for f in functions),
            'modes': entries, 'generator_modes': generators,
            'ABI_and_generated_unit_inventory_not_created': True,
        }
        report['status'] = 'STATIC_INPUTS_AND_FINITE_IR_PASS'
    except BaseException:
        report['exception'] = traceback.format_exc()
    finally:
        try:
            after = snapshot(inputs)
            report['source_after'] = after
            report['source_preserved'] = before is not None and after == before
            if not report['source_preserved']:
                report['status'] = 'HOLD'
        except BaseException:
            report['source_preserved'] = False
            report['status'] = 'HOLD'
            report['final_identity_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        save('report.json', report)
        print(json.dumps({key: report.get(key) for key in (
            'status', 'scope', 'seconds', 'source_preserved', 'exception',
            'final_identity_error')}, sort_keys=True), flush=True)
    return 0 if report['status'] == 'STATIC_INPUTS_AND_FINITE_IR_PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
