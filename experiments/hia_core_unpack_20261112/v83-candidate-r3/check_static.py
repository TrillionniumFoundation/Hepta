"""Compile-only and independent AST checks for the ordinary UNPACK overlay."""
from __future__ import annotations
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
import traceback


def digest(path):
    raw = path.read_bytes()
    return {'size': len(raw), 'sha256': sha256(raw).hexdigest()}


def test_ids(raw, module):
    return sorted(module + '.' + cls.name + '.' + method.name
                  for cls in ast.parse(raw).body if isinstance(cls, ast.ClassDef)
                  for method in cls.body if isinstance(method, ast.FunctionDef)
                  and method.name.startswith('test_'))


def run(inputs, baseline, output):
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'hepta.hia.core-unpack-static-control.v1', 'status': 'HOLD',
              'python': sys.version, 'checks': [], 'product_executed': False,
              'native_or_cold_claimed': False}
    started = time.monotonic()
    paths = sorted(p for p in inputs.rglob('*') if p.is_file())
    before = {p.relative_to(inputs).as_posix(): digest(p) for p in paths}
    report['source_before'] = before
    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        report['checks'].append(name)
    def text(name):
        return (inputs / name).read_text()
    try:
        for path in paths:
            if path.suffix == '.py':
                compile(path.read_bytes(), str(path), 'exec')
        check('all Python overlay inputs compile without execution', True)
        original_tests = 'tests/test_hia_core_lowering_native.py'
        check('all original fifteen Core component IDs are unchanged',
              test_ids((baseline / original_tests).read_bytes(), 'tests.test_hia_core_lowering_native')
              == test_ids((inputs / original_tests).read_bytes(), 'tests.test_hia_core_lowering_native')
              and len(test_ids((inputs / original_tests).read_bytes(), 'tests.test_hia_core_lowering_native')) == 15)
        check('eight new methods supplement the unchanged116',
              len(test_ids(text('tests/test_hia_core_unpack_native.py'), 'tests.test_hia_core_unpack_native')) == 8)
        old = ast.parse((baseline / 'hepta/hia_core_lowering_native.py').read_bytes())
        cls = next(n for n in old.body if isinstance(n, ast.ClassDef) and n.name == 'LoweringSession')
        method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_primitive')
        branch = next(n for n in method.body if isinstance(n, ast.If)
                      and ast.dump(n.test) == ast.dump(ast.parse('opcode == 14', mode='eval').body))
        new = ast.parse(text('hepta/hia_core_lowering_native.py'))
        helper = next(n for n in new.body if isinstance(n, ast.FunctionDef) and n.name == '_host_unpack')
        check('retained helper has only the declared literal docstring before its policy',
              isinstance(helper.body[0], ast.Expr) and isinstance(helper.body[0].value, ast.Constant)
              and helper.body[0].value.value == 'Retained opcode-14 value policy, independent of the HIA companion.')
        check('retained complete unpack is exactly original cardinality body',
              ast.dump(ast.Module(body=branch.body[2:], type_ignores=[]))
              == ast.dump(ast.Module(body=helper.body[1:], type_ignores=[])))
        old_methods = {n.name: ast.dump(n) for n in cls.body if isinstance(n, ast.FunctionDef)}
        new_cls = next(n for n in new.body if isinstance(n, ast.ClassDef) and n.name == cls.name)
        new_methods = {n.name: ast.dump(n) for n in new_cls.body if isinstance(n, ast.FunctionDef)}
        check('every outer LoweringSession method except primitive is unchanged',
              {k: v for k, v in old_methods.items() if k != '_primitive'}
              == {k: v for k, v in new_methods.items() if k != '_primitive'})
        check('full retained pre-overlay bridge bytes are preserved',
              (inputs / 'tests/fixtures/hia_core_lowering_native_before_unpack.py.txt').read_bytes()
              == (baseline / 'hepta/hia_core_lowering_native.py').read_bytes())
        old_backend = ast.parse((baseline / 'hepta/hia_program_native.py').read_bytes())
        new_backend = ast.parse(text('hepta/hia_program_native.py'))
        for name in ('_Function', '_Emitter'):
            old_class = next(n for n in old_backend.body if isinstance(n, ast.ClassDef) and n.name == name)
            new_class = next(n for n in new_backend.body if isinstance(n, ast.ClassDef) and n.name == name)
            check('complete original backend class unchanged: ' + name, ast.dump(old_class) == ast.dump(new_class))
        pins = json.loads(text('tests/fixtures/hia_core_unpack_core39.json'))['files']
        check('forty old inputs are actual39 HIA plus exact ABI', len(pins) == 40
              and all(digest(baseline / name) == pin for name, pin in pins.items())
              and not any(name in before for name in pins))
        parsed = ast.parse(text(original_tests))
        child_node = next(n.value for n in parsed.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'INSTALLED_CHILD' for t in n.targets))
        child = ast.literal_eval(child_node)
        compile(child, '<installed UNPACK child>', 'exec')
        check('actual installed child syntax is independently valid', True)
        resources = ast.parse(text('hepta/hia_agent_contract.py'))
        resources = ast.literal_eval(next(n.value for n in resources.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'NATIVE_SOURCE_FILES' for t in n.targets)))
        old_resources = ast.parse((baseline / 'hepta/hia_agent_contract.py').read_bytes())
        old_resources = ast.literal_eval(next(n.value for n in old_resources.body if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == 'NATIVE_SOURCE_FILES' for t in n.targets)))
        extra = ('hepta/hia_core_unpack_abi.json', 'examples/hia_bootstrap/core_unpack.hiaasm')
        check('resource tuple keeps every old item in order and adds only companion pair',
              resources == extra + old_resources and len(resources) == len(set(resources)))
        manifest = text('MANIFEST.in')
        check('MANIFEST retains all original bytes and adds only companion pair',
              manifest == (baseline / 'MANIFEST.in').read_text() + ''.join('include ' + n + '\n' for n in extra))
        generic = 'tests/test_hia_agent_installed_resources.py'
        check('all original generic installed-resource methods are unchanged',
              test_ids((baseline / generic).read_bytes(), 'tests.test_hia_agent_installed_resources')
              == test_ids((inputs / generic).read_bytes(), 'tests.test_hia_agent_installed_resources')
              and len(test_ids((inputs / generic).read_bytes(), 'tests.test_hia_agent_installed_resources')) == 21)
        old_ast, new_ast = ast.parse((baseline / generic).read_bytes()), ast.parse((inputs / generic).read_bytes())
        check('generic installed-resource class bodies are byte-for-byte AST equivalent',
              [ast.dump(n) for n in old_ast.body if isinstance(n, ast.ClassDef)]
              == [ast.dump(n) for n in new_ast.body if isinstance(n, ast.ClassDef)])
        report['status'] = 'STATIC_CONTROL_PASS'
    except BaseException:
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        try:
            report['source_after'] = {p.relative_to(inputs).as_posix(): digest(p) for p in paths}
            report['source_stable'] = before == report['source_after']
            if not report['source_stable']:
                report['status'] = 'HOLD'
        except BaseException:
            report['status'] = 'HOLD'
            report['preservation_error'] = traceback.format_exc()
        report['seconds'] = time.monotonic() - started
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'STATIC_CONTROL_PASS' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.inputs.resolve(), args.baseline.resolve(), args.evidence.resolve()))
