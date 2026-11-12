"""Read exact v88 and frozen numeric bytes; never import or execute the product.

This creates a small source handoff, not a checkout, generator, test run or
native qualification. The only mutable destination is this private directory.
"""
from __future__ import annotations

import ast
import copy
import difflib
from hashlib import sha1, sha256
import json
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
FROZEN = Path('/workspace/scratch/e26ed3e2edcf/core-numeric-comparison-r1')
PLAN = Path('/workspace/scratch/e26ed3e2edcf/core-numeric-native-plan-r3')


def pin(raw):
    return dict(size=len(raw), sha256=sha256(raw).hexdigest(),
                git_blob_sha1=sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def write(relative, raw):
    path = HERE / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def assigned(tree, name):
    return next(node.value for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))


def method(tree, class_name, method_name):
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    return next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method_name)


def main():
    context = json.loads((HERE / 'BASE-CONTEXT.json').read_bytes())
    selected = {row['path']: row for row in context['selected_canonical_files']}
    observed = []
    for name, row in selected.items():
        path = BASE / name
        raw = path.read_bytes()
        actual = pin(raw)
        assert actual['size'] == row['size'] and actual['git_blob_sha1'] == row['sha'], name
        assert stat.S_IMODE(path.stat().st_mode) == int(row['mode'][-3:], 8), name
        observed.append(dict(path=name, mode=row['mode'], **actual))
    original_delta_raw = (FROZEN / 'final-evidence/SOURCE-DELTA.json').read_bytes()
    original_delta = json.loads(original_delta_raw)
    write('references/SOURCE-DELTA.original.json', original_delta_raw)
    rows, differences = [], []
    for item in original_delta['delta']:
        name = item['path']
        source = FROZEN / item.get('source_in_preexec', item.get('actual_source', ''))
        raw = source.read_bytes()
        assert pin(raw) == {key: item['after'][key] for key in ('size', 'sha256', 'git_blob_sha1')}, name
        before = None
        if item['before'] is not None:
            old = (BASE / name).read_bytes()
            before = pin(old)
            assert before == {key: item['before'][key] for key in before}, name
            assert before['git_blob_sha1'] == selected[name]['sha'], name
            write('base/' + name, old)
            differences.extend(difflib.unified_diff(old.decode().splitlines(True), raw.decode().splitlines(True),
                               fromfile='a/' + name, tofile='b/' + name))
        else:
            assert not (BASE / name).exists(), name
        write('product/' + name, raw)
        rows.append(dict(path=name, mode='100644', before=before, after=pin(raw),
                         status='modified' if before else 'added', frozen_source=str(source)))
    assert len(rows) == 13 and sum(row['before'] is None for row in rows) == 10
    write('EXISTING-THREE-FILES.diff', ''.join(differences).encode())
    fixture = json.loads((HERE / 'product/tests/fixtures/hia_core_compare_core39.json').read_bytes())
    assert len(fixture['files']) == 40
    for row in fixture['files']:
        raw = (BASE / row['path']).read_bytes()
        assert len(raw) == row['size'] and sha256(raw).hexdigest() == row['sha256']
    old = ast.parse((BASE / 'hepta/hia_core_lowering_native.py').read_bytes())
    new = ast.parse((HERE / 'product/hepta/hia_core_lowering_native.py').read_bytes())
    old_class = next(node for node in old.body if isinstance(node, ast.ClassDef) and node.name == 'LoweringSession')
    new_class = next(node for node in new.body if isinstance(node, ast.ClassDef) and node.name == 'LoweringSession')
    new_class = copy.deepcopy(new_class)
    primitive = next(node for node in new_class.body if getattr(node, 'name', None) == '_primitive')
    branch = next(node for node in primitive.body if isinstance(node, ast.If)
                  and ast.dump(node.test) == ast.dump(ast.parse('opcode == 13', mode='eval').body))
    assert len(branch.body) == 3 and isinstance(branch.body[1], ast.If)
    chosen = branch.body[1]
    assert ast.unparse(chosen.body[0]) == 'target = _COMPARE[operation]'
    assert ast.unparse(chosen.body[1]) == 'observed_left = get(left)'
    assert ast.unparse(chosen.body[2]) == 'observed_right = get(right)'
    del branch.body[1]
    assert ast.dump(old_class) == ast.dump(new_class)
    callers_tree = ast.parse((BASE / 'tools/qualify_hia_core_lowering_callers.py').read_bytes())
    groups = {name: ast.literal_eval(assigned(callers_tree, name))
              for name in ('COMPONENT_IDS', 'ORIGINAL_IDS', 'CORE_IDS')}
    assert [len(row) for row in groups.values()] == [15, 51, 50]
    assert len({name for group in groups.values() for name in group}) == 116
    source_tree = ast.parse((HERE / 'product/tests/test_hia_core_compare_source.py').read_bytes())
    source_ids = ['tests.test_hia_core_compare_source.ExactNumericComparisonSourceTests.' + node.name
                  for node in next(c for c in source_tree.body if isinstance(c, ast.ClassDef)
                                   and c.name == 'ExactNumericComparisonSourceTests').body
                  if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    assert len(source_ids) == 11
    finite = ast.parse((PLAN / 'control/native_cases.py').read_bytes())
    finite_ids = ['__main__.FiniteNumericComparisonNativeTests.' + node.name
                  for node in next(c for c in finite.body if isinstance(c, ast.ClassDef)
                                   and c.name == 'FiniteNumericComparisonNativeTests').body
                  if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
    assert len(finite_ids) == 8
    workflow = (BASE / '.github/workflows/hia-core.yml').read_text()
    generator_line = next(line for line in workflow.splitlines() if 'for component in ' in line)
    generators = generator_line.split('for component in ', 1)[1].split('; do')[0].split()
    assert len(generators) == 61 and generators[-2:] == ['bounded_read', 'core_unpack']
    assert workflow.count("python-version: '3.14.4'") == 2
    source_envs = sorted({node.slice.value for node in ast.walk(source_tree)
                         if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
                         and isinstance(node.value.value, ast.Name) and node.value.value.id == 'os'
                         and node.value.attr == 'environ' and isinstance(node.slice, ast.Constant)})
    assert source_envs == ['HEPTA_COMPARE_BASE_ROOT', 'HEPTA_COMPARE_CONTROL_EVIDENCE']
    generator_tree = ast.parse((HERE / 'product/tools/generate_hia_core_compare.py').read_bytes())
    output_required = [node for node in ast.walk(generator_tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument'
                       and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == '--output'
                       and any(k.arg == 'required' and isinstance(k.value, ast.Constant) and k.value.value is True
                               for k in node.keywords)]
    assert len(output_required) == 1
    installed_tree = ast.parse((BASE / 'tests/test_hia_core_lowering_native.py').read_bytes())
    installed_child = ast.literal_eval(assigned(installed_tree, 'INSTALLED_CHILD'))
    assert installed_child.count('if len(sys.argv)==5:') == 2
    assert 'HEPTA_' in (BASE / 'tools/qualify_hia_core_unpack_ci.py').read_text()
    report = dict(schema='hepta.hia.numeric-v88-static-merge-audit.v1', status='STATIC_EXACT_DELTA_VERIFIED',
        canonical_base=context['canonical_commit'], canonical_tree=context['canonical_tree'],
        observed_head=context['observed_local_HEAD'], observed_index=context['observed_index_tree'],
        selected_base_files_verified=observed, product_delta=rows,
        delta_files=13, added=10, modified=3, deleted=0, existing_files_match_original_numeric_base=True,
        complete_LoweringSession_AST_equal_after_removing_only_selected_numeric_branch=True,
        bound_target_left_get_right_get_order_unchanged=True,
        Core39_HIA_and_ABI_40_files_exactly_unchanged=True, original116_groups=groups,
        source11_ids=sorted(source_ids), finite8_ids=sorted(finite_ids), existing61_generators=generators,
        source_environment_requirements=source_envs, generator_currently_requires_output=True,
        installed_UNPACK_only_len5_branches=2, both_standard_CI_interpreters_exact_3144=True,
        source_compatibility_blockers_are_not_product_execution_failures=True,
        product_imported=False, generator_or_Core_VM_executed=False, native_executed=False,
        tests_executed=False, current_source_checkout_created=False, current_source_modified=False,
        original_native_result_commit='8abaaa8c0dd381b8ab4422d13eee7b4f033f1aea')
    write('STATIC-MERGE-AUDIT.json', wire(report))
    write('MERGE-MANIFEST.json', wire(dict(schema='hepta.hia.numeric-exact-v88-delta.v1',
        base_commit=context['canonical_commit'], base_tree=context['canonical_tree'], delta=rows,
        semantic_integration_complete=False, current_source_qualification_pass=False)))
    print(json.dumps({key: report[key] for key in ('status', 'delta_files', 'added', 'modified', 'deleted',
          'existing_files_match_original_numeric_base', 'Core39_HIA_and_ABI_40_files_exactly_unchanged',
          'product_imported', 'generator_or_Core_VM_executed', 'native_executed', 'tests_executed')}))


if __name__ == '__main__':
    main()
