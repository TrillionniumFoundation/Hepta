from pathlib import Path
import ast
import base64
from collections import Counter
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import sys
import unittest
import zlib
import yaml

ROOT = Path('/workspace/scratch/dda74a4fae35')
BASE = ROOT / 'v75-heap-product-publication/source'
SOURCE = ROOT / 'v76-unified-integration-r1/source'
HARNESS = ROOT / 'v76-source-generation-r1'
OVERLAY_DIR = HARNESS / 'overlay'
assert not OVERLAY_DIR.exists()
assert not (SOURCE / '.git').exists()
sys.dont_write_bytecode = True
sys.path.insert(0, str(HARNESS / 'tools'))
sys.path.insert(0, str(SOURCE))
spec = importlib.util.spec_from_file_location('v76_source_authoring', HARNESS / 'tools/hia_source_integration_v76.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)

def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())

def inventory(root):
    result = {}
    for p in root.rglob('*'):
        assert not p.is_symlink(), str(p)
        if p.is_file():
            mode = stat.S_IMODE(p.stat().st_mode)
            assert mode in (0o644, 0o755), (p, mode)
            raw = p.read_bytes()
            result[p.relative_to(root).as_posix()] = dict(identity(raw), mode='100755' if mode & 0o111 else '100644')
    return result

base, current = inventory(BASE), inventory(SOURCE)
assert len(base) == 3120 and len(current) == 3153
assert set(base) <= set(current)
assert base['tools/check_hia_core_only.py'] == current['tools/check_hia_core_only.py']
bw = (BASE / '.github/workflows/hia-core.yml').read_text()
cw = (SOURCE / '.github/workflows/hia-core.yml').read_text()
old_generators, old_shell = driver.parse_generator_step(bw)
new_generators, new_shell = driver.parse_generator_step(cw)
driver.preserve_subsequence(old_generators, new_generators, 'source generators')
assert len(old_generators) == 77 and len(new_generators) == 80
assert set(new_generators) - set(old_generators) == {'machine_elf', 'machine_plan', 'service_context'}
extra = ['tests.test_hia_candidate_evidence', 'tests.test_hia_candidate_preflight']
control = driver.source_controls(bw, cw, extra)
assert len(control['original_names']) == 143
assert len(control['workflow_names']) == 148
assert len(control['executed_selectors']) == 152
loader = unittest.TestLoader()
suite = loader.loadTestsFromNames(control['executed_selectors'])
def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item.id()
ids = list(flatten(suite))
assert not loader.errors, loader.errors
assert len(ids) == len(set(ids)) == 728

# Old workflow jobs and steps remain byte-for-byte equivalent as parsed values,
# except the two explicitly extended inventories and append-only retention.
base_workflow, current_workflow = yaml.safe_load(bw), yaml.safe_load(cw)
assert set(base_workflow['jobs']) == set(current_workflow['jobs'])
workflow_checks = []
for job, old in base_workflow['jobs'].items():
    new = current_workflow['jobs'][job]
    assert {k: v for k, v in old.items() if k != 'steps'} == {k: v for k, v in new.items() if k != 'steps'}, job
    old_names = [step.get('name') for step in old['steps']]
    new_names = [step.get('name') for step in new['steps']]
    assert [name for name in new_names if name in old_names] == old_names, job
    for step in old['steps']:
        matches = [candidate for candidate in new['steps'] if candidate.get('name') == step.get('name')]
        assert len(matches) == 1
        candidate = matches[0]
        name = step.get('name')
        if name in ('Regenerate actual HIA sources', 'Core source and independent reference controls'):
            assert {k: v for k, v in step.items() if k != 'run'} == {k: v for k, v in candidate.items() if k != 'run'}
        elif name == 'Preserve actual cold failure and stage evidence':
            left, right = dict(step), dict(candidate)
            left['with'], right['with'] = dict(left['with']), dict(right['with'])
            original_paths = left['with'].pop('path').splitlines()
            actual_paths = right['with'].pop('path').splitlines()
            assert left == right and actual_paths[:len(original_paths)] == original_paths
        else:
            assert step == candidate, name
        workflow_checks.append(name)

old = (HARNESS / 'originals/driver.py').read_text()
new = (HARNESS / 'tools/hia_source_integration_v76.py').read_text()
restored = new.replace('5f7f95367e8e395863801487e969d286b9091110', 'f8d9680a9b0ae609850c006480a7d1f68ea00979')
restored = restored.replace('4f4e58e06a6e03adcd6548bd8ea4ef591c20359f', '473404cdccc38a7e6bba633ef4a894877540d70e')
restored = restored.replace('v76', 'v75').replace('exact 5f7', 'exact f8d')
ot, nt = ast.parse(old), ast.parse(restored)
allow = {'GENERATED_HIA', 'EXTRA_GENERATORS', 'MANDATORY_CONTROLS'}
assignments = {n.targets[0].id: n for n in ot.body if isinstance(n, ast.Assign)
               and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
for n in nt.body:
    if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id in allow:
        n.value = assignments[n.targets[0].id].value
assert ast.dump(nt) == ast.dump(ot)
assert (HARNESS / 'tools/workflow_process.py').read_bytes() == (HARNESS / 'originals/workflow_process.py').read_bytes()

files = []
for name, row in sorted(current.items()):
    if base.get(name) != row:
        raw = (SOURCE / name).read_bytes()
        files.append(dict(path=name, **row, content=raw.decode('utf-8', 'strict')))
assert len(files) == 55
overlay = dict(schema=driver.OVERLAY_SCHEMA, base_commit=driver.BASE_COMMIT, base_tree=driver.BASE_TREE,
               files=files, expected_generated_paths=list((*driver.GENERATED_HIA, *driver.GENERATED_DOCS)),
               extra_controls=extra)
raw = (json.dumps(overlay, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
args = type('Args', (), dict(overlay_sha256=identity(raw)['sha256'], expected_commit=driver.BASE_COMMIT,
                            expected_tree=driver.BASE_TREE))()
assert driver.decode_overlay(raw, args) == overlay
compressed = zlib.compress(raw, 9)
wrapper = dict(schema='hia.source-overlay-zlib-wrapper.v1', bytes=len(raw), sha256=identity(raw)['sha256'],
               compressed_bytes=len(compressed), compressed_sha256=identity(compressed)['sha256'],
               data=base64.b64encode(compressed).decode())
wrapped = (json.dumps(wrapper, sort_keys=True, separators=(',', ':')) + '\n').encode()
assert zlib.decompress(base64.b64decode(wrapper['data'], validate=True)) == raw
OVERLAY_DIR.mkdir()
(OVERLAY_DIR / 'source-overlay.json').write_bytes(raw)
(OVERLAY_DIR / 'source-overlay.wrapper.json').write_bytes(wrapped)
workflow_path = HARNESS / '.github/workflows/hia-source-generation-v76.yml'
text = workflow_path.read_text()
assert text.count('OVERLAY_SHA256_PENDING_FINAL_SOURCE') == 1
text = text.replace('OVERLAY_SHA256_PENDING_FINAL_SOURCE', identity(raw)['sha256'])
workflow_path.write_text(text)
shells = []
for label, body in [('harness', text), ('product', cw)]:
    parsed = yaml.safe_load(body)
    for job in parsed['jobs'].values():
        for step in job['steps']:
            if 'run' not in step:
                continue
            script = step['run']
            subprocess.run(['bash', '--noprofile', '--norc', '-n'], input=script.encode(), check=True)
            # Python heredocs are parsed without executing their tests or builders.
            lines = script.splitlines()
            for index, line in enumerate(lines):
                match = re.search(r"<<'([A-Z][A-Z0-9_]*)'", line)
                if match and 'python' in line:
                    end = lines.index(match.group(1), index + 1)
                    ast.parse('\n'.join(lines[index + 1:end]) + '\n')
            shells.append(dict(workflow=label, step=step.get('name'), syntax_only=True))

assert inventory(SOURCE) == current
report = dict(schema='hia.v76.source-harness-final-authoring.v1', status='READY_FOR_INDEPENDENT_SOURCE_GENERATION',
              base_commit=driver.BASE_COMMIT, base_tree=driver.BASE_TREE, source_files=len(current),
              overlay_files=len(files), new_files=len(set(current) - set(base)), deleted_files=[],
              original_generators=old_generators, candidate_generators=new_generators,
              source_control_inventory=control, loaded_test_count=len(ids), unique_test_count=len(set(ids)),
              loaded_ids=ids, tests_executed=0, loader_errors=loader.errors,
              overlay_identity=identity(raw), wrapper_identity=identity(wrapped),
              driver_identity=identity((HARNESS / 'tools/hia_source_integration_v76.py').read_bytes()),
              supervisor_identity=identity((HARNESS / 'tools/workflow_process.py').read_bytes()),
              workflow_identity=identity(workflow_path.read_bytes()),
              all_original_driver_function_asts_unchanged_after_identity_literal_projection=True,
              extended_constants=sorted(allow), all_original_workflow_step_semantics_preserved=workflow_checks,
              all_original_limits_preserved=True, shell_syntax_checks=shells,
              component_counts=dict(cli=38, machine_elf=37, machine_plan=21, service_context=52),
              original_caller_counts=dict(machine_instructions=51, machine_elf=51, machine_plan=44, service_context=48),
              whole_native_delivery_qualified=False, current_source_cold_qualified=False)
(HARNESS / 'FINAL-AUTHORING.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
(HARNESS / 'FROZEN-SOURCE.json').write_text(json.dumps(current, sort_keys=True, indent=2) + '\n')
print(json.dumps({key: report[key] for key in ('status', 'source_files', 'overlay_files', 'new_files',
      'loaded_test_count', 'unique_test_count', 'tests_executed', 'overlay_identity', 'wrapper_identity',
      'driver_identity', 'workflow_identity', 'whole_native_delivery_qualified')}, sort_keys=True))
