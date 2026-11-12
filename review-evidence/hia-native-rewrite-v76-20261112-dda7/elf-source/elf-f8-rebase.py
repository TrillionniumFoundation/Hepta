from __future__ import annotations
import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'integration-f8-delta-r1'
OUT.mkdir()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def meta(raw):
    return {'bytes': len(raw), 'sha256': sha(raw), 'git_blob': hashlib.sha1(
        b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'mode': '100644'}

def unique_replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('non-unique exact merge anchor: ' + before)
    return text.replace(before, after)

base = json.loads((ROOT / 'f8-inputs.json').read_bytes())
with zipfile.ZipFile(ROOT / 'hia-elf-v76-development-43178050672-1.zip') as z:
    pieces = []
    for i in range(4):
        suffix = 'inputs/overlay.part-' + str(i).zfill(3) + '.txt'
        names = [name for name in z.namelist() if name.endswith(suffix)]
        assert len(names) == 1
        pieces.append(z.read(names[0]))
    wrapper_raw = b''.join(pieces)
    assert sha(wrapper_raw) == '24ecdcb42ebf002afdc0e0b612d18600cde6c3722b1a4f01d8d1d0f2534c9d6d'
    wrapper = json.loads(wrapper_raw)
    overlay_raw = zlib.decompress(base64.b64decode(wrapper['zlib_base64'], validate=True))
    assert sha(overlay_raw) == '9c066bdddbf0568be9013ad6d7db242caccd49690c08972df00ec18fefe8c98c'
    overlay = json.loads(overlay_raw)

for name, row in base['files'].items():
    raw = row['utf8'].encode()
    assert meta(raw) == {key: row[key] for key in meta(raw)}

shared = ['hepta/hia_exception_delivery.py', 'tools/hia_exception_delivery.py',
          'hepta/hia_json_preflight_native.py']
shared_records = {}
for name in shared:
    current = base['files'][name]['utf8'].encode()
    tested = base64.b64decode(overlay['files'][name]['base64'], validate=True)
    assert ast.dump(ast.parse(current), include_attributes=False) == ast.dump(ast.parse(tested), include_attributes=False)
    shared_records[name] = {'preserve_current_f8': meta(current), 'tested_7e9_overlay': meta(tested),
                            'exact_bytes_equal': current == tested, 'ast_equal': True,
                            'included_in_owner_delta': False}

existing = {'MANIFEST.in', 'hepta/hia_agent_contract.py', 'hepta/hia_native_helpers.py',
            'hepta/hia_machine_elf.py', 'hepta/hia_program_native.py'}
after = {name: base64.b64decode(row['base64'], validate=True)
         for name, row in overlay['files'].items() if name not in shared and name not in existing}
assert len(after) == 10

name = 'hepta/hia_machine_elf.py'
original = base['files'][name]['utf8'].encode()
tested = base64.b64decode(overlay['files'][name]['base64'], validate=True)
assert len(original) == 7026 and sha(original) == 'c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101'
assert tested[:len(original)] == original
after[name] = tested

name = 'MANIFEST.in'
text = base['files'][name]['utf8']
assert 'include examples/hia_bootstrap/machine_elf.hiaasm\n' not in text
after[name] = ('include examples/hia_bootstrap/machine_elf.hiaasm\n' + text).encode()

name = 'hepta/hia_agent_contract.py'
text = base['files'][name]['utf8']
after[name] = unique_replace(text, 'NATIVE_SOURCE_FILES = (\n',
    "NATIVE_SOURCE_FILES = (\n    'examples/hia_bootstrap/machine_elf.hiaasm',\n").encode()

name = 'hepta/hia_native_helpers.py'
text = base['files'][name]['utf8']
after[name] = unique_replace(text, 'HELPERS = {\n',
    'HELPERS = {\n    "HEPTA_HIA_MACHINE_ELF_MANIFEST": ("hia_machine_elf_native", "NativeMachineElf"),\n').encode()

name = 'hepta/hia_program_native.py'
text = base['files'][name]['utf8']
text = unique_replace(text, '"hia_machine_elf.py", "hia_machine_plan.py",',
    '"hia_machine_elf.py", "hia_machine_elf_native.py", "hia_machine_plan.py",')
anchor = "    digest.update(b'native-machine-encoding\\0' + encoding_identity() + b'\\0')\n"
addition = ('    from .hia_machine_elf import native_implementation_identity as elf_identity\n'
            '    selected_elf = elf_identity()\n'
            '    if selected_elf:\n'
            '        digest.update(b"machine-elf-native\\0" + selected_elf + b"\\0")\n')
text = unique_replace(text, anchor, anchor + addition)
text = unique_replace(text,
    '    from .hia_machine_x64 import native_encoding_scope\n    with native_encoding_scope():\n',
    '    from .hia_machine_x64 import native_encoding_scope\n    from .hia_machine_elf import native_elf_scope\n'
    '    with native_encoding_scope(), native_elf_scope():\n')
after[name] = text.encode()

def definitions(raw):
    return {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(raw).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}

old = definitions(base['files']['hepta/hia_program_native.py']['utf8'])
new = definitions(after['hepta/hia_program_native.py'])
assert old.keys() == new.keys()
changed_defs = [name for name in old if old[name] != new[name]]
assert changed_defs == ['_implementation_hash', 'emit_program_machine']

def assignments(raw):
    return {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name) and node.targets[0].id.endswith('_FILES')
            and isinstance(node.value, ast.Tuple)}

before_groups = assignments(base['files']['hepta/hia_agent_contract.py']['utf8'])
after_groups = assignments(after['hepta/hia_agent_contract.py'])
for name in ['DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'PUBLICATION_BUILD_FILES', 'SOURCE_BUILD_FILES', 'COMPILER_BUILD_FILES']:
    assert set(before_groups[name]).issubset(set(after_groups[name]))
    if name == 'NATIVE_SOURCE_FILES':
        assert set(after_groups[name]) - set(before_groups[name]) == {'examples/hia_bootstrap/machine_elf.hiaasm'}
    else:
        assert before_groups[name] == after_groups[name]

q = ast.parse(after['tools/qualify_hia_machine_elf.py'])
pins = next(ast.literal_eval(node.value) for node in q.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'MODULE_SOURCE_PINS' for target in node.targets))
assert all(base['files'][name]['sha256'] == value for name, value in pins.items())

files = {}
diffs = []
for name, raw in sorted(after.items()):
    if name.endswith('.py'):
        ast.parse(raw)
    before = base['files'][name] if name in existing else None
    files[name] = {'before': before, 'after': {**meta(raw), 'utf8': raw.decode()},
                   'matches_tested_7e9_overlay': raw == base64.b64decode(overlay['files'][name]['base64'])}
    target = OUT / 'source' / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    target.chmod(0o644)
    diffs.extend(difflib.unified_diff((before['utf8'] if before else '').splitlines(True),
        raw.decode().splitlines(True), 'a/' + name if before else '/dev/null', 'b/' + name))
assert len(files) == 15
patch = ''.join(diffs)
(OUT / 'f8-owner.patch').write_text(patch)

packet = {'schema': 'hia.machine-elf.f8-narrow-owner-delta.v1',
    'base_commit': base['commit'], 'base_tree': base['tree'],
    'status': 'AUTHORED_F8_REBASE_WITH_STATIC_CHECKS_NOT_MACHINE_TESTED',
    'tested_development_source': {'base': overlay['base_commit'], 'overlay_sha256': sha(overlay_raw),
        'run': 43178050672, 'job': 131046985965, 'component': 37, 'original_callers': 51,
        'result': 'PASS; this result is not transferred to the combined f8 source'},
    'files': files, 'patch': patch, 'shared_dependencies_preserved': shared_records,
    'rebase_choices': ['Keep f8 target rejection before native admission.',
        'Pin Code first, then ELF, in the existing complete emission scope.',
        'Preserve checker digest and every f8 Code identity input; append ELF source and selected identity.',
        'Preserve all five existing installed asset groups; add only the ELF HIA asset.',
        'Keep all original 51 caller source pins unchanged; exact f8 bytes match them.'],
    'static_checks': {'python_ast_parsed': True, 'unrelated_backend_definitions_unchanged': True,
        'changed_backend_definitions': changed_defs, 'original_writer_prefix_preserved': True,
        'all_five_original_resource_groups_preserved': True, 'shared_ast_equivalent_to_tested': True},
    'registration_followup': {'generator': 'python -B -m tools.generate_hia_machine_elf',
        'asset': 'examples/hia_bootstrap/machine_elf.hiaasm',
        'source_files_additions': [name for name in files if not name.startswith('hepta/') and name != 'MANIFEST.in'],
        'source_selector': 'tests.test_hia_machine_elf_native.MachineElfSourceTests',
        'native_selectors': ['tests.test_hia_machine_elf_native.MachineElfNativeTests',
            'tests.test_hia_machine_elf_native.MachineElfBoundaryTests',
            'tests.test_hia_machine_elf_protocol.MachineElfProtocolTests'],
        'cold_env': 'HEPTA_HIA_MACHINE_ELF_COLD_REPORT',
        'evidence_env': 'HEPTA_HIA_MACHINE_ELF_FIXTURE_EVIDENCE',
        'development_env_to_clear_in_cold': 'HEPTA_HIA_MACHINE_ELF_DEVELOPMENT_MANIFEST',
        'runtime_selector': 'HEPTA_HIA_MACHINE_ELF_MANIFEST',
        'builder': 'python -B -m tools.build_hia_machine_elf --compiler COMPILER --cold-report CURRENT_COMPLETE_COLD --output EXCLUSIVE_OUTPUT',
        'original_caller_qualification': 'python -B -m tools.qualify_hia_machine_elf --cold-report CURRENT_COMPLETE_COLD --output EXCLUSIVE_OUTPUT',
        'generated_records': ['docs/HIA_SELFHOST_CORE_SUPPORT.json', 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json',
            'docs/HIA_NATIVE_REWRITE_INVENTORY.json']},
    'current_source_cold_qualified': False, 'whole_stack_qualified': False,
    'defaults_changed': False, 'live_worker_changed': False, 'old_stack_deleted': False}
raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode()
(OUT / 'SOURCE-PACKET.json').write_bytes(raw)
compressed = zlib.compress(raw, 9)
wrapper = {'schema': 'hia.zlib-base64-bytes.v1', 'raw_bytes': len(raw), 'raw_sha256': sha(raw),
    'compressed_bytes': len(compressed), 'compressed_sha256': sha(compressed),
    'zlib_base64': base64.b64encode(compressed).decode()}
(OUT / 'SOURCE-PACKET.wrapper.json').write_text(json.dumps(wrapper, indent=2, sort_keys=True) + '\n')
summary = {'paths': 15, 'new_paths': 10, 'existing_paths': 5, 'source_packet': meta(raw),
           'wrapper': meta((OUT / 'SOURCE-PACKET.wrapper.json').read_bytes()),
           'patch': meta(patch.encode()), 'static_checks': packet['static_checks'],
           'scope': packet['status'], 'shared_files_overwritten': False,
           'caller_pins_changed': False, 'source_root': str(OUT / 'source')}
(OUT / 'SUMMARY.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
print(json.dumps(summary, sort_keys=True), flush=True)
