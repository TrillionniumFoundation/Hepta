from pathlib import Path
import ast
import hashlib
import json
import shutil
import struct
import subprocess
import sys

ROOT = Path('/tmp/hepta-6ddb-recovery-589c')
BASE = '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375'
HISTORY = '6ddb7d4bda799befdaf9c92f5e9586c71042cda9'
BUILD = Path('/workspace/scratch/589c0a6dd85b/runtime-6ddb-wire-development-589c')
CONTROL = Path('/workspace/scratch/589c0a6dd85b/runtime-6ddb-wire-controls-589c')
DEST = ROOT / 'docs/qualification/hia-json-wire-cache-recovery-20261127-589c'
sys.path.insert(0, str(ROOT))
from tools.read_hia_cold_native_transport import decode_original_process_streams


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def save(name, value):
    (DEST / name).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


assert git('rev-parse', 'HEAD').decode().strip() == BASE
changed = git('diff', '--name-only').decode().splitlines()
assert set(changed) == {
    'examples/hia_bootstrap/json_wire.hepta', 'hepta/hia_json_wire_native.py',
    'tests/test_hia_json_wire_cache.py', 'tests/test_hia_selfhost_chain.py',
    'tools/generate_hia_json_wire.py', 'tools/hia_selfhost_chain_allocator_child.py',
    'tools/qualify_hia_selfhost.py',
}
assert not git('ls-files', '--others', '--exclude-standard')
controls = json.loads((CONTROL / 'receipt.json').read_bytes())
assert controls['tests'] == 25 and not any(controls[x] for x in ('errors', 'failures', 'skipped'))
assert controls['source_before'] == controls['source_after']
for path, expected in controls['source_after'].items():
    assert pin((ROOT / path).read_bytes()) == expected
DEST.mkdir(parents=True, exist_ok=False)

for source, target in [
    (CONTROL / 'receipt.json', 'controls.json'), (CONTROL / 'stdout', 'controls.stdout'),
    (CONTROL / 'stderr', 'controls.stderr'),
    (CONTROL / 'qualification-serialization-control.json', 'qualification-serialization-control.json'),
    (Path('/tmp/runtime-6ddb-wire-controls-589c.py'), 'run_component_controls.py'),
]:
    shutil.copyfile(source, DEST / target)

sources = [
    (BUILD, 'json-wire', 'examples/hia_bootstrap/json_wire.hepta', 'wire-build'),
    (CONTROL / 'cache-fixture/format', 'agent-binary64-format',
     'examples/hia_bootstrap/agent_binary64_format.hepta', 'format-build'),
]
native = []
for directory, label, source_path, subdir in sources:
    target = DEST / subdir
    target.mkdir()
    for name in ['manifest.json', 'build.json', *[label + suffix for suffix in (
        '.request.json', '.receipt.json', '.stdout.log', '.stderr.log',
        '.process-streams.json', '.process.stdout.zlib', '.process.stderr.zlib')]]:
        path = directory / name
        if path.exists():
            shutil.copyfile(path, target / name)
    request_raw = (directory / (label + '.request.json')).read_bytes()
    request = json.loads(request_raw)
    receipt = json.loads((directory / (label + '.receipt.json')).read_bytes())
    original, streams = decode_original_process_streams(
        (directory / (label + '.process-streams.json')).read_bytes(), request_raw,
        {name: (directory / (label + '.process.' + name + '.zlib')).read_bytes()
         for name in ('stdout', 'stderr')}, label=label)
    assert original['returncode'] == 0 and original['timed_out'] is False
    assert not streams['stderr']
    source = (ROOT / source_path).read_bytes()
    compiler = Path(request['image']).read_bytes()
    assert pin(source)['sha256'] == request['source_sha256']
    assert pin(compiler)['sha256'] == request['image_sha256']
    assert Path(request['source']).read_bytes() == source
    raw = streams['stdout']
    assert raw[:8] == b'HIAOBR02'
    assert len(raw) == 24 + len(source) + request['capacity'] + request['workspace_size']
    returned, elapsed = struct.unpack_from('<2Q', raw, 8)
    assert returned == receipt['result_u64'] and elapsed == receipt['native_elapsed_ns']
    assert returned >> 32 == 0 and 0 < returned <= request['capacity']
    assert raw[24:24 + len(source)] == source
    output = raw[24 + len(source):24 + len(source) + request['capacity']]
    assert output == Path(request['output']).read_bytes()
    image = (directory / (label + '.image.bin')).read_bytes()
    assert image == output[:returned]
    assert pin(output)['sha256'] == receipt['output_sha256']
    native.append({'label': label, 'source_path': source_path, 'source': pin(source),
        'compiler': pin(compiler), 'observer_sha256': request['observer_sha256'],
        'retained_original_streams': subdir + '/' + label + '.process-streams.json',
        'raw_stdout': pin(raw), 'source_echo_equal': True,
        'full_output_equal': True, 'produced_image': pin(image),
        'produced_image_is_exact_prefix_of_original_stdout_output': True,
        'native_elapsed_ns': elapsed, 'returncode': 0, 'timed_out': False})
save('original-native-stream-readback.json', {
    'schema': 'hepta.hia.wire-cache-original-stream-readback.v1',
    'decoder_source': pin((ROOT / 'tools/read_hia_cold_native_transport.py').read_bytes()),
    'scope': 'data-only readback of actual development compiler processes',
    'builds': native, 'current_source_cold_qualified': False})

# Prove current v9 authoring/partial-trap helpers survive the historical merge.
generator = 'tools/generate_hia_json_wire.py'
old_py = git('show', BASE + ':' + generator).decode()
new_py = (ROOT / generator).read_text()


def python_function(source, name):
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(nodes) == 1
    return ast.get_source_segment(source, nodes[0])


def constant(source, name):
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.Assign)
             and any(isinstance(n, ast.Name) and n.id == name for n in node.targets)]
    assert len(nodes) == 1
    return ast.literal_eval(nodes[0].value)


preserved = {}
for name in ('source_program', 'document'):
    before, after = python_function(old_py, name), python_function(new_py, name)
    assert before == after
    preserved[name] = pin(after.encode())
for name in ('normalize', 'emit', 'escaped'):
    before = python_function(constant(old_py, 'SOURCE'), name)
    after = python_function(constant(new_py, 'SOURCE'), name)
    assert before == after
    preserved['SOURCE.' + name] = pin(after.encode())

incoming = []
for path in sorted(Path('/tmp/hepta-6ddb-review-589c/incoming').rglob('*.py')):
    relative = path.relative_to('/tmp/hepta-6ddb-review-589c/incoming').as_posix()
    raw = path.read_bytes()
    assert raw == git('show', HISTORY + ':' + relative)
    incoming.append({'path': relative, 'git_blob': blob(raw), **pin(raw),
        'selection': ('retain current v9 source without changes' if 'generate_hia_sha256_stream' in relative
                      else 'retain current complete qualifier; transplant only two compact JSON output calls'
                      if relative == 'tools/qualify_hia_selfhost.py'
                      else 'historical protocols plus exact current v9 helpers and source construction'
                      if relative == generator else 'restore historical file byte for byte')})
    if relative not in (generator, 'tools/qualify_hia_selfhost.py', 'tools/generate_hia_sha256_stream.py'):
        assert (ROOT / relative).read_bytes() == raw

inventory = {}
index = git('ls-files', '--stage', '-z').split(b'\0')
for item in index:
    if not item:
        continue
    header, path_raw = item.split(b'\t', 1)
    mode, original_blob, stage = header.decode().split()
    path = path_raw.decode()
    physical = ROOT / path
    if not physical.is_file():
        continue
    raw = physical.read_bytes()
    observed_blob = blob(raw)
    if path not in changed:
        assert observed_blob == original_blob, path
    inventory[path] = {**pin(raw), 'git_blob': observed_blob,
                       'base_git_blob': original_blob, 'mode': mode}
save('source-readback.json', {
    'schema': 'hepta.hia.component-checkout-source-readback.v1',
    'base_commit': BASE, 'base_tree': git('rev-parse', BASE + '^{tree}').decode().strip(),
    'scope': 'post-test complete readback of every physically present tracked file; sparse absent files remain bound by base Git tree; not a retroactive before-execution capture',
    'during_execution_before_after_pins': 'controls.json',
    'all_non_changed_present_files_equal_base_git_blobs': True,
    'changed_paths': changed, 'present_files': inventory,
    'absent_tracked_paths': [item.split(b'\t', 1)[1].decode() for item in index
                             if item and item.split(b'\t', 1)[1].decode() not in inventory],
})

test_methods = {}
for path in ('tests/test_hia_json_wire_cache.py', 'tests/test_hia_json_wire_native.py',
             'tests/test_hia_selfhost_chain.py'):
    for cls in ast.parse((ROOT / path).read_text()).body:
        if isinstance(cls, ast.ClassDef):
            test_methods[path + ':' + cls.name] = {
                'executed_in_this_receipt': path.replace('/', '.')[:-3] + '.' + cls.name in controls['classes'],
                'methods': [node.name for node in cls.body if isinstance(node, ast.FunctionDef)
                            and node.name.startswith('test_')]}
save('recovery-decisions.json', {
    'schema': 'hepta.hia.historical-wire-feature-recovery.v1',
    'base_commit': BASE, 'historical_feature_commit': HISTORY,
    'incoming_files': incoming, 'preserved_exact_authoring_functions': preserved,
    'current_sha256_stream_generator_and_HIA_unchanged': True,
    'current_native_contract_and_authority_unchanged': True,
    'generated_json_wire_is_inside_frozen_1278_source_authority': True,
    'new_matching_source_freeze_and_full_native_qualification_required': True,
    'native_protocols': ['HIAWIR04 immutable built-in scalar summary cache',
                         'HIAWIR05 adjacent key-then-value CHILD transport'],
    'custom_observers_and_renderers_keep_uncached_profiles': True,
    'allocator_child_disables_and_reads_back_dumpability_before_fixture_load': True,
    'qualifier_only_two_compact_serialization_calls': 'qualification-serialization-control.json',
    'test_methods': test_methods,
    'controls': {'tests': 25, 'failures': 0, 'errors': 0, 'skips': 0},
    'whole_stack_native': False, 'installed_complete_release_qualified': False,
})

(DEST / 'README.md').write_text('''# Historical JSON wire cache recovery

This restores the missing HIAWIR04 immutable-summary cache, HIAWIR05 adjacent
key/value CHILD transport, and allocator-child dumpability setup from
`6ddb7d4bda799befdaf9c92f5e9586c71042cda9` onto the canonical source
`06d21f6032d7b3a946b1d6581a13c5cfd5fa4375`.

The current v9 word-load generator, ordered partial writes, current SHA-256
stream implementation, native-v2 contract, native transport/capture, and
release qualification logic remain in place. The qualifier changes only its
two JSON output calls to compact separators. The retained serialization control
checks complete source/AST preservation apart from those parameters and exact
parsed-field equality using an existing report solely as a data fixture.

## Actual verification

The original 19 cache tests, four source/Core VM tests, and two allocator-child
boundary tests all passed: 25 run, zero failures, zero errors, zero skips.
The native cache image and binary64 formatter were actually compiled from these
sources by historical native B1 `acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9`
through the original 1107-byte native observer. This is explicit development
component verification. The original C dumpability witness is an external test
fixture; it is not a HIA compiler or product implementation.

`controls.json` records the actual before/after source pins and original test
outcome. `controls.stderr` retains every test name and result. The two build
directories retain original requests, process-state records and complete zlib
stdout/stderr. `original-native-stream-readback.json` verifies their actual
decoded HIAOBR02 frames, unchanged source echoes and full output, including the
exact produced-image bytes. Those images are recoverable from the retained raw
stdout; no reconstructed process response replaces the original evidence.

`source-readback.json` is the post-test readback of all physically present
tracked files, with every unchanged path verified against the base Git blob.
It is not an invented before-execution whole-source capture. The source pin
inventory and preservation decisions bind the selective historical recovery.

## Remaining qualification

The generated `json_wire.hepta` is a member of the frozen native source authority
and has changed. The old F/D qualification cannot cover this candidate. A new
matching source freeze and full native cold/installed qualification are required.
The unchanged 13 `WireNativeTests` and seven `ChainSourceTests` were not rerun in
this targeted receipt; they are explicitly listed as unexecuted in the method
inventory. Complete installed release qualification and whole-stack native
closure remain false. No production activation or legacy retirement occurred.
''')

# Archive the actual observer script itself and pin every retained evidence byte.
shutil.copyfile(__file__, DEST / 'archive_original_evidence.py')
evidence = {path.relative_to(DEST).as_posix(): pin(path.read_bytes())
            for path in sorted(DEST.rglob('*')) if path.is_file()}
save('evidence-pins.json', {'schema': 'hepta.hia.wire-recovery-evidence-pins.v1',
    'files': evidence, 'scope': 'exact retained original bytes and labelled derived readbacks'})

# Final physical rereads are bounded to this new isolated worktree and originals.
for path, expected in inventory.items():
    assert pin((ROOT / path).read_bytes()) == {key: expected[key] for key in ('bytes', 'sha256')}
for path, expected in evidence.items():
    assert pin((DEST / path).read_bytes()) == expected
print(json.dumps({'archive': str(DEST), 'files': len(evidence) + 1,
    'bytes': sum(path.stat().st_size for path in DEST.rglob('*') if path.is_file()),
    'present_source_files': len(inventory), 'native_builds': len(native),
    'controls': 25, 'whole_stack_native': False}, sort_keys=True))
