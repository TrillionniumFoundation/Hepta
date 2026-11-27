from hashlib import sha1, sha256
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path('/tmp/hepta-evaluation-capture-recovery-589c')
BASE = '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375'
D = ROOT / 'docs/qualification/hia-evaluation-capture-recovery-20261127-589c'
REVIEW = Path('/tmp/hepta-evaluation-capture-review-589c')
CONTROL = Path('/tmp/runtime-evaluation-capture-controls-v2-589c')
BUILD = Path('/tmp/runtime-evaluation-capture-native-build-v2-589c')
sys.path.insert(0, str(ROOT))
from tools.read_hia_cold_native_transport import decode_original_process_streams

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
def copy(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    assert target.read_bytes() == source.read_bytes()
def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])

assert git('rev-parse', 'HEAD').decode().strip() == BASE
result = json.loads((CONTROL / 'receipt.json').read_bytes())
assert result['tests'] == 12 and not any(result[key] for key in ('errors', 'failures', 'skips'))
assert result['source_unchanged']
for name, expected in result['sources_after'].items():
    assert pin((ROOT / name).read_bytes()) == expected
for name in ('evidence-pins.json', 'result.json', 'source-readback.json', 'README.md'):
    path = D / name
    path.rename(D / ('initial-' + name))

aliases = {}
for source in sorted(CONTROL.rglob('*')):
    if not source.is_file():
        continue
    relative = source.relative_to(CONTROL).as_posix()
    original = D / 'controls-v1' / relative
    if original.is_file() and original.read_bytes() == source.read_bytes():
        aliases['controls-v2/' + relative] = {'retained_at': original.relative_to(D).as_posix(),
            'actual_new_output_byte_equal': True, **pin(source.read_bytes())}
    else:
        copy(source, D / 'controls-v2' / relative)
for path in Path('/tmp/runtime-evaluation-capture-provider-before-589c').iterdir():
    if path.is_file():
        copy(path, D / 'provider-before' / path.name)
for suffix in ('stdout', 'stderr'):
    copy(Path('/tmp/runtime-evaluation-capture-provider-before-589c.' + suffix),
         D / 'provider-before' / suffix)
for name in ('runtime-evaluation-capture-provider-before-589c.py',
             'runtime-evaluation-capture-build-v2-589c.py',
             'runtime-evaluation-capture-controls-v2-589c.py'):
    copy(Path('/tmp') / name, D / 'observers' / name)
copy(BUILD / 'construction-custody.json', D / 'construction-custody-v2.json')

native = []
old_readback = json.loads((D / 'native-stream-readback.json').read_bytes())
for component, label, source_name in (
    ('evaluation', 'evaluation', 'examples/hia_bootstrap/evaluation.hepta'),
    ('admission', 'native_build_admission', 'examples/hia_bootstrap/native_build_admission.hepta')):
    directory = BUILD / component
    for name in ('manifest.json', 'build.json', *[label + suffix for suffix in (
        '.request.json', '.receipt.json', '.stdout.log', '.stderr.log',
        '.process-streams.json', '.process.stdout.zlib', '.process.stderr.zlib')]):
        path = directory / name
        previous = D / 'native-build' / component / name
        if previous.is_file() and previous.read_bytes() == path.read_bytes():
            aliases['native-build-v2/' + component + '/' + name] = {
                'retained_at': previous.relative_to(D).as_posix(),
                'actual_new_output_byte_equal': True, **pin(path.read_bytes())}
        else:
            copy(path, D / 'native-build-v2' / component / name)
    request_raw = (directory / (label + '.request.json')).read_bytes()
    request = json.loads(request_raw)
    receipt = json.loads((directory / (label + '.receipt.json')).read_bytes())
    process, streams = decode_original_process_streams(
        (directory / (label + '.process-streams.json')).read_bytes(), request_raw,
        {key: (directory / (label + '.process.' + key + '.zlib')).read_bytes()
         for key in ('stdout', 'stderr')}, label=label)
    assert process['returncode'] == 0 and process['timed_out'] is False and not streams['stderr']
    raw = streams['stdout']
    source = (ROOT / source_name).read_bytes()
    assert raw[:8] == b'HIAOBR02' and len(raw) == 24 + len(source) + request['capacity'] + request['workspace_size']
    returned, elapsed = struct.unpack_from('<2Q', raw, 8)
    assert returned == receipt['result_u64'] and elapsed == receipt['native_elapsed_ns']
    assert returned >> 32 == 0 and 0 < returned <= request['capacity']
    assert raw[24:24 + len(source)] == source
    output = raw[24 + len(source):24 + len(source) + request['capacity']]
    image = (directory / (label + '.image.bin')).read_bytes()
    assert output == Path(request['output']).read_bytes() and image == output[:returned]
    old = next(row for row in old_readback['builds'] if row['component'] == component)
    assert pin(image) == old['produced_image'] and pin(source) == {k:v for k,v in old['source'].items() if k != 'path'}
    assert request['frame_sha256'] == old['reconstructed_input']['sha256']
    native.append({'component': component, 'original_stdout': pin(raw), 'produced_image': pin(image),
        'source': {'path': source_name, **pin(source)}, 'original_process_returncode': 0,
        'timed_out': False, 'native_elapsed_ns': elapsed, 'full_output_equal': True,
        'actual_new_image_equal_previous_component_image': True,
        'original_input_frame_hash_equal_previous_verified_reconstruction': True})
save(D / 'native-stream-readback-v2.json', {'schema': 'hepta.hia.evaluation-capture-native-readback.v2',
    'scope': 'fresh explicit development construction binds final guard source; no cold qualification',
    'builds': native})
save(D / 'retained-evidence-aliases.json', {'schema': 'hepta.hia.byte-equal-evidence-aliases.v1', 'files': aliases})

paths = git('diff', '--cached', '--name-only').decode().splitlines()
reverse = REVIEW / 'reverse-source-v2'
reverse.mkdir(exist_ok=False)
for name in paths:
    path = reverse / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((ROOT / name).read_bytes())
subprocess.run(['git', 'apply', '--reverse', str(REVIEW / 'product-v2.patch')], cwd=reverse, check=True)
reconstructed = {}
for name in paths:
    original = subprocess.run(['git', '-C', str(ROOT), 'show', BASE + ':' + name], capture_output=True)
    if original.returncode == 0:
        assert (reverse / name).read_bytes() == original.stdout
        reconstructed[name] = {'entire_original_file_reconstructed': True, 'original': pin(original.stdout)}
    else:
        assert not (reverse / name).exists()
        reconstructed[name] = {'new_path_removed': True}
    reconstructed[name]['current'] = pin((ROOT / name).read_bytes())
copy(REVIEW / 'product-v2.patch', D / 'source-v2.patch')
save(D / 'source-reconstruction-v2.json', {'base_commit': BASE,
    'patch': pin((REVIEW / 'product-v2.patch').read_bytes()), 'files': reconstructed})
inventory, absent = {}, []
for item in git('ls-files', '--stage', '-z').split(b'\0'):
    if not item:
        continue
    header, path_raw = item.split(b'\t', 1)
    mode, expected_blob, stage = header.decode().split()
    name = path_raw.decode()
    if not (ROOT / name).is_file():
        absent.append(name)
        continue
    raw = (ROOT / name).read_bytes()
    actual_blob = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    assert actual_blob == expected_blob, name
    inventory[name] = {**pin(raw), 'git_blob': actual_blob, 'mode': mode}
save(D / 'source-readback.json', {'schema': 'hepta.hia.component-checkout-source-readback.v1',
    'base_commit': BASE, 'scope': 'final post-test complete present indexed source readback; original during-execution captures retained independently',
    'files': inventory, 'absent_tracked_paths': absent, 'changed_paths': paths})
save(D / 'result.json', {'schema': 'hepta.hia.evaluation-capture-recovery.v2',
    'base_commit': BASE, 'historical_feature_commit': 'f587bda212423ae0ad6c4bf238ba32c855c3885a',
    'source_files': {name: pin((ROOT / name).read_bytes()) for name in paths},
    'final_controls': {'tests': 12, 'passed': 12, 'failed': 0, 'errors': 0, 'skipped': 0,
                       'elapsed_seconds': result['elapsed_seconds']},
    'custom_provider_controls': {'variants': 5, 'routes': 4, 'differential_combinations': 20,
        'unchanged_original_oracle': True, 'all_actual_exceptions_and_foreign_effects_equal': True},
    'original_111_foreign_scenarios_rerun_on_final_source': True,
    'four_actual_caller_routes_passed_on_final_source': True,
    'original_VM_and_native_full_state_controls': {
        'prior_component_revision_passed': True, 'cases': 6, 'repeated_on_final_guard_revision': False,
        'HIA_source_protocol_and_actual_images_byte_equal': True},
    'provider_counterexamples_retained': 'provider-before/receipt.json',
    'public_dict_subclass_boundary': 'original public call rejects non-JSON object before invoking its items protocol',
    'fast_path': 'ordinary object.__getattribute__, exact builtin arguments and reference dicts with exact str keys/values, and original build providers',
    'candidate_corruption_precedes_receipt_authority_error': True,
    'original_first_capture_and_spy_failures_retained': True,
    'custom_and_dynamic_providers_preserve_the_original_route': True,
    'scope': 'finite development component controls; capture adapter and opaque providers remain hosted',
    'whole_stack_rewritten_in_hia': False, 'all_input_equivalence_proved': False,
    'installed_complete_release_qualified': False, 'new_matching_source_qualification_required': True})
(D / 'README.md').write_text('''# Evaluation candidate observation recovery

The final source preserves the original candidate and receipt events. It captures
candidate bytes once, then applies the complete existing hosted or selected HIA
build-input policy to that same observation at the original receipt event.
Service, reference identity/content, creator process/thread and one consumption
are bound without mutating the service or Store.

The path is limited to ordinary object attribute access and exact built-in JSON
reference dictionaries. Dynamic providers, dict subclasses, argument subclasses
and other foreign protocols keep the original route. The real pre-guard
counterexamples are retained: a dynamic build provider was bypassed, and a dict
subclass acquired a new items call. The public object boundary already refuses
that subclass; its private provider domain is still preserved.

Final source passed 12 controls without skips, including all 111 original foreign
traces/first errors, 20 custom-domain comparisons against the unchanged frozen
oracle, four real caller routes, actual first-byte substitution refusals, and the
corrupt-candidate-before-invalid-receipt order. Both native owners were really
constructed again with the final source pins in explicit development mode.

Initial source and observer failures remain under their original labels. The
earlier independent VM and full native-buffer controls passed before the final
eligibility guard change; those are not represented as rerun. Their HIA source,
protocol and actual image bytes are unchanged. Identical raw output retained
once is mapped explicitly in retained-evidence-aliases.json.

The complete original reference AST and entire preexisting files reconstruct
by the exact reviewed reverse patch. Original fixture data and all assertions
remain. Native original stdout/stderr are retained in full compressed streams;
output images are recoverable from their exact prefixes. Separately labelled
reconstructed stdin frames match the actual original request hashes.

The capture adapter and opaque providers remain hosted. Current cold, installed
whole-release, all-input equivalence and full HIA replacement are false. The
original class's hosted-cold setup was not substituted; its control methods ran
with official explicit native development construction and source custody.
''')
copy(Path(__file__), D / 'observers/archive_evaluation_capture_v2.py')
pins = {path.relative_to(D).as_posix(): pin(path.read_bytes()) for path in sorted(D.rglob('*')) if path.is_file()}
save(D / 'evidence-pins.json', {'schema': 'hepta.hia.evaluation-capture-evidence-pins.v2', 'files': pins})
print(json.dumps({'evidence_files': len(pins) + 1, 'evidence_bytes': sum(path.stat().st_size for path in D.rglob('*') if path.is_file()),
                  'aliases': len(aliases), 'source_files': paths, 'result': pin((D / 'result.json').read_bytes())}, sort_keys=True))
