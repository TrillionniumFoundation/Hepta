from hashlib import sha256
import importlib
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path('/tmp/hepta-native-component-custody-20261127-2ac5')
OUT = Path('/tmp/root-component-custody-28-regression-2ac5')
COMPILER = Path('/tmp/hia-custody-development-component-2ac5/development-B1.flat')
sys.path.insert(0, str(ROOT))
OUT.mkdir(mode=0o700)
start = time.monotonic()
compiler_raw = COMPILER.read_bytes()
assert sha256(compiler_raw).hexdigest() == 'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
fixture_raw = (ROOT / 'tests/fixtures/hia_component_authoring_successor_v1.json').read_bytes()
fixture = json.loads(fixture_raw)
builders = sorted(fixture['files'])
originals, candidates, errors = {}, {}, []

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def run_builder(name, lane):
    original = subprocess.check_output(['git', 'show', fixture['predecessor_commit'] + ':' + name], cwd=ROOT)
    current = (ROOT / name).read_bytes()
    declared = fixture['files'][name]
    assert pin(original) == {'bytes': declared['old_bytes'], 'sha256': declared['old_sha256']}
    assert pin(current) == {'bytes': declared['new_bytes'], 'sha256': declared['new_sha256']}
    module = importlib.import_module(name[:-3].replace('/', '.'))
    if lane == 'original':
        namespace = {'__file__': str(ROOT / name), '__name__': 'original_component_builder', '__package__': 'tools'}
        exec(compile(original, str(ROOT / name) + '@060ce11', 'exec'), namespace)
        factory = namespace['build']
        assert tuple(module.INPUTS) == ('tools/hia_component_input_custody.py', *namespace['INPUTS'])
    else:
        factory = module.build
    directory = OUT / lane / Path(name).stem
    manifest_path = factory(directory, COMPILER, development=True)
    manifest = json.loads(manifest_path.read_bytes())
    build = json.loads((directory / 'build.json').read_bytes())
    assert build['scope'] == 'DEVELOPMENT_COMPONENT' and build['source_manifest'] is None
    assert build['cold_report_sha256'] is None and 'component_input_custody' not in build
    image = (directory / manifest['image_path']).read_bytes()
    assert sha256(image).hexdigest() == manifest['image_sha256']
    full_outputs = list(directory.glob('*.output.bin'))
    assert len(full_outputs) == 1
    return {'image': pin(image), 'full_native_output': pin(full_outputs[0].read_bytes()),
            'source_sha256': manifest['source_sha256'], 'compiler_sha256': manifest['compiler_sha256'],
            'manifest_path': str(manifest_path), 'builder_source': pin(original if lane == 'original' else current)}

for lane, records in [('original', originals), ('candidate', candidates)]:
    (OUT / lane).mkdir(mode=0o700)
    for name in builders:
        try:
            records[name] = run_builder(name, lane)
            print(json.dumps({'lane': lane, 'builder': name, 'status': 'PASS'}), flush=True)
        except BaseException:
            error = {'lane': lane, 'builder': name, 'traceback': traceback.format_exc()}
            errors.append(error)
            print(json.dumps(error), flush=True)
    (OUT / (lane + '-sealed-results.json')).write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')
    if lane == 'original':
        original_seal = (OUT / 'original-sealed-results.json').read_bytes()
        if errors:
            break

comparisons = []
if not errors:
    assert (OUT / 'original-sealed-results.json').read_bytes() == original_seal
    for name in builders:
        fields = ('image', 'full_native_output', 'source_sha256', 'compiler_sha256')
        comparisons.append({'builder': name, 'equal': all(originals[name][f] == candidates[name][f] for f in fields)})
unchanged = COMPILER.read_bytes() == compiler_raw and (ROOT / 'tests/fixtures/hia_component_authoring_successor_v1.json').read_bytes() == fixture_raw
passed = not errors and len(comparisons) == 28 and all(r['equal'] for r in comparisons) and unchanged
report = {'schema': 'hepta.hia.component-authoring-28-development-regression.v1',
          'status': 'PASS' if passed else 'FAIL', 'scope': 'EXPLICIT_DEVELOPMENT_BUILDER_OUTPUT_REGRESSION',
          'original_commit': fixture['predecessor_commit'], 'fixture': pin(fixture_raw),
          'compiler': pin(compiler_raw), 'original_outputs_sealed_before_candidates': not errors,
          'comparisons': comparisons, 'errors': errors, 'inputs_unchanged': unchanged,
          'original_builds': originals, 'candidate_builds': candidates,
          'wall_seconds': time.monotonic() - start,
          'matching_native_cold_qualified': False, 'original_caller_suites_qualified': False,
          'whole_native_delivery_qualified': False}
(OUT / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ('status', 'scope', 'wall_seconds')}), flush=True)
raise SystemExit(0 if passed else 1)
