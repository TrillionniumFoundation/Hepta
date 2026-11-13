"""Preserve the incomplete authoring attempt and prepare a fresh successor."""
from pathlib import Path
import hashlib
import json
import os

OLD = Path(__file__).resolve().parent
NEW = Path('/workspace/scratch/e26ed3e2edcf/native-cli-c-runtime-lifetime-plan-r4b')
assert not NEW.exists()
NEW.mkdir(mode=0o700)


def put(relative, raw):
    path = NEW / relative
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


for path in sorted((OLD / 'reference').rglob('*')):
    if path.is_file():
        put(path.relative_to(OLD), path.read_bytes())
for name in ('build_runtime_mapping_revision.py', 'freeze_revision_r4.py',
             'source_controls.py', 'BUILD-AUTHORING-RETURN.original.json',
             'MAP-METADATA-AUTHORING-RETURN.original.json', 'FREEZE-AUTHORING-RETURN.original.json'):
    put(Path('history/mode-authoring-hold-r4') / name, (OLD / name).read_bytes())
builder = (OLD / 'build_runtime_mapping_revision.py').read_text()
assert builder.count('import hashlib\n') == 1
builder = builder.replace('import hashlib\n', 'import hashlib\nimport os\nimport stat\n', 1)
before = "        with path.open('xb') as file:\n            file.write(raw)\n"
after = ("        with path.open('xb') as file:\n"
         "            os.fchmod(file.fileno(), stat.S_IMODE((OLD / 'source' / relative).stat().st_mode))\n"
         "            file.write(raw)\n")
assert builder.count(before) == 1
builder = builder.replace(before, after, 1)
put('build_runtime_mapping_revision.py', builder.encode())
freeze = (OLD / 'freeze_revision_r4.py').read_text()
freeze = freeze.replace('native-cli-c-runtime-lifetime-plan-r4', 'native-cli-c-runtime-lifetime-plan-r4b')
freeze = freeze.replace('native-cli-c-runtime-lifetime-actual-r4', 'native-cli-c-runtime-lifetime-actual-r4b')
freeze = freeze.replace('native-cli-runtime-layout-source-controls-r4', 'native-cli-runtime-layout-source-controls-r4b')
freeze = freeze.replace('hia-cli-json-c-runtime-lifetime-local312-r4', 'hia-cli-json-c-runtime-lifetime-local312-r4b')
put('freeze_revision_r4.py', freeze.encode())
put('source_controls.py', (OLD / 'source_controls.py').read_bytes())
note = {'schema': 'hia.cli-json.authoring-mode-correction.v1',
        'original_namespace': str(OLD), 'new_namespace': str(NEW),
        'old_status': 'AUTHORING_HOLD_BEFORE_POLICY_OR_REQUEST',
        'actual_cause': 'New source files were 0644, while both original source rows require 0600.',
        'correction': 'Use the original source mode with fchmod on the new exclusive file descriptor before writing.',
        'old_source_bytes_or_modes_not_modified': True,
        'product_source_algorithm_unchanged': True,
        'product_owner_C_HIA_native_or_source_controls_executed': False,
        'new_request_not_replay_of_old_execution': True}
put('history/mode-authoring-hold-r4/CORRECTION.json', (json.dumps(note, sort_keys=True, indent=2) + '\n').encode())
print(json.dumps({'status': 'FRESH_AUTHORING_SUCCESSOR_PREPARED', 'root': str(NEW),
                  'builder_sha256': hashlib.sha256(builder.encode()).hexdigest(),
                  'native_or_source_controls_executed': False}))
