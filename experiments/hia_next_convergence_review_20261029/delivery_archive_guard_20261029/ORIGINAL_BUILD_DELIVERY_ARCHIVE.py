"""Package retained observations without retagging their original source identities."""
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timezone
import json
import os
import stat
import sys
import zipfile

root = Path('/workspace/scratch/220b9d034358/Hepta')
tmp = Path('/tmp')
output = Path(sys.argv[1])
phase = sys.argv[2] if len(sys.argv) > 2 else 'completed-work-checkpoint-before-v8'
assert not output.exists(), 'Refuse overwriting an earlier delivery archive'
sources = {}

def add(path, archive_name):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refuse unreviewed symlink ' + str(path))
    if path.name.lower().endswith(('.gguf', '.gguf.partial', '.safetensors')):
        raise ValueError('Model weights are outside the evidence archive: ' + str(path))
    if not path.is_file():
        raise ValueError('Missing retained file ' + str(path))
    if archive_name in sources:
        assert sources[archive_name] == path
    sources[archive_name] = path

directories = [
    'hepta-next-legacy-development', 'hepta-next-legacy-formal-01',
    'hepta-next-legacy-irpgo-probe-01', 'hepta-next-legacy-irpgo-development-01',
    'hepta-next-legacy-irpgo-formal-01', 'hepta-next-legacy-rust-shadow-formal-01',
    'hepta-next-safety-development-evidence', 'hepta-next-safety-scalar-formal-01',
    'hepta-next-safety-scalar-formal-02', 'hepta-next-ndu-activation-formal-01',
    'hepta-next-ndu-formal-build-01',
    'hepta-next-agent-v5-controls-01', 'hepta-next-agent-v5-controls-02',
    'hepta-next-agent-v5-qwen1_5b-01', 'hepta-next-agent-v5-qwen1_5b-03',
    'hepta-next-agent-v5-qwen1_5b-04', 'hepta-next-agent-v5-qwen7b-01',
    'hepta-next-agent-v5-into-typecheck-01',
    'hepta-next-agent-v6-profile-controls-01', 'hepta-next-agent-v6-qwen7b-01',
]
patterns = ['hepta-next-agent-structured-controls-*']
if phase != 'completed-work-checkpoint-before-v8':
    patterns += ['hepta-next-agent-v7-*', 'hepta-next-agent-v8-*',
                 'hepta-next-agent-v9-*', 'hepta-next-agent-v10-*']
for pattern in patterns:
    for p in tmp.glob(pattern):
        if p.is_dir():
            if (p / '.git').exists():
                raise ValueError('Use a source bundle instead of archiving a live checkout: ' + str(p))
            directories.append(p.name)
extra = tmp / 'hepta-next-delivery-extra-paths.json'
if extra.exists():
    for p in json.loads(extra.read_text()):
        path = Path(p)
        if path.is_dir():
            for child in path.rglob('*'):
                if child.is_file():
                    add(child, 'extra/' + path.name + '/' + str(child.relative_to(path)))
        else:
            add(path, 'extra/' + path.name)
for name in sorted(set(directories)):
    path = tmp / name
    assert path.is_dir(), name
    for child in sorted(path.rglob('*')):
        if child.is_file():
            add(child, 'raw/' + name + '/' + str(child.relative_to(path)))
for path in sorted(tmp.glob('hepta-next-*')):
    if phase == 'completed-work-checkpoint-before-v8' and path.name.startswith(('hepta-next-agent-v7-', 'hepta-next-agent-v8-')):
        continue
    if path.is_file() and (path.suffix in {'.log', '.json', '.bundle', '.hepta'}
                           or path.name.startswith('hepta-next-measured-sources-20261029.')
                           or path.name == 'hepta-next-ndu-prepared-evidence-20261029.tar.gz'):
        add(path, 'receipts/' + path.name)
for name in ('env.sh', 'execution-prerequisites-before.json', 'llvm-restoration.json',
             'rust-bootstrap.stdout', 'rust-bootstrap.stderr', 'llvm-bootstrap.stdout',
             'llvm-bootstrap.stderr', 'cargo-build.stdout', 'cargo-build.stderr',
             'cargo-fetch.stdout', 'cargo-fetch.stderr'):
    path = tmp / 'hepta-next-closure-20261028' / name
    if path.is_file():
        add(path, 'environment/' + name)
for name in ('docs/HIA_NEXT_SIX_OUTCOMES_20261029.md',
             'experiments/hia_next_closure/BLOCKERS_20261029.json',
             'experiments/hia_next_closure/CI_OBSERVATIONS_20261029.json',
             'experiments/hia_next_closure/SOURCE_PUBLICATIONS_20261029.json'):
    add(root / name, 'report/' + Path(name).name)
add(Path(__file__), 'reproduction/' + Path(__file__).name)

manifest = {'schema': 'hepta.hia.next-closure-delivery.v1',
            'snapshot_phase': phase,
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'preserve_original_experiment_source_identities': True,
            'all_blockers_closed': False,
            'no_model_weights_toolchains_or_cargo_cache_included': True,
            'files': []}
with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for name, path in sorted(sources.items()):
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
        assert (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), str(path)
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = before.st_mode << 16
        archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        manifest['files'].append({'archive_path': name, 'original_path': str(path),
                                  'bytes': len(data), 'mode': stat.S_IMODE(before.st_mode),
                                  'sha256': sha256(data).hexdigest()})
    archive.writestr('MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
    archive.writestr('README.txt',
        'HIA next closure evidence, 2026-10-29\n\n'
        'Read report/HIA_NEXT_SIX_OUTCOMES_20261029.md first.\n'
        'Each experiment retains its own source identity, environment and denominator.\n'
        'Negative and failed attempts are retained. These results do not establish every\n'
        'language, migration, performance, Agent or NDU claim.\n'
        'MANIFEST.json binds every included file. The nested NDU archive includes its\n'
        'own raw member inventory. Source bundles require the recorded public prerequisite.\n')
with zipfile.ZipFile(output) as archive:
    for row in manifest['files']:
        data = archive.read(row['archive_path'])
        assert len(data) == row['bytes'] and sha256(data).hexdigest() == row['sha256'], row['archive_path']
        assert stat.S_IMODE(archive.getinfo(row['archive_path']).external_attr >> 16) == row['mode'], row['archive_path']
receipt = {'path': str(output), 'bytes': output.stat().st_size,
           'sha256': sha256(output.read_bytes()).hexdigest(),
           'verified_member_files': len(manifest['files']),
           'uncompressed_member_bytes': sum(x['bytes'] for x in manifest['files']),
           'created_utc': manifest['created_utc']}
(tmp / 'hepta-next-final-delivery-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
