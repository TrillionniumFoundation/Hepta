"""Actual filesystem/socket controls for the revised external preparation tool."""
from hashlib import sha256
import argparse
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[3])
parser.add_argument('--preparation', type=Path,
                    default=Path(__file__).resolve().parents[1] / 'prepare_remote_qualification_v2.py')
parser.add_argument('--output', type=Path, default=Path(__file__).with_suffix('.json'))
args = parser.parse_args()
root = args.source
source = args.preparation
spec = importlib.util.spec_from_file_location('hia_external_preparation_v2', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
checks = {}

with tempfile.TemporaryDirectory(prefix='hqp-') as folder:
    base = Path(folder)

    def prepare(label, path):
        args = SimpleNamespace(source=root, prereq_root=base / 'old',
                               output=base / ('out-' + label), temporary_root=path,
                               candidate_environment=None)
        return module.Preparation(args)

    good = prepare('good', base / 'tmp')
    checks['fresh_owned_short_directory_actual_unix_round_trip'] = good.prepare_temporary()
    checks['environment_all_temp_names_bound'] = all(
        good.env[key] == str(base / 'tmp') for key in ('TMPDIR', 'TMP', 'TEMP'))
    owner = base / 'tmp/QUALIFICATION_TEMPORARY_OWNER.json'
    checks['owner_identity_bound'] = good.bindings[str(owner)] == sha256(owner.read_bytes()).hexdigest()

    git = base / 'project'
    (git / '.git').mkdir(parents=True)
    blocked = prepare('git', git / 'tmp')
    checks['git_ancestor_refused_without_creating_temp'] = (
        not blocked.prepare_temporary() and not (git / 'tmp').exists())

    long_path = base / ('long-' + 'x' * 50)
    blocked = prepare('long', long_path)
    checks['long_socket_root_refused_before_creation'] = (
        not blocked.prepare_temporary() and not long_path.exists())

    link = base / 'link'
    link.symlink_to(base / 'tmp', target_is_directory=True)
    blocked = prepare('link', link / 'new')
    checks['symlink_ancestor_refused'] = (
        not blocked.prepare_temporary() and not (base / 'tmp/new').exists())

    old = base / 'existing'
    old.mkdir()
    sentinel = old / 'sentinel'
    sentinel.write_bytes(b'original retained bytes')
    blocked = prepare('existing', old)
    try:
        blocked.prepare_temporary()
        checks['existing_directory_refused_without_changes'] = False
    except FileExistsError:
        checks['existing_directory_refused_without_changes'] = (
            sentinel.read_bytes() == b'original retained bytes'
            and list(old.iterdir()) == [sentinel])

record = {'schema': 'hepta.hia.external-temporary-preparation-controls.v1',
          'source_sha256': sha256(source.read_bytes()).hexdigest(), 'checks': checks,
          'qualification_or_whole_native_authority': False}
args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
print(json.dumps(record, sort_keys=True))
raise SystemExit(0 if checks and all(value is True for value in checks.values()) else 1)
