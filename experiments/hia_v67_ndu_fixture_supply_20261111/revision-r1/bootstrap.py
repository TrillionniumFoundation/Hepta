"""Create a single private supply root and exec the unchanged outer guardian."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import types


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload-sha256', required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read((1 << 20) + 1)
    if len(raw) > 1 << 20 or sha256(raw).hexdigest() != args.payload_sha256:
        raise RuntimeError('exact complete launch payload is required')
    def no_duplicates(items):
        value = {}
        for name, item in items:
            if name in value:
                raise RuntimeError('duplicate launch JSON key')
            value[name] = item
        return value
    payload = json.loads(raw, object_pairs_hook=no_duplicates)
    if set(payload) != {'schema', 'request', 'files'} or payload['schema'] != 'hia.v67.ndu-supply-bootstrap.v1':
        raise RuntimeError('unknown bootstrap payload')
    request = payload['request']
    expected_names = {'bootstrap.py', 'common.py', 'driver.py', 'producer.py', 'verify_terminal.py',
                      'source-inputs.json', 'guardian.py', 'process_owner_impl.py', 'workflow_process.py'}
    if (request.get('schema') != 'hia.v67.ndu-supply-launch.v1' or request.get('frozen') is not True
            or set(payload['files']) != expected_names or set(request['control_files']) != expected_names):
        raise RuntimeError('complete frozen controller files required')
    for name, content in payload['files'].items():
        if type(content) is not str or sha256(content.encode()).hexdigest() != request['control_files'][name]:
            raise RuntimeError('controller byte pin differs: ' + name)
    if sys.argv[0] == '-c':
        if sys.orig_argv.count('-c') != 1:
            raise RuntimeError('ambiguous Python source argv')
        executing = sys.orig_argv[sys.orig_argv.index('-c') + 1].encode()
    else:
        executing = Path(__file__).read_bytes()
    if sha256(executing).hexdigest() != request['control_files']['bootstrap.py']:
        raise RuntimeError('executed bootstrap is not the reviewed source')
    # All helper bytes are already externally payload-bound before evaluating
    # definitions. common.py does no I/O or process launch on import.
    helper = types.ModuleType('fixed_supply_common')
    helper.__file__ = '/home/qian-qi/he26v67fixturesr1/control/common.py'
    exec(compile(payload['files']['common.py'], helper.__file__, 'exec'), helper.__dict__)
    root = helper.ROOT
    require = helper.require
    cfg = json.loads(payload['files']['source-inputs.json'], object_pairs_hook=no_duplicates)
    require(root == Path('/home/qian-qi/he26v67fixturesr1')
            and request.get('root') == str(root) and cfg.get('root') == str(root)
            and request.get('stable_key') == helper.KEY == cfg.get('stable_key')
            and cfg.get('head') == helper.HEAD and cfg.get('tree') == helper.TREE
            and cfg.get('source') == str(helper.SOURCE)
            and cfg.get('limits') == {'controller_seconds': 3600, 'build_seconds': 900,
                'workflow_seconds': 960, 'cargo_jobs': 2,
                'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000},
            'fixed source/root/key/supply bounds differ')
    require(all(request['control_files'][name] == expected for name, expected in helper.FIXED_HELPERS.items()),
            'unchanged original guardians and helper required')
    require(sys.version_info[:3] == (3, 14, 4) and Path(sys.executable).resolve() == helper.PYTHON.resolve(),
            'formal Python differs')
    python_pin, _ = helper.stable_file(helper.PYTHON, helper.PYTHON_SHA, executable=True,
                                      resolve=True, independent=False)
    require(not os.path.lexists(root), 'new supply root exists; reconcile original operation, never replay')
    require(not any(p.is_symlink() for p in (root.parent, *root.parent.parents)), 'symlink ancestor refused')
    home = root.parent.lstat()
    require(stat.S_ISDIR(home.st_mode) and home.st_uid == os.geteuid()
            and not stat.S_IMODE(home.st_mode) & 0o022, 'operator home ownership/mode differs')
    capacity = os.statvfs(root.parent)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
            'original storage/inode minimum not satisfied')
    identities = {python_pin['resolved']: helper.PYTHON_SHA}
    for path, digest in cfg['old_inputs'].items():
        helper.stable_file(path, digest)
        identities[path] = digest
    os.umask(0o077)
    root.mkdir(mode=0o700, exist_ok=False)
    for name in ('control', 'guard'):
        (root / name).mkdir(mode=0o700, exist_ok=False)
    for name, content in payload['files'].items():
        helper.create(root / 'control' / name, content.encode())
        identities[str(root / 'control' / name)] = request['control_files'][name]
    request_raw = helper.wire(request)
    helper.create(root / 'control/request.json', request_raw)
    identities[str(root / 'control/request.json')] = sha256(request_raw).hexdigest()
    helper.create(root / 'control/bootstrap-stdin.json', raw)
    identities[str(root / 'control/bootstrap-stdin.json')] = sha256(raw).hexdigest()
    guardian_request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 3600,
        'command': [str(helper.PYTHON), '-B', str(root / 'control/driver.py'),
                    '--request-sha256', sha256(request_raw).hexdigest()],
        'cwd': str(root), 'source_identities': identities}
    guardian_raw = helper.wire(guardian_request)
    helper.create(root / 'guard/request.json', guardian_raw)
    helper.create(root / 'launch-intent.json', helper.wire({
        'schema': 'hia.v67.ndu-supply-intent.v1', 'status': 'GUARDIAN_EXEC_REQUESTED_NOT_READY',
        'root': str(root), 'stable_key': helper.KEY, 'head': helper.HEAD, 'tree': helper.TREE,
        'payload_sha256': args.payload_sha256, 'request_sha256': sha256(request_raw).hexdigest(),
        'guardian_request_sha256': sha256(guardian_raw).hexdigest(),
        'control_files': request['control_files'], 'limits': cfg['limits'],
        'qualification_executed': False, 'whole_native_delivery_qualified': False,
        'old_formal_hold_replayed': False, 'old_targets_mutated': False,
        'hard_sigkill_host_loss_cleanup_claimed': False,
        'remaining_acceptance': 'actual three fixtures AND natural outer guardian with no kill/overflow/error',
    }))
    for directory in (root / 'control', root / 'guard', root, root.parent):
        helper.sync_directory(directory)
    os.environ.clear()
    os.environ.update(helper.environment(cfg))
    print(json.dumps({'stage': 'NDU_SUPPLY_GUARDIAN_EXEC', 'root': str(root),
                      'stable_key': helper.KEY, 'controller_seconds': 3600}), flush=True)
    os.execv(str(helper.PYTHON), [str(helper.PYTHON), '-B', str(root / 'control/guardian.py'),
        '--config', str(root / 'guard/request.json'), '--config-sha256', sha256(guardian_raw).hexdigest(),
        '--implementation', str(root / 'control/process_owner_impl.py')])


if __name__ == '__main__':
    main()
