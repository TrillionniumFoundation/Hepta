"""Invoke the unchanged exact608 NDU builder once for one fresh fixture."""
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback

from common import (BUILDER_SHA, HEAD, PROFILES, PYTHON, PYTHON_SHA, ROOT, SOURCE, TREE,
                    config, create, environment, load_exact, require, stable_file,
                    sync_directory, validate_receipt, wire)


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in PROFILES, 'one fixed profile required')
    profile = sys.argv[1]
    cfg = config()
    pin = cfg['profiles'][profile]
    output, target = ROOT / 'fixtures' / profile, ROOT / 'targets' / profile
    report_path = ROOT / 'steps' / profile / 'producer.json'
    require(not any(os.path.lexists(p) for p in (output, target, report_path)),
            'fresh fixture paths already exist; never replay this producer')
    require(Path(sys.executable).resolve() == PYTHON.resolve() and sys.version_info[:3] == (3, 14, 4),
            'formal Python identity differs')
    stable_file(PYTHON, PYTHON_SHA, resolve=True, executable=True, independent=False)
    expected_environment = environment(cfg, target=target)
    require(dict(os.environ) == expected_environment, 'producer environment is not the fixed whitelist')
    report = {'schema': 'hia.v67.ndu-fixture-producer.v1', 'status': 'HOLD', 'profile': profile,
              'head': HEAD, 'tree': TREE, 'source': str(SOURCE), 'builder_sha256': BUILDER_SHA,
              'output': str(output), 'target': str(target), 'started_unix_ns': time.time_ns(),
              'environment': expected_environment, 'original_builder_modified': False,
              'qualification_executed': False, 'production_activation': False}
    try:
        stable_file(SOURCE / 'tools/build_hia_ndu_bridge.py', BUILDER_SHA)
        for tool in ('cargo', 'rustc'):
            tool_pin = next(p for p in cfg['fixed_tools'] if p['name'] == tool)
            stable_file(tool_pin['path'], tool_pin['sha256'], executable=True,
                        resolve=True, independent=False)
        adapter = SOURCE / pin['adapter']
        actual = {p.relative_to(adapter).as_posix(): stable_file(p)[0]['sha256']
                  for p in sorted(adapter.rglob('*')) if p.is_file()}
        require(actual == pin['adapter_files'], 'complete current adapter bytes differ')
        module = load_exact('exact_608_ndu_builder', SOURCE / 'tools/build_hia_ndu_bridge.py', BUILDER_SHA)
        receipt = module.build(Path(cfg['upstream']), output, cargo=cfg['tools']['cargo'],
                               adapter=adapter, release=pin['release'])
        report['fixture'] = validate_receipt(cfg, profile, receipt)
        # Preserve the original builder files verbatim. Durability does not
        # require changing modes or rewriting its generated receipt.
        for path in [*sorted(p for p in output.rglob('*') if p.is_file()),
                     Path(report['fixture']['binary'])]:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for directory in sorted((p for p in output.rglob('*') if p.is_dir()),
                                key=lambda p: len(p.parts), reverse=True):
            sync_directory(directory)
        for directory in (output, output.parent, Path(report['fixture']['binary']).parent, target, target.parent):
            sync_directory(directory)
        report['status'] = 'FRESH_ORIGINAL_BUILDER_COMPLETED_NOT_QUALIFICATION'
    except BaseException as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error),
                             'traceback': traceback.format_exc()}
        raise
    finally:
        report['ended_unix_ns'] = time.time_ns()
        create(report_path, wire(report))
        sync_directory(report_path.parent)
        print(json.dumps({'profile': profile, 'status': report['status'],
                          'report': str(report_path)}), flush=True)


if __name__ == '__main__':
    main()
