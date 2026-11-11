"""Three independent fresh fixture builds; no product qualification here."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import traceback

from common import (BUILDER_SHA, FIXED_HELPERS, HEAD, KEY, PROFILES, PYTHON, ROOT, SCHEMA,
                    SOURCE, TREE, config, create, environment, load_exact, natural_guardian,
                    pinned_inputs, read_json, require, source_state, stable_file,
                    sync_directory, upstream_state, validate_receipt, wire)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    request, _ = read_json(ROOT / 'control/request.json', args.request_sha256)
    cfg = config()
    require(request['stable_key'] == KEY and request['root'] == str(ROOT), 'request binding differs')
    for name, digest in request['control_files'].items():
        stable_file(ROOT / 'control' / name, digest)
    for name, digest in FIXED_HELPERS.items():
        require(request['control_files'][name] == digest, 'original helper changed')
    for name in ('t', 'fixtures', 'targets', 'steps', 'snapshots', 'old-originals'):
        (ROOT / name).mkdir(mode=0o700, exist_ok=False)
    os.environ.clear()
    os.environ.update(environment(cfg))
    workflow = load_exact('original_workflow', ROOT / 'control/workflow_process.py', FIXED_HELPERS['workflow_process.py'])
    report = {'schema': SCHEMA, 'status': 'HOLD', 'stable_key': KEY,
              'head': HEAD, 'tree': TREE, 'source': str(SOURCE), 'root': str(ROOT),
              'builder_sha256': BUILDER_SHA, 'fixtures': {}, 'steps': {},
              'started_unix_ns': time.time_ns(), 'limits': cfg['limits'],
              'outer_guardian': str(ROOT / 'guard/guardian.json'),
              'source_preserved': False, 'pinned_inputs_preserved': False, 'upstream_preserved': False,
              'old_formal_hold': cfg['original_formal_hold'], 'qualification_executed': False,
              'whole_native_delivery_qualified': False, 'production_activation': False,
              'cache_tree_immutability_claimed': False,
              'source_scope': 'all 3925 exact608 tracked leaves, raw Git blobs and modes before and after',
              'upstream_scope': 'read-only selected immutable Git commits; original builder independently verifies all consumed blobs',
              'fresh_builds_are_not_a_formal_qualification_retry': True}
    before_source = before_inputs = before_upstream = None
    def progress():
        print(json.dumps({'stage': 'NDU_FIXTURE_SUPPLY', 'completed': list(report['fixtures']),
                          'root': str(ROOT), 'status': report['status']}), flush=True)
    try:
        capacity = os.statvfs(ROOT)
        require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
                'original minimum storage/inodes not satisfied')
        require(ROOT.stat().st_dev == SOURCE.stat().st_dev == ROOT.parent.stat().st_dev,
                'supply output/source must remain on the same ordinary home filesystem')
        report['capacity_before'] = {'free_bytes': capacity.f_bavail * capacity.f_frsize,
                                    'free_inodes': capacity.f_favail, 'device': ROOT.stat().st_dev}
        before_inputs = pinned_inputs(cfg)
        report['inputs_before'] = create(ROOT / 'snapshots/inputs-before.json', wire(before_inputs))
        before_source = source_state()
        report['source_before'] = create(ROOT / 'snapshots/source-before.json', wire(before_source))
        before_upstream = upstream_state(cfg)
        report['upstream_before'] = create(ROOT / 'snapshots/upstream-before.json', wire(before_upstream))
        original = cfg['source_materialization_original']
        original_pin, raw = stable_file(original['path'], original['sha256'], collect=True)
        require(len(raw) == original['bytes'], 'original materialization report length differs')
        copied = create(ROOT / 'old-originals/source-materialization.original.json', raw)
        report['source_materialization_original_preservation'] = {'original': original_pin, 'copy': copied,
                                                                  'exact_bytes_equal': True}
        progress()
        for profile in PROFILES:
            step = ROOT / 'steps' / profile
            step.mkdir(mode=0o700)
            guard = step / 'guard'
            guard.mkdir(mode=0o700)
            target = ROOT / 'targets' / profile
            require(not os.path.lexists(target) and not os.path.lexists(ROOT / 'fixtures' / profile),
                    'new target or workspace already exists')
            identities = {str(ROOT / 'control' / name): digest for name, digest in request['control_files'].items()}
            identities[str(SOURCE / 'tools/build_hia_ndu_bridge.py')] = BUILDER_SHA
            for name, digest in cfg['profiles'][profile]['adapter_files'].items():
                identities[str(SOURCE / cfg['profiles'][profile]['adapter'] / name)] = digest
            for tool in ('cargo', 'rustc'):
                pin = next(p for p in cfg['fixed_tools'] if p['name'] == tool)
                identities[str(Path(pin['path']).resolve(strict=True))] = pin['sha256']
            inner = {'schema': 'hia-external-guardian-request.v1',
                     'controller_seconds': cfg['limits']['build_seconds'],
                     'command': [str(PYTHON), '-B', str(ROOT / 'control/producer.py'), profile],
                     'cwd': str(ROOT), 'source_identities': identities}
            raw = wire(inner)
            create(guard / 'request.json', raw)
            command = [str(PYTHON), '-B', str(ROOT / 'control/guardian.py'),
                       '--config', str(guard / 'request.json'), '--config-sha256', sha256(raw).hexdigest(),
                       '--implementation', str(ROOT / 'control/process_owner_impl.py')]
            step_report = workflow.run_workflow_step(command, cwd=ROOT, env=environment(cfg, target=target),
                stdout_path=step / 'guardian.stdout.log', stderr_path=step / 'guardian.stderr.log',
                receipt_path=step / 'workflow.json', seconds=cfg['limits']['workflow_seconds'])
            report['steps'][profile] = step_report
            require(step_report.get('status') == 'WORKFLOW_STEP_COMPLETED', 'profile workflow failed: ' + profile)
            inner_result, guard_pin = read_json(guard / 'guardian.json')
            require(natural_guardian(inner_result)
                    and inner_result.get('command') == inner['command']
                    and inner_result.get('cwd') == str(ROOT)
                    and inner_result.get('external_controller_seconds') == cfg['limits']['build_seconds']
                    and inner_result.get('source_identities_before') == identities,
                    'profile ownership was not the exact natural, fully reaped completion')
            producer, producer_pin = read_json(step / 'producer.json')
            require(producer.get('status') == 'FRESH_ORIGINAL_BUILDER_COMPLETED_NOT_QUALIFICATION',
                    'actual profile producer did not complete')
            receipt, _ = read_json(ROOT / 'fixtures' / profile / 'build-receipt.json')
            observed = validate_receipt(cfg, profile, receipt)
            require(producer.get('fixture') == observed, 'producer and independent receipt readback differ')
            report['fixtures'][profile] = dict(observed, guardian=guard_pin, producer=producer_pin)
            progress()
        require(set(report['fixtures']) == set(PROFILES), 'three actual fixtures required')
        report['status'] = 'THREE_FIXTURES_READY_PENDING_OUTER_GUARDIAN_NOT_QUALIFICATION'
    except BaseException as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error),
                             'traceback': traceback.format_exc()}
    finally:
        # Even a successful producer cannot keep READY after a failed or
        # changed final snapshot. Existing report/failure bytes remain explicit.
        for label, before, observe in (
            ('source', before_source, source_state),
            ('inputs', before_inputs, lambda: pinned_inputs(cfg)),
            ('upstream', before_upstream, lambda: upstream_state(cfg))):
            try:
                after = observe()
                report[label + '_after'] = create(ROOT / 'snapshots' / (label + '-after.json'), wire(after))
                unchanged = before is not None and after == before
                key = 'pinned_inputs_preserved' if label == 'inputs' else label + '_preserved'
                report[key] = unchanged
                require(unchanged, label + ' before/after custody differs')
            except BaseException as error:
                report.setdefault('final_snapshot_errors', {})[label] = repr(error)
                report['status'] = 'HOLD'
        if not all(report.get(k) is True for k in ('source_preserved', 'pinned_inputs_preserved', 'upstream_preserved')):
            report['status'] = 'HOLD'
        report['ended_unix_ns'] = time.time_ns()
        create(ROOT / 'report.json', wire(report))
        for directory in (ROOT / 'snapshots', ROOT / 'old-originals', ROOT / 'steps', ROOT):
            sync_directory(directory)
        progress()
    return 0 if report['status'] == 'THREE_FIXTURES_READY_PENDING_OUTER_GUARDIAN_NOT_QUALIFICATION' else 1


if __name__ == '__main__':
    raise SystemExit(main())
