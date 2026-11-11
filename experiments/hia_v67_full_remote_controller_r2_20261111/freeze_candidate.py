"""Bind a new formal controller to independently retrieved actual supply files.

This local preparation writes no remote path and executes no product or build.
It requires complete original report, guardian and separate terminal acceptance;
an incomplete supply cannot be replaced by a declared READY string.
"""
import argparse
import ast
from hashlib import sha256
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/hia-v67-full-remote-controller-20261111')
SUPPLY = Path('/home/qian-qi/he26v67fixturesr1')
OLD_ADAPTER_SHA = 'ca5dfabafce068e1a05a1c121d60bae66a35f5472f5c9a323d9d32155d909136'
EXPECTED_HEAD = '608157e52b0b94e0d294f6b99c4e809869f183aa'
EXPECTED_TREE = 'e7c29a60796a1a78946a2c667aa80df86529e532'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def read(path):
    raw = Path(path).read_bytes()
    return json.loads(raw), {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def assignment(source, name):
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == name for x in node.targets):
            return node, ast.literal_eval(node.value)
    raise RuntimeError('required literal assignment absent: ' + name)


def natural_guardian(value, seconds):
    life = value.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    events = life.get('events')
    require(value.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and value.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and value.get('external_controller_seconds') == seconds
            and value.get('input_identity_preserved') is True
            and value.get('source_identities_before') == value.get('source_identities_after')
            and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('returncode') == 0 and life.get('timed_out') is False
            and life.get('exit_observed_before_deadline') is True
            and life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and life.get('interrupted_signals') == [] and not life.get('owner_error')
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and type(events) is list and bool(events)
            and all(e.get('kind') in {'qualification_started', 'owned_child_observed',
                        'qualification_exit_observed', 'owned_child_reaped'} for e in events),
            'actual supply outer guardian was not natural and fully reaped')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--guardian', type=Path, required=True)
    parser.add_argument('--acceptance', type=Path, required=True)
    args = parser.parse_args()
    require(not any((HERE / n).exists() for n in ('request.frozen.json', 'payload.frozen.json', 'launch.frozen.json')),
            'this candidate was already frozen; preserve it instead of overwriting')
    report, report_pin = read(args.report)
    guardian, guardian_pin = read(args.guardian)
    accepted, acceptance_pin = read(args.acceptance)
    natural_guardian(guardian, 3600)
    require(report.get('schema') == 'hia.v67.ndu-fixture-supply.v1'
            and report.get('status') == 'THREE_FIXTURES_READY_PENDING_OUTER_GUARDIAN_NOT_QUALIFICATION'
            and report.get('head') == EXPECTED_HEAD and report.get('tree') == EXPECTED_TREE
            and report.get('root') == str(SUPPLY)
            and report.get('qualification_executed') is False
            and report.get('whole_native_delivery_qualified') is False
            and all(report.get(k) is True for k in ('source_preserved', 'pinned_inputs_preserved', 'upstream_preserved'))
            and not report.get('failure') and not report.get('final_snapshot_errors'),
            'actual complete three-fixture supply report has not passed its own gates')
    require(accepted.get('schema') == 'hia.v67.ndu-fixture-supply-acceptance.v1'
            and accepted.get('status') == 'THREE_FIXTURES_READY_NOT_TEST_PASS'
            and accepted.get('head') == EXPECTED_HEAD and accepted.get('tree') == EXPECTED_TREE
            and accepted.get('root') == str(SUPPLY) and accepted.get('qualification_executed') is False
            and accepted.get('whole_native_delivery_qualified') is False,
            'independent original terminal acceptance is required')
    for field, pin, suffix in (('report', report_pin, 'report.json'),
                               ('outer_guardian', guardian_pin, 'guard/guardian.json')):
        require(accepted[field]['path'] == str(SUPPLY / suffix)
                and all(accepted[field].get(k) == v for k, v in pin.items()),
                'acceptance does not bind the retrieved original ' + field)
    fields = ('receipt', 'receipt_sha256', 'binary', 'binary_sha256',
              'cargo_lock_sha256', 'builder_sha256', 'upstream_commit')
    require(set(report['fixtures']) == set(accepted['fixtures']) == {'ranking', 'raw', 'dynamic'},
            'exactly three actual fixture records required')
    fixtures = {}
    for name in ('ranking', 'raw', 'dynamic'):
        row = {k: accepted['fixtures'][name][k] for k in fields}
        require(all(report['fixtures'][name].get(k) == v for k, v in row.items()),
                'report and actual terminal acceptance differ: ' + name)
        fixtures[name] = row

    request = json.loads((HERE / 'request.pending.json').read_text())
    require(request['source']['commit'] == EXPECTED_HEAD and request['source']['tree'] == EXPECTED_TREE,
            'frozen product source differs')
    driver_source = (HERE / 'driver.py').read_text()
    _, controls = assignment(driver_source, 'SUPPLY_CONTROL_FILES')
    _, supply_request_sha = assignment(driver_source, 'SUPPLY_REQUEST_SHA256')
    spec = {'schema': 'hia.v67.full-qualification-fixture-supply-pins.v1',
            'root': str(SUPPLY), 'stable_key': report['stable_key'], 'head': EXPECTED_HEAD,
            'tree': EXPECTED_TREE, 'builder_sha256': report['builder_sha256'],
            'report': dict(report_pin, path=str(SUPPLY / 'report.json')),
            'outer_guardian': dict(guardian_pin, path=str(SUPPLY / 'guard/guardian.json')),
            'fixtures': fixtures}
    request['fixture_supply'] = spec
    readonly = request['readonly_inputs']
    readonly.update({str(SUPPLY / 'control' / name): digest for name, digest in controls.items()})
    readonly[str(SUPPLY / 'control/request.json')] = supply_request_sha
    readonly.update({spec[k]['path']: spec[k]['sha256'] for k in ('report', 'outer_guardian')})
    readonly.update({row['receipt']: row['receipt_sha256'] for row in fixtures.values()})
    readonly.update({
        '/home/qian-qi/he26v67r1/preparation.json': 'e711e98894126825bbef9e70e170a6491a7302e5d81cd2e72bd4eed215d16be2',
        '/home/qian-qi/he26v67r1/guard/guardian.json': '2dc57458b09a064be0fcfe23a6e4bd191513d670d66ecefd725b220ede0ede0a',
        '/home/qian-qi/he26v67r1/p/preparation.json': 'af5f7f29642e279132ec93a42315891d0a3aa0aaff370568b70d497023a6ff73',
        '/home/qian-qi/he26v67r1/source-materialization.json': '7451e4517a2a00731f8019924127179ff1a4a952e005636b3352edef00efa7e7',
    })

    original = (BASE / 'dependencies/prepare_v67_cargo_environment.py').read_bytes()
    require(sha256(original).hexdigest() == OLD_ADAPTER_SHA, 'original r1 adapter bytes differ')
    text = original.decode()
    node, config = assignment(text, 'CONFIG')
    hints = json.loads((BASE / 'dependencies/desktop-v67-input-hints.json').read_text())
    hints['revision'] = 'NEW_V67_R2_THREE_FRESH_FIXTURES_NOT_RECOVERED_C127'
    hints['set'].update({
        'HEPTA_NDU_BRIDGE': fixtures['ranking']['binary'],
        'HEPTA_NDU_BUILD': str(Path(fixtures['ranking']['receipt']).parent),
        'HEPTA_RAW_MODEL_BRIDGE': fixtures['raw']['binary'],
        'HEPTA_RAW_MODEL_BUILD': fixtures['raw']['receipt'],
        'HEPTA_DYNAMIC_POLICY_BINARY': fixtures['dynamic']['binary'],
        'HEPTA_DYNAMIC_POLICY_MANIFEST': fixtures['dynamic']['receipt'],
    })
    hints_raw = wire(hints)
    config['hints'], config['hints_sha256'] = hints['set'], sha256(hints_raw).hexdigest()
    for pin in config['fixture_receipts']:
        if pin['profile'] in fixtures:
            row = fixtures[pin['profile']]
            pin.update(path=row['receipt'], sha256=row['receipt_sha256'],
                       origin_report_sha256=report_pin['sha256'])
    lines = text.splitlines(keepends=True)
    adapter = ''.join(lines[:node.lineno - 1]) + 'CONFIG = ' + repr(config) + '\n' + ''.join(lines[node.end_lineno:])
    adapter = adapter.replace('"revision": "new-private-cargo-v67-r1"',
                              '"revision": "new-private-cargo-v67-r2-three-fresh-fixtures"')
    ast.parse(adapter)
    adapter_raw = adapter.encode()
    adapter_sha = sha256(adapter_raw).hexdigest()
    updated = {'dependencies/prepare_v67_cargo_environment.py': adapter_raw,
               'dependencies/desktop-v67-input-hints.json': hints_raw}
    for name in ('driver.py', 'bootstrap.py'):
        text = (HERE / name).read_text()
        require(text.count(OLD_ADAPTER_SHA) == 1, 'draft original adapter pin differs: ' + name)
        updated[name] = text.replace(OLD_ADAPTER_SHA, adapter_sha).encode()
        ast.parse(updated[name])
    files = {}
    for name in request['control_files']:
        relative = name if (HERE / name).is_file() else 'dependencies/' + name
        files[name] = updated.get(relative, (HERE / relative).read_bytes()).decode()
    request['control_files'] = {name: sha256(raw.encode()).hexdigest() for name, raw in files.items()}
    request['frozen'], request['pending'] = True, []
    payload = wire({'schema': 'hia.v67.full-qualification-bootstrap-payload.v1', 'request': request, 'files': files})
    launch = json.loads((BASE / 'launch.frozen.json').read_text())
    launch.update(idempotency_key=request['stable_key'], stdin=payload.decode(),
                  args=['-I', '-S', '-B', '-c', files['bootstrap.py'], '--payload-sha256', sha256(payload).hexdigest()])
    raw_request = wire(request)
    raw_launch = wire(launch)
    evidence = {'schema': 'hia.v67.full-r2-freeze-inputs.v1',
                'actual_supply_report': dict(report_pin, local_path=str(args.report)),
                'actual_supply_guardian': dict(guardian_pin, local_path=str(args.guardian)),
                'actual_supply_acceptance': dict(acceptance_pin, local_path=str(args.acceptance)),
                'product_source_unchanged': True, 'remote_mutation_requested': False,
                'original_r1_hold_evidence_commit': 'ae2c29d40ea37e80aaf80943b4e706b931d34fc6',
                'remaining_before_dispatch': ['independent final exact-byte review', 'canonical preexecution publication/readback']}
    original_dir = HERE / 'supply-originals'
    original_dir.mkdir(mode=0o700, exist_ok=False)
    for name, original in (('report.json', args.report), ('guardian.json', args.guardian),
                           ('acceptance.json', args.acceptance)):
        raw = original.read_bytes()
        with (original_dir / name).open('xb') as stream:
            stream.write(raw)
        require((original_dir / name).read_bytes() == raw, 'actual supply original copy differs')
    for name, raw in updated.items():
        (HERE / name).write_bytes(raw)
    for name, raw in {'request.frozen.json': raw_request, 'payload.frozen.json': payload,
                      'launch.frozen.json': raw_launch, 'FREEZE-INPUTS.json': wire(evidence)}.items():
        with (HERE / name).open('xb') as stream:
            stream.write(raw)
    print(json.dumps({'status': 'FROZEN_LOCAL_NOT_DISPATCHED',
                      'request_sha256': sha256(raw_request).hexdigest(),
                      'payload_sha256': sha256(payload).hexdigest(),
                      'launch_sha256': sha256(raw_launch).hexdigest(), 'files': len(files)}))


if __name__ == '__main__':
    main()
