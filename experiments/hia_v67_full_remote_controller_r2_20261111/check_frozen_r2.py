"""Local exact-byte and input-rejection controls; no remote/product execution."""
import ast
import copy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/hia-v67-full-remote-controller-20261111')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def literal(path, name):
    for n in ast.parse(path.read_bytes()).body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.literal_eval(n.value)
    raise AssertionError(name)


def main():
    sys.path[:0] = [str(HERE), str(HERE / 'dependencies')]
    driver = load('exact_r2_driver', HERE / 'driver.py')
    bootstrap = load('exact_r2_bootstrap', HERE / 'bootstrap.py')
    request = json.loads((HERE / 'request.frozen.json').read_bytes())
    payload_raw = (HERE / 'payload.frozen.json').read_bytes()
    payload = json.loads(payload_raw)
    launch = json.loads((HERE / 'launch.frozen.json').read_bytes())
    original = json.loads((BASE / 'request.frozen.json').read_bytes())
    assert payload['request'] == request
    assert driver.validate_request(request) is request
    assert bootstrap.validate_payload(payload) is request or bootstrap.validate_payload(payload) == request
    assert launch['stdin'].encode() == payload_raw
    assert launch['args'] == ['-I', '-S', '-B', '-c', payload['files']['bootstrap.py'],
                              '--payload-sha256', sha256(payload_raw).hexdigest()]
    assert launch['idempotency_key'] == request['stable_key']
    old_launch = json.loads((BASE / 'launch.frozen.json').read_bytes())
    for key in set(launch) - {'idempotency_key', 'stdin', 'args'}:
        assert launch[key] == old_launch[key]
    assert request['root'] == '/home/qian-qi/he26v67r2'
    assert request['stable_key'] == 'hia-e26e-desktop-v67-608157e5-full-qualification-r2'
    for key in ('source', 'artifact', 'runtime', 'limits', 'scope'):
        assert request[key] == original[key]
    file_rows = {}
    for name, digest in request['control_files'].items():
        path = HERE / name if (HERE / name).is_file() else HERE / 'dependencies' / name
        raw = path.read_bytes()
        assert sha256(raw).hexdigest() == digest
        assert payload['files'][name].encode() == raw
        file_rows[name] = {'path': str(path), 'bytes': len(raw), 'sha256': digest}
    assert len(file_rows) == 13
    allowed_changes = {'driver.py', 'bootstrap.py', 'verify_terminal.py',
                       'prepare_v67_cargo_environment.py', 'desktop-v67-input-hints.json'}
    for name in set(file_rows) - allowed_changes:
        assert request['control_files'][name] == original['control_files'][name]
    old_adapter = BASE / 'dependencies/prepare_v67_cargo_environment.py'
    new_adapter = HERE / 'dependencies/prepare_v67_cargo_environment.py'
    before, after = literal(old_adapter, 'CONFIG'), literal(new_adapter, 'CONFIG')
    for key in set(before) - {'hints_sha256', 'hints', 'fixture_receipts'}:
        assert before[key] == after[key]
    changed_hints = {key for key in before['hints'] if before['hints'][key] != after['hints'][key]}
    assert changed_hints == {'HEPTA_NDU_BRIDGE', 'HEPTA_NDU_BUILD', 'HEPTA_RAW_MODEL_BRIDGE',
                            'HEPTA_RAW_MODEL_BUILD', 'HEPTA_DYNAMIC_POLICY_BINARY', 'HEPTA_DYNAMIC_POLICY_MANIFEST'}
    before_receipts = {row['profile']: row for row in before['fixture_receipts']}
    after_receipts = {row['profile']: row for row in after['fixture_receipts']}
    assert set(before_receipts) == set(after_receipts) and len(after_receipts) == 6
    for name in ('finite', 'recursive', 'stream'):
        assert before_receipts[name] == after_receipts[name]
    for name in ('ranking', 'raw', 'dynamic'):
        fixture = request['fixture_supply']['fixtures'][name]
        assert after_receipts[name]['path'] == fixture['receipt']
        assert after_receipts[name]['sha256'] == fixture['receipt_sha256']
        assert after_receipts[name]['origin_report_sha256'] == request['fixture_supply']['report']['sha256']
    def behavior(path, normalize=False):
        text = path.read_text()
        if normalize:
            text = text.replace('new-private-cargo-v67-r2-three-fresh-fixtures', 'new-private-cargo-v67-r1')
        return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}
    assert behavior(old_adapter) == behavior(new_adapter, normalize=True)
    assert sha256((HERE / 'dependencies/desktop-v67-input-hints.json').read_bytes()).hexdigest() == after['hints_sha256']
    assert json.loads((HERE / 'dependencies/desktop-v67-input-hints.json').read_bytes())['set'] == after['hints']
    cases = [
        ('old_request_not_admitted', lambda r: r.clear() or r.update(original)),
        ('missing_supplied_profile', lambda r: r['fixture_supply']['fixtures'].pop('raw')),
        ('wrong_binary_location', lambda r: r['fixture_supply']['fixtures']['raw'].__setitem__('binary', '/tmp/unbound-binary')),
        ('old_supply_guardian_not_pinned', lambda r: r['readonly_inputs'].pop(r['fixture_supply']['outer_guardian']['path'])),
        ('supply_common_bytes_not_pinned', lambda r: r['readonly_inputs'].__setitem__('/home/qian-qi/he26v67fixturesr1/control/common.py', '0' * 64)),
        ('cold_budget_increase', lambda r: r['limits'].__setitem__('cold_seconds', 181)),
    ]
    results = []
    for label, mutate in cases:
        bad = copy.deepcopy(request)
        mutate(bad)
        try:
            driver.validate_request(bad)
        except (RuntimeError, KeyError, TypeError) as error:
            results.append({'case': label, 'rejected': True, 'type': type(error).__name__, 'message': str(error)})
        else:
            raise AssertionError(label)
    report = {'schema': 'hia.v67.full-r2-frozen-controller-controls.v1', 'status': 'PASS',
              'actual_control_files': file_rows, 'request': {'bytes': (HERE / 'request.frozen.json').stat().st_size,
                'sha256': sha256((HERE / 'request.frozen.json').read_bytes()).hexdigest()},
              'payload': {'bytes': len(payload_raw), 'sha256': sha256(payload_raw).hexdigest()},
              'positive_frozen_request_and_payload_admitted': True, 'negative_request_controls': results,
              'original_source_artifact_runtime_limits_and_scope_equal': True,
              'original_eight_fixed_dependency_bytes_equal': True,
              'adapter_behavior_ast_equal_except_explicit_revision_literal': True,
              'only_six_candidate_hint_settings_and_three_receipts_changed': True,
              'remote_access_or_product_execution': False,
              'supply_verifier_executed_locally': False,
              'supply_verifier_will_read_actual_remote_records_inside_formal_guardian': True}
    output = HERE / 'FINAL-INTEGRITY.json'
    with output.open('xb') as stream:
        stream.write((json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({'status': 'PASS', 'positive': 1, 'negative': len(results),
                      'file_count': len(file_rows), 'output': str(output),
                      'sha256': sha256(output.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
