"""Read-only conjunction after the original outer guardian has terminated."""
import json
from pathlib import Path

from common import (BUILDER_SHA, HEAD, KEY, PROFILES, ROOT, SCHEMA, TREE, config,
                    PYTHON, natural_guardian, read_json, require, validate_receipt)


def verify():
    cfg = config()
    report, report_pin = read_json(ROOT / 'report.json')
    guardian, guardian_pin = read_json(ROOT / 'guard/guardian.json')
    request, request_pin = read_json(ROOT / 'control/request.json')
    require(natural_guardian(guardian) and guardian.get('cwd') == str(ROOT)
            and guardian.get('external_controller_seconds') == cfg['limits']['controller_seconds']
            and guardian.get('command') == [str(PYTHON), '-B', str(ROOT / 'control/driver.py'),
                '--request-sha256', request_pin['sha256']]
            and all(guardian.get('source_identities_before', {}).get(str(ROOT / 'control' / name)) == digest
                    for name, digest in request['control_files'].items()),
            'outer guardian is not the exact natural fully reaped completion')
    require(report.get('schema') == SCHEMA
            and report.get('status') == 'THREE_FIXTURES_READY_PENDING_OUTER_GUARDIAN_NOT_QUALIFICATION'
            and report.get('head') == HEAD and report.get('tree') == TREE
            and report.get('builder_sha256') == BUILDER_SHA and report.get('stable_key') == KEY
            and report.get('qualification_executed') is False
            and report.get('whole_native_delivery_qualified') is False
            and set(report.get('fixtures', {})) == set(PROFILES), 'actual supply report is incomplete')
    for prefix, key in (('source', 'source_preserved'), ('inputs', 'pinned_inputs_preserved'),
                        ('upstream', 'upstream_preserved')):
        before = report[prefix + '_before']
        after = report[prefix + '_after']
        before_value, _ = read_json(before['path'], before['sha256'])
        after_value, _ = read_json(after['path'], after['sha256'])
        require(report.get(key) is True and before_value == after_value,
                'original before/after custody is not preserved: ' + prefix)
    fixtures = {}
    for profile in PROFILES:
        row = report['fixtures'][profile]
        inner, _ = read_json(row['guardian']['path'], row['guardian']['sha256'])
        require(natural_guardian(inner) and inner.get('cwd') == str(ROOT)
                and inner.get('external_controller_seconds') == cfg['limits']['build_seconds']
                and inner.get('command') == [str(PYTHON), '-B', str(ROOT / 'control/producer.py'), profile],
                'exact profile did not complete naturally: ' + profile)
        receipt, _ = read_json(row['receipt'], row['receipt_sha256'])
        observed = validate_receipt(cfg, profile, receipt)
        require(all(row.get(key) == value for key, value in observed.items()),
                'live actual receipt/binary differs from the supply record')
        fixtures[profile] = observed
    return {'schema': 'hia.v67.ndu-fixture-supply-acceptance.v1',
            'status': 'THREE_FIXTURES_READY_NOT_TEST_PASS', 'head': HEAD, 'tree': TREE,
            'builder_sha256': BUILDER_SHA, 'root': str(ROOT), 'stable_key': KEY,
            'report': report_pin, 'outer_guardian': guardian_pin, 'fixtures': fixtures,
            'qualification_executed': False, 'whole_native_delivery_qualified': False,
            'old_formal_hold_preserved': True}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
