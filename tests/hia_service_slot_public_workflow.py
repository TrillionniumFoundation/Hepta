"""Actual original service transaction and replay paths with complete Slot control."""
from __future__ import annotations
import argparse
from collections import Counter
import ctypes
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from tests.hia_service_slot_controls import encoded, put, digest

def state(store):
    return {key: [dict(row) for row in store.db.execute(query)] for key, query in (
        ('requests', 'SELECT * FROM requests ORDER BY key'),
        ('artifacts', 'SELECT * FROM artifacts ORDER BY id'),
        ('costs', 'SELECT * FROM costs ORDER BY sequence'),
        ('slots', 'SELECT * FROM slots ORDER BY name'),
        ('versions', 'SELECT * FROM versions ORDER BY slot,generation'))}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--authority', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    authority = json.loads(args.authority.read_bytes())
    from hepta import hia_agent_service as api
    from hepta import hia_service_slot_native as native
    from hepta import hia_native_delivery as delivery
    from hepta.hia_native_helpers import native_helpers_scope
    from tests.test_hia_agent_native_tools import AgentToolCase
    from tools.build_hia_json_preflight import current_sources
    before = current_sources(); observations = []; counts = Counter()
    case = AgentToolCase('runTest')
    with native_helpers_scope(authority['bundle'], authority['bundle_sha256']):
        case.setUp()
        try:
            base, revised, baseline, built, receipts = case.build_pair()
            evaluation = case.session.evaluate(baseline, built, receipts=receipts)
            arguments = case.session.arguments(target_slot='public-slot',
                expected_current={'generation': '0', 'epoch': '0'},
                candidate_artifact=built['native_artifact'],
                evaluation_receipt=evaluation['evaluation_receipt'], verification_receipts=receipts)
            image = native.installed_service_slot(authority['manifests']['service'])
            entry = image._entry
            aliases = api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE
            def forbidden(*a, **k): raise AssertionError('selected public route executed retained body')
            def counted(source, size, output, capacity, buffer, extent):
                request = struct.unpack('<10Q', ctypes.string_at(source, size))
                result = entry(source, size, output, capacity, buffer, extent)
                counts[(request[5], request[1])] += 1
                return result
            image._entry = counted
            api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE = api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = forbidden
            try:
                for tool in ('hia_adopt', 'hia_rollback'):
                    before_state = state(case.service.store); counts.clear()
                    first = case.service.call(tool, arguments)
                    first_counts = [[list(k), v] for k, v in counts.items()]
                    assert first['status'] == 'completed', first
                    assert sum(counts.values()) > 0
                    after_first = state(case.service.store); counts.clear()
                    replay = case.service.call(tool, arguments)
                    after_replay = state(case.service.store)
                    assert replay == first and not counts and after_replay == after_first
                    assert len(after_first['requests']) == len(before_state['requests']) + 1
                    observations.append({'tool': tool, 'first': first, 'replay': replay,
                        'first_entries': first_counts, 'replay_handler_entries': sum(counts.values()),
                        'exact_replay': first == replay, 'database_unchanged': after_first == after_replay,
                        'before': before_state, 'after_first': after_first, 'after_replay': after_replay})
                    if tool == 'hia_adopt':
                        result = first['result']
                        arguments = case.session.arguments(target_slot='public-slot',
                            expected_current=result['current'],
                            retained_generation=result['previous']['generation'], reason='public replay')
            finally:
                image._entry = entry
                api._NATIVE_SERVICE_SLOT_ROLLBACK_REFERENCE, api._NATIVE_SERVICE_SLOT_ADOPT_REFERENCE = aliases
        finally: case.tearDown()
    after = current_sources()
    assert before == after and not delivery.custody_snapshot()
    put(args.output / 'report.json', {'schema': 'hepta.hia.service-slot-public-workflow.v1',
        'status': 'PASS', 'tools': ['hia_adopt', 'hia_rollback'], 'observations': observations,
        'source_before': before, 'source_after': after, 'authority_sha256': digest(args.authority),
        'original_transaction_connection_and_request_replay': True,
        'old_caller_gates_replaced': False})
    print(encoded({'status': 'PASS', 'tools': 2}).decode(), end='')

if __name__ == '__main__': main()
