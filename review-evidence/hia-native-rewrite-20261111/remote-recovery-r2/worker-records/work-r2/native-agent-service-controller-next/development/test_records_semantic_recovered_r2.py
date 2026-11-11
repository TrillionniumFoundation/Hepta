"""Unexecuted post-disconnection record semantic draft, not a recovered run."""
import json
from pathlib import Path
import resource
import sys
import time
import traceback
from types import SimpleNamespace

resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
from records_harness_recovered_r2 import Actual, capture, observed_value
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import wire
from hepta.hia_agent_contract import VERSION

OUT = Path(sys.argv[1])
actual = Actual(OUT)
rows = []
start = time.monotonic_ns()
summary = dict(status='INCOMPLETE', scope='NATIVE_RECORD_OWNER_WITH_PRIVATE_PUBLICATION_FIXTURES_NOT_NAMESPACE_OR_COMPLETE_WORKER',
               cpu_limit_seconds=90, address_space_bytes=1 << 30)


def check(label, request_id, payload, *, error=False, published=None, failed=None):
    calls = []
    if error:
        class ObservedError(ValueError):
            pass
        exc = ObservedError(payload['message'])
        ObservedError.__name__ = payload['type']
        for key, value in payload.items():
            if key not in ('message', 'type'):
                setattr(exc, key, value)
        def store_json(snapshot, kind):
            calls.append((snapshot, kind))
            if failed is not None:
                raise OSError(failed['message'])
            return published
        service = SimpleNamespace(store=SimpleNamespace(json=store_json))
        try:
            expected = HIAAgentService._error(service, request_id, exc)
            expected_failure = False
        except OSError:
            expected = failed
            expected_failure = True
        fixture = capture(failed if expected_failure else published, lease=882) if calls else None
    else:
        expected = dict(contract_version=VERSION, request_id=request_id, status='completed', result=payload)
        expected_failure = False
        fixture = None
    source = capture([request_id, payload], lease=881)
    result = actual.run(source, int(error), publication_fixture=fixture,
                        publication_failed=expected_failure, exact_growth=True, label=label)
    got = observed_value(result['graph'])
    assert got == expected, (label, got, expected)
    assert list(got) == list(expected), label
    if error and not expected_failure:
        assert list(got['error']) == list(expected['error']), label
    assert result['event'][1] == (3 if expected_failure else 0)
    assert result['publication_fixture_calls'] == len(calls)
    if calls:
        assert calls == [(payload['pending_slot_snapshot'], 'slot-snapshot')]
    try:
        expected_wire = dict(wire=wire(expected))
    except Exception as exc:
        expected_wire = dict(error=str(exc))
    actual_wire = actual.serialize(result['graph'], label=label + '/wire')
    assert actual_wire.get('wire') == expected_wire.get('wire') and actual_wire.get('error') == expected_wire.get('error'), (label, actual_wire, expected_wire)
    row = dict(case=label, status='PASS', publication_fixture_calls=len(calls), namespace_effect_performed=False,
               publication_failure=expected_failure, grows=result['grows'], event=result['event'],
               source=actual.save(source), result=result['result'],
               expected_wire=actual.save(expected_wire['wire']) if 'wire' in expected_wire else expected_wire)
    rows.append(row)
    with (OUT / 'cases.jsonl').open('a') as handle:
        handle.write(json.dumps(row, sort_keys=True) + '\n')
    print(json.dumps(dict(case=label, status='PASS'), sort_keys=True), flush=True)
    return result, got


try:
    values = [None, False, True, 0, -1, 2**80, 0.0, -0.0, 1.25, '', '雪🙂', [], {},
              {'accepted': True, 'ref': {'id': 'abc', 'sha256': 'a' * 64}},
              [None, True, 2**120, 'x', {'order': ['b', 'a']}]]
    for index, value in enumerate(values):
        check('success-' + str(index), 'r-' + 'a' * 64, value)
    shared = ['alias', {'payload': 1}]
    result, got = check('success-alias', shared, {'a': shared, 'b': shared})
    assert got['request_id'] is got['result']['a'] is got['result']['b']
    base = dict(message='original rejection', type='ValueError')
    check('defaults', 'unadmitted-123', base, error=True)
    for key in ('code', 'phase', 'retry_action', 'details_artifact', 'pending_slot_snapshot'):
        for index, value in enumerate((None, False, 0, '', [], {}, 'value', 1.5)):
            payload = dict(base, **{key: value})
            published = {'id': 'issued-snapshot', 'sha256': 'b' * 64, 'kind': 'slot-snapshot'}
            check(key + '-' + str(index), 'r-test', payload, error=True, published=published)
    for width, character in ((1, 'A'), (2, 'é'), (3, '雪'), (4, '🙂')):
        for length in (0, 1, 127, 128, 129):
            check('code-unicode-%s-%s' % (width, length), 'r', dict(base, code=character * length), error=True)
        for length in (0, 1, 4095, 4096, 4097):
            check('message-unicode-%s-%s' % (width, length), 'r', dict(base, message=character * length), error=True)
    check('explicit-composite-attributes', 'r', dict(base, phase=['phase', None], retry_action={'x': 1}, details_artifact=['ref']), error=True)
    check('empty-message-type-fallback', 'r', dict(base, message='', type='ActualCustomFailure'), error=True)
    check('code-surrogate-kept', 'r', dict(base, code='a' * 127 + '\ud800' + 'tail'), error=True)
    check('code-surrogate-after-prefix', 'r', dict(base, code='a' * 128 + '\ud800'), error=True)
    check('message-surrogate-kept', 'r', dict(base, message='a' * 4095 + '\udc00'), error=True)
    check('message-surrogate-after-prefix', 'r', dict(base, message='a' * 4096 + '\udc00'), error=True)
    detail = ['same']
    result, got = check('error-alias', detail, dict(base, phase=detail, retry_action=detail, details_artifact=detail), error=True)
    assert got['request_id'] is got['error']['phase'] is got['error']['retry_action'] is got['error']['details_artifact']
    for pending in (False, 0, '', [], {}, {'generation': 7}):
        check('publication-failure-' + str(len(rows)), 'r', dict(base, pending_slot_snapshot=pending), error=True,
              failed=dict(type='OSError', message='actual publication failure observation', phase='namespace'))
    summary.update(status='PASS', cases=len(rows), entries=actual.entries)
except BaseException as exc:
    summary.update(status='FAIL', cases=len(rows), entries=actual.entries, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    summary['wall_ns'] = time.monotonic_ns() - start
    actual.close()
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print(json.dumps(summary, sort_keys=True), flush=True)
