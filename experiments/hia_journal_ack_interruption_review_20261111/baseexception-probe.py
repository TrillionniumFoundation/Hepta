"""Independent actual SQLite/native-image acknowledgement fault observation."""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path('/home/agent/hia-journal-review-330ce4c')
MANIFEST = Path('/workspace/scratch/e26ed3e2edcf/journal-recovered-development-r3/manifest.json')
DEST = Path('/workspace/scratch/e26ed3e2edcf/journal-330-baseexception-observations')
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_journal_native import JournalSession, SELECTOR, installed_agent_journal


def snapshot(service):
    return {table: [dict(row) for row in service.store.db.execute('SELECT * FROM ' + table)]
            for table in ('requests', 'costs', 'effect_probe')}


DEST.mkdir(exist_ok=False)
manifest = json.loads(MANIFEST.read_bytes())
image = installed_agent_journal(str(MANIFEST))
assert sha256((ROOT / 'examples/hia_bootstrap/agent_journal.hepta').read_bytes()).hexdigest() == manifest['source_sha256']
assert image.image_sha256 == manifest['image_sha256']
observations = []
for kind in (KeyboardInterrupt, SystemExit, MemoryError, RuntimeError):
    for operation in ('reserved', 'inline', 'committed_inline'):
        for after in (False, True):
            name = kind.__name__ + '-' + operation + ('-after' if after else '-before')
            service = HIAAgentService(DEST / name)
            service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
            original = getattr(JournalSession, operation)
            reached = []

            def fault(session, *args):
                reached.append('entry')
                if after:
                    original(session, *args)
                    reached.append('native-ack-returned')
                raise kind('independent injected ACK interruption')

            def effect(_args):
                service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
                return {'effect': 'would-have-committed'}

            args = {'catalog_sha256': service.catalog_sha256, 'request_key': 'independent-ack'}
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {SELECTOR: str(MANIFEST)}))
                stack.enter_context(patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('native fell back')))
                stack.enter_context(patch('hepta.hia_agent_service.validate', return_value=None))
                stack.enter_context(patch.object(service, '_hia_adopt', side_effect=effect))
                stack.enter_context(patch.object(JournalSession, operation, fault))
                try:
                    result = service.call('hia_adopt', args)
                    thrown = None
                except BaseException as exc:
                    thrown = {'type': type(exc).__name__, 'message': str(exc)}
                    result = None
            state = snapshot(service)
            service.close()
            reopened = HIAAgentService(DEST / name)
            durable = snapshot(reopened)
            assert durable == state, name
            retry = None
            retry_error = None
            if operation != 'reserved':
                with patch.dict(os.environ, {SELECTOR: str(MANIFEST)}), \
                        patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('retry fell back')), \
                        patch.object(reopened, '_hia_adopt', side_effect=AssertionError('unknown effect retried')):
                    try:
                        retry = reopened.call('hia_adopt', args)
                    except BaseException as exc:
                        retry_error = {'type': type(exc).__name__, 'message': str(exc)}
            reopened.close()
            observations.append({'case': name, 'fault_reached': reached, 'thrown': thrown,
                'returned': result, 'durable_after_reopen': durable,
                'retry': retry, 'retry_error': retry_error,
                'false_completed_response': bool(not durable['effect_probe'] and durable['requests']
                    and durable['requests'][0]['state'] == 'completed'),
                'completed_cost_without_effect': any(r['status'] == 'completed' for r in durable['costs'])
                    and not durable['effect_probe']})

report = {'schema': 'hepta.hia.journal-independent-ack-interruption-review.v1',
    'source_commit': '330ce4c5600c22985d1a7bad1b9199751a15fcc0',
    'source_root': str(ROOT), 'manifest': str(MANIFEST), 'source_sha256': manifest['source_sha256'],
    'image_sha256': image.image_sha256,
    'qualification': 'DEVELOPMENT_ONLY; actual pinned HIA image and actual SQLite with deliberate method-boundary exception injection',
    'observations': observations,
    'false_completed_response_cases': [r['case'] for r in observations if r['false_completed_response']],
    'completed_cost_without_effect_cases': [r['case'] for r in observations if r['completed_cost_without_effect']]}
(DEST / 'audit.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'observations'}, sort_keys=True))
raise SystemExit(1 if report['false_completed_response_cases'] else 0)
