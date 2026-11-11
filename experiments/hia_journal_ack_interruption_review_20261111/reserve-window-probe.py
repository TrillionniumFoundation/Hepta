"""Independent SQL INSERT-to-ACK interruption witness with real SQLite."""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

ROOT = Path('/home/agent/hia-journal-review-330ce4c')
MANIFEST = Path('/workspace/scratch/e26ed3e2edcf/journal-recovered-development-r3/manifest.json')
DEST = Path('/workspace/scratch/e26ed3e2edcf/journal-330-reserve-window-observations')
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_journal_native import JournalSession, SELECTOR, installed_agent_journal


def snapshot(service):
    return {table: [dict(row) for row in service.store.db.execute('SELECT * FROM ' + table)]
            for table in ('requests', 'costs', 'effect_probe')}


class FaultDB:
    def __init__(self, actual, kind, after):
        self.actual, self.kind, self.after = actual, kind, after
        self.fired = False

    def __getattr__(self, name):
        return getattr(self.actual, name)

    def execute(self, sql, *args):
        if sql.startswith('INSERT INTO requests') and not self.fired:
            self.fired = True
            if self.after:
                self.actual.execute(sql, *args)
            raise self.kind('independent interruption between SQL INSERT and native ACK')
        return self.actual.execute(sql, *args)


DEST.mkdir(exist_ok=False)
manifest = json.loads(MANIFEST.read_bytes())
image = installed_agent_journal(str(MANIFEST))
assert sha256((ROOT / 'examples/hia_bootstrap/agent_journal.hepta').read_bytes()).hexdigest() == manifest['source_sha256']
assert image.image_sha256 == manifest['image_sha256']
observations = []
for kind in (KeyboardInterrupt,):
    for after in (False, True):
        name = kind.__name__ + ('-insert-after' if after else '-insert-before')
        service = HIAAgentService(DEST / name)
        service.store.db.execute('CREATE TABLE effect_probe (value TEXT)')
        proxy = FaultDB(service.store.db, kind, after)
        service.store.db = proxy
        stages = []
        original = JournalSession._run

        def trace(session, stage, *args):
            stages.append({'stage': stage, 'after_sql_fault': proxy.fired})
            return original(session, stage, *args)

        def effect(_args):
            service.store.db.execute("INSERT INTO effect_probe VALUES ('effect')")
            return {'effect': 'would-have-committed'}

        args = {'catalog_sha256': service.catalog_sha256, 'request_key': 'independent-sql-ack'}
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {SELECTOR: str(MANIFEST)}))
            stack.enter_context(patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('native fell back')))
            stack.enter_context(patch('hepta.hia_agent_service.validate', return_value=None))
            stack.enter_context(patch.object(service, '_hia_adopt', side_effect=effect))
            stack.enter_context(patch.object(JournalSession, '_run', trace))
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
        with patch.dict(os.environ, {SELECTOR: str(MANIFEST)}), \
                patch.object(HIAAgentService, '_reference_call', side_effect=AssertionError('retry fell back')), \
                patch.object(reopened, '_hia_adopt', side_effect=AssertionError('unknown effect retried')):
            retry = reopened.call('hia_adopt', args) if durable['requests'] else None
        reopened.close()
        observations.append({'case': name, 'fault_reached': proxy.fired, 'native_stage_trace': stages,
            'thrown': thrown, 'returned': result, 'durable_after_reopen': durable, 'retry': retry,
            'false_completed_response': bool(not durable['effect_probe'] and durable['requests']
                and durable['requests'][0]['response'] is not None
                and json.loads(durable['requests'][0]['response']).get('status') == 'completed')})

report = {'schema': 'hepta.hia.journal-independent-sql-ack-review.v1',
    'source_commit': '330ce4c5600c22985d1a7bad1b9199751a15fcc0',
    'source_root': str(ROOT), 'manifest': str(MANIFEST), 'source_sha256': manifest['source_sha256'],
    'image_sha256': image.image_sha256, 'qualification': 'DEVELOPMENT_ONLY',
    'observations': observations,
    'false_completed_response_cases': [r['case'] for r in observations if r['false_completed_response']],
    'native_calls_after_interruption': {r['case']: [t['stage'] for t in r['native_stage_trace'] if t['after_sql_fault']] for r in observations}}
(DEST / 'audit.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'observations'}, sort_keys=True))
raise SystemExit(1 if report['false_completed_response_cases'] else 0)
