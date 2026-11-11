from pathlib import Path
from hashlib import sha256
import json, sqlite3, sys, traceback
from types import SimpleNamespace

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / 'source'))
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_artifact_page_native import installed_artifact_page

output = root / 'original-page-boundaries-r1'; output.mkdir(mode=0o700)
owner = installed_artifact_page('/tmp/hia-e26e-artifact-page-r4/page-bundle.json')

def execute(label, native, mutation=None, offset=0):
    folder = output / (label + ('-native' if native else '-reference')); folder.mkdir(mode=0o700)
    data = b'A' * 600
    ref = {'id': 'artifact-old', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://old'}
    args = {'artifact': ref, 'max_bytes': 512}
    if mutation != 'insert-bind': args['cursor'] = 'missing' if mutation == 'select-bind' else 'cursor-good'
    path = folder / 'state.sqlite3'
    connection = sqlite3.connect(path, isolation_level=None); connection.row_factory = sqlite3.Row
    connection.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
    connection.execute('INSERT INTO cursors VALUES (?,?,?,?)', ('cursor-good', ref['id'], ref['sha256'], offset))
    events = []; sql = []; connection.set_trace_callback(sql.append)
    class Database:
        @property
        def execute(self):
            events.append('execute.lookup')
            if mutation == 'select-bind': args['cursor'] = 'cursor-good'
            if mutation == 'insert-bind': ref.update(id='artifact-mutated', sha256='f' * 64)
            def bound(query, parameters):
                events.append({'execute': query, 'parameters': [v.hex() if type(v) is bytes else v for v in parameters]})
                return connection.execute(query, parameters)
            return bound
    def get(reference):
        events.append('store.get'); return data, {}
    service = SimpleNamespace(store=SimpleNamespace(get=get, db=Database()))
    try:
        result = owner.read(service, args) if native else HIAAgentService._hia_read(service, args)
        value = {'returned': result}
    except BaseException as exc:
        value = {'exception': {'type': type(exc).__name__, 'message': str(exc), 'code': getattr(exc, 'code', None)}}
    rows = [list(row) for row in connection.execute('SELECT * FROM cursors ORDER BY id')]
    rows = [[v.hex() if type(v) is bytes else v for v in row] for row in rows]
    connection.close()
    reopened = sqlite3.connect(path)
    try:
        again = [[v.hex() if type(v) is bytes else v for v in row] for row in reopened.execute('SELECT * FROM cursors ORDER BY id')]
    finally: reopened.close()
    assert again == rows
    record = {'result': value, 'events': events, 'sql': sql, 'rows': rows, 'reopened': again}
    (folder / 'observations.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record

cases = [('select-bind', 'select-bind', 0), ('insert-bind', 'insert-bind', 0),
         ('offset-none', None, None), ('offset-real', None, 0.5),
         ('offset-text', None, 'bad'), ('offset-blob', None, b'bad'),
         ('offset-zero-control', None, 0), ('offset-negative-control', None, -1)]
observations = []
for label, mutation, offset in cases:
    reference = execute(label, False, mutation, offset)
    native = execute(label, True, mutation, offset)
    observations.append({'case': label, 'matches': reference == native, 'reference': reference, 'native': native})
report = {'schema': 'hia.artifact-read-original-page-counterexamples.v1',
          'scope': 'NEW_FINITE_CONTROLS_OF_OLD_PUBLISHED_PAGE_IMAGE_NOT_A_RESUMED_42_CASE_RUN',
          'policy_image': owner.policy.image_sha256, 'wire_image': owner.wire.image_sha256,
          'cases': observations, 'matching': sum(r['matches'] for r in observations),
          'total': len(observations), 'old_42_case_state_unchanged': True}
(output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps({'matching': report['matching'], 'total': report['total'],
                  'cases': [{'case': x['case'], 'matches': x['matches'], 'reference_exception': x['reference']['result'].get('exception'),
                             'native_exception': x['native']['result'].get('exception')} for x in observations]}, indent=2))
