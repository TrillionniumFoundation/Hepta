"""Additional data controls for the installed journal query correction.

These SQLite fixtures do not execute a worker and do not qualify installation.
The full original v1/v2 installed methods remain required independently.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from tests.hia_worker_installed_journal import JournalSnapshots, canonical, pin
from tools.read_hia_worker_unknown import Capture, _read_installed_journal


def digest(value):
    return sha256(canonical(value)).hexdigest()


class InstalledJournalSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-journal-capture-control-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root/'evidence'
        self.output.mkdir()
        self.database = self.root/'original.sqlite3'
        self.connection = sqlite3.connect(self.database)
        self.addCleanup(self.connection.close)
        self.connection.executescript(
            'CREATE TABLE requests(key TEXT PRIMARY KEY,digest TEXT,tool TEXT,state TEXT,response TEXT,started_ns TEXT);'
            'CREATE TABLE artifacts(id TEXT);CREATE TABLE costs(id TEXT);')
        self.commands = []

    def command(self, label):
        # Deliberately identified as pure fixture data, never a child receipt
        # acceptable to the full installed reader's completed() checks.
        value = {'pure_data_control': True, 'label': label}
        self.commands.append(value)
        (self.output/(label+'.result.json')).write_bytes(canonical(value)+b'\n')
        return value

    def request(self, name):
        return {'request_key': 'installed-verification/'+name, 'text': '雪'}

    def insert(self, request, state='running', *, tool='hia_verify', response=None):
        key = digest({'tool':tool, 'key':request['request_key']})
        self.connection.execute('INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?,?)',
            (key,digest({'tool':tool,'arguments':request}),tool,state,
             None if response is None else canonical(response).decode(),'123'))
        self.connection.commit()
        return key

    def observer(self, labels):
        return JournalSnapshots(self.output,self.database,labels,digest,self.commands)

    def test_01_namespaced_row_and_original_raw_key_miss_are_both_retained(self):
        request=self.request('lost');key=self.insert(request)
        self.command('lost-receipt')
        observer=self.observer(('lost-receipt',))
        value=observer.capture(request)
        self.assertEqual(value,{'request':('running',),'artifacts':0,'costs':0})
        row=json.loads((self.output/'journal-snapshots/00-lost-receipt.json').read_bytes())
        self.assertIsNone(row['raw_key_row'])
        self.assertEqual(row['namespaced_row']['key'],key)
        self.assertEqual(row['namespaced_row']['state'],'running')
        self.assertEqual(row['arguments'],request)
        observer.finish()

    def test_02_same_raw_key_in_another_tool_does_not_alias(self):
        request=self.request('lost')
        other=self.insert(request,tool='hia_emit',state='completed',response={'other':True})
        correct=self.insert(request)
        self.assertNotEqual(other,correct)
        self.command('lost-receipt')
        observer=self.observer(('lost-receipt',))
        self.assertEqual(observer.capture(request)['request'],('running',))
        observer.finish()
        self.assertEqual(self.connection.execute(
            'SELECT state FROM requests WHERE key=?',(other,)).fetchone(),('completed',))

    def test_03_missing_row_is_captured_without_fabricated_running_state(self):
        self.command('lost-receipt')
        observer=self.observer(('lost-receipt',))
        value=observer.capture(self.request('absent'))
        self.assertIsNone(value['request'])
        row=json.loads((self.output/'journal-snapshots/00-lost-receipt.json').read_bytes())
        self.assertIsNone(row['namespaced_row'])
        self.assertTrue((self.output/'journal-snapshots/00-lost-receipt.sqlite3').is_file())

    def test_04_capture_retains_actual_completed_state_and_rejects_later_drift(self):
        request=self.request('actual-completed')
        self.insert(request,'completed',response={'status':'completed'})
        self.command('normal')
        observer=self.observer(('normal',))
        self.assertEqual(observer.capture(request)['request'],('completed',))
        path=self.output/'journal-snapshots/00-normal.sqlite3'
        raw=path.read_bytes()
        path.write_bytes(raw+b'changed')
        with self.assertRaisesRegex(ValueError,'evidence changed'):
            observer.finish()

    def test_05_incomplete_inventory_cannot_publish_complete_capture(self):
        request=self.request('normal');self.insert(request)
        self.command('normal')
        observer=self.observer(('normal','completed-replay'))
        observer.capture(request)
        with self.assertRaisesRegex(ValueError,'incomplete'):
            observer.finish()

    def _complete_data_fixture(self, lost_name='lost'):
        labels=('normal','completed-replay','lost-receipt','unknown-replay')
        observer=self.observer(labels)
        normal=self.request('normal');lost=self.request(lost_name)
        response={'status':'completed','request_id':'r-'+digest({'tool':'hia_verify','arguments':normal})}
        self.insert(normal,'completed',response=response)
        states={}
        for label in labels:
            if label=='lost-receipt':self.insert(lost)
            if label=='unknown-replay':
                self.connection.execute("INSERT INTO costs VALUES ('unknown')")
                self.connection.commit()
            self.command(label)
            states[label]=json.loads(canonical(observer.capture(normal if label in labels[:2] else lost)))
        descriptor=observer.finish()
        command_labels=['wheel','install','identity',*labels,'source-drift']
        by_label={row['label']:row for row in self.commands}
        report={'database_capture':descriptor,
            'commands':[by_label.get(label,{'pure_data_control':True,'label':label}) for label in command_labels],
            'observations':{'normal_state':states['normal'],'replay_state':states['completed-replay'],
                'lost_state':states['lost-receipt'],'unknown_state':states['unknown-replay'],
                'normal':{'response':response},'replay':{'response':response},
                'unknown':{'response':{'request_id':'r-'+digest({'tool':'hia_verify','arguments':lost}),
                    'error':{'code':'E_HIA_REQUEST_UNKNOWN'}}}}}
        return report

    def test_06_independent_reader_reopens_every_actual_snapshot(self):
        report=self._complete_data_fixture()
        capture=Capture()
        result=_read_installed_journal(capture,self.output,report,'v1')
        self.assertEqual(result['snapshot_count'],4)
        self.assertTrue(result['raw_key_rows_absent'])
        self.assertEqual(len([path for path in capture.raw if path.endswith('.sqlite3')]),4)
        self.assertTrue(result['actual_worker_request_bound'])
        self.assertTrue(result['SQL_consumed_captured_raw'])
        capture.stable()

    def test_07_resigned_wrong_key_metadata_cannot_override_sqlite_bytes(self):
        report=self._complete_data_fixture()
        directory=self.output/'journal-snapshots'
        index=json.loads((directory/'index.json').read_bytes())
        entry=index['records'][2]
        path=directory/entry['record']
        record=json.loads(path.read_bytes())
        record['storage_key']=record['raw_request_key']
        raw=canonical(record)+b'\n';path.write_bytes(raw);entry.update(pin(raw))
        raw=canonical(index)+b'\n';(directory/'index.json').write_bytes(raw)
        report['database_capture'].update(pin(raw))
        with self.assertRaisesRegex(ValueError,'namespace'):
            _read_installed_journal(Capture(),self.output,report,'v1')

    def test_08_another_real_running_row_cannot_replace_the_actual_request(self):
        report=self._complete_data_fixture(lost_name='another-real-request')
        # All snapshot bytes, stored rows, key/digest metadata and indexes are
        # internally valid for another request. The actual worker response
        # authority is for the original request and must bind these together.
        report['observations']['unknown']['response']['request_id']='r-'+digest(
            {'tool':'hia_verify','arguments':self.request('lost')})
        with self.assertRaisesRegex(ValueError,'actual worker request digest'):
            _read_installed_journal(Capture(),self.output,report,'v1')

    def test_09_WAL_source_backup_bytes_are_consumed_without_header_changes(self):
        self.assertEqual(self.connection.execute('PRAGMA journal_mode=WAL').fetchone()[0],'wal')
        report=self._complete_data_fixture()
        snapshots={str(path):path.read_bytes()
                   for path in (self.output/'journal-snapshots').glob('*.sqlite3')}
        capture=Capture()
        result=_read_installed_journal(capture,self.output,report,'v1')
        self.assertEqual(result['snapshot_count'],4)
        self.assertTrue(result['SQL_consumed_captured_raw'])
        self.assertEqual(self.connection.execute('PRAGMA journal_mode').fetchone()[0],'wal')
        self.assertEqual(snapshots,{path:Path(path).read_bytes() for path in snapshots})
        self.assertEqual(snapshots,{path:raw for path,raw in capture.raw.items() if path.endswith('.sqlite3')})
        capture.stable()


if __name__=='__main__':
    unittest.main()
