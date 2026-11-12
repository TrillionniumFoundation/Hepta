"""Publicly issued lease -> native SQLite process -> original durable observer.

The original service performs real verification/emission/evaluation/adoption,
then closes its own main/budget connections. The new ELF opens its own official
DB handles; no Python connection or precomputed row decision crosses the bridge.
"""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

from tests import test_hia_agent_native_tools as legacy
from tests.test_hia_sqlite_store import actual_build
from hepta.hia_agent_store import AgentRejected
from hepta.hia_sqlite_store_native import NativeSqliteStore,trace_records


class SqliteStoreIntegrationTests(legacy.AgentToolCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest,cls.development=actual_build()

    def issue(self):
        _base,_candidate,baseline,build,receipts=self.build_pair()
        evaluation=self.session.evaluate(baseline,build,receipts=receipts)
        adopted=self.client.result('hia_adopt',self.session.arguments(
            target_slot='leased',expected_current={'generation':'0','epoch':'0'},
            candidate_artifact=build['native_artifact'],
            evaluation_receipt=evaluation['evaluation_receipt'],verification_receipts=receipts))
        lease=self.service.acquire_slot('leased')
        self.assertEqual(lease['artifact'],build['native_artifact'])
        self.assertEqual(lease['generation'],adopted['current']['generation'])
        rolled=self.client.result('hia_rollback',self.session.arguments(
            target_slot='leased',expected_current=adopted['current'],
            retained_generation=adopted['previous']['generation'],reason='retain issued lease across rollback'))
        supplied=os.environ.get('HIA_SQLITE_PLATFORM_EVIDENCE')
        evidence=Path(supplied)/'integration'/self._testMethodName if supplied else self.root/'evidence'
        evidence.mkdir(mode=0o700,parents=True)
        (evidence/'issued.json').write_text(json.dumps({
            'lease':lease,'adopted':adopted,'rolled_back':rolled,'evaluation':evaluation,'verification_receipts':receipts,
            'artifact_roots':[str(self.files_root)],'source':'original public AgentToolCase.build_pair',
        },indent=2,sort_keys=True)+'\n')
        self.database=self.service.store.database
        self.service.close()
        self.service_closed=True
        return lease,evidence

    def tearDown(self):
        if not getattr(self,'service_closed',False):
            self.service.close()
        self.temporary.cleanup()

    def test_real_public_lease_releases_via_hia_owned_sqlite_and_original_service_observes_it(self):
        lease,evidence=self.issue()
        before=sqlite3.connect(self.database)
        retained=before.execute('SELECT * FROM versions ORDER BY slot,generation').fetchall()
        before.close()
        with patch('sqlite3.connect',side_effect=AssertionError('no hosted SQLite call allowed')), \
             patch.object(legacy.HIAAgentService,'_reference_slot_release',
                          side_effect=AssertionError('hosted release owner forbidden')), \
             patch.object(legacy.HIAAgentService,'_reference_slot_lease',
                          side_effect=AssertionError('hosted lease owner forbidden')):
            with NativeSqliteStore(self.manifest,self.database,evidence=evidence/'native',
                                   allow_development=self.development) as native:
                self.assertEqual(native.release_slot(lease),
                    {'released':True,'generation':lease['generation'],'artifact_retained':True})
        self.service=legacy.HIAAgentService(self.state_root,artifact_roots=(self.files_root,))
        self.service_closed=False
        with self.assertRaises(AgentRejected) as caught:
            self.service.release_slot(lease)
        self.assertEqual(caught.exception.code,'E_HIA_LEASE')
        self.assertEqual(list(map(tuple,self.service.store.db.execute('SELECT * FROM versions ORDER BY slot,generation').fetchall())),
                         retained)
        self.assertEqual(sha256(self.service.store.get(lease['artifact'])[0]).hexdigest(),lease['artifact']['sha256'])
        actual=trace_records((evidence/'native/native-trace.bin').read_bytes())
        roles={row['words'][4] for row in actual if row['kind']==2 and row['words'][1]==1}
        self.assertEqual(roles,{1,2})
        self.assertTrue(any(row['kind']==2 and row['words'][1]==4
                            and row['fields']==(b'COMMIT',) for row in actual))

    def test_public_descriptor_mutation_is_rejected_without_retiring_the_original_lease(self):
        lease,evidence=self.issue()
        forged=deepcopy(lease)
        forged['artifact']['uri']='hepta:modified-caller-uri'
        with NativeSqliteStore(self.manifest,self.database,evidence=evidence/'native',
                               allow_development=self.development) as native:
            with self.assertRaises(AgentRejected) as caught:
                native.release_slot(forged)
            self.assertEqual(caught.exception.code,'E_HIA_LEASE')
            self.assertTrue(native.release_slot(lease)['released'])
        connection=sqlite3.connect(self.database)
        try:
            row=connection.execute('SELECT active,artifact FROM leases WHERE id=?',(lease['id'],)).fetchone()
            self.assertEqual(row[0],0)
            self.assertEqual(json.loads(row[1]),lease['artifact'])
        finally:
            connection.close()
