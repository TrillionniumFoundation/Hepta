"""Protocol and actual SQLite controls for the closed HIA platform prototype.

Native controls require an actual explicitly supplied build. They do not seed a
compiler, synthesize a native receipt, skip missing prerequisites, or activate the
ordinary service. SQL rows in this module are declared fixtures; the separate
integration module uses genuinely issued public leases.
"""
from __future__ import annotations
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_sqlite_store_native import (
    NativeSqliteStore, SOURCE, HEADER, REQUEST_MAGIC, EVENT_MAGIC, EFFECT_MAGIC,
    packet, capture_lease, decode_packet, trace_records)
from hepta.hia_agent_store import AgentStore, AgentRejected, wire

ROOT=Path(__file__).resolve().parents[1]


class VM:
    def __init__(self,workspace=65536):
        from hepta.hia_agent_assembly import assemble_program
        self.program=assemble_program(SOURCE.read_bytes())
        self.entry=next(f for f in self.program.as_dict()['functions'] if f['name']=='f0')
        self.state=bytearray(workspace)

    def call(self,raw,capacity=4096):
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(b'\xa5'*capacity)),
                _Owner(-3,self.state)]
        machine=_Machine(self.program,4_000_000,16<<20,None,128)
        count=machine.invoke(self.entry,[_View(owners[0],False),_View(owners[1],True),
                                        _View(owners[2],True)])[0]
        if bytes(owners[0].data)!=raw:
            raise AssertionError('input custody changed')
        return count,bytes(owners[1].data)


class SqliteStoreSourceTests(unittest.TestCase):
    def test_current_core_does_not_admit_platform_symbols_effects_or_resource_types(self):
        from hepta.hia_program import verify_program,HIAProgramRejected
        from tools.generate_hia_sqlite_store import document
        original=document()
        verify_program(original)
        for mutation in ('effect','type','foreign-call'):
            candidate=deepcopy(original)
            if mutation=='effect':
                candidate['functions'][0]['effects'].append('sqlite')
            elif mutation=='type':
                candidate['functions'][0]['params'][0]['type']='sqlite_connection'
            else:
                first=candidate['functions'][0]['blocks'][0]['ops'][0]
                first['op']='platform.sqlite.call'
            with self.subTest(mutation=mutation),self.assertRaises(HIAProgramRejected):
                verify_program(candidate)

    def test_checked_in_source_roundtrips_with_all_existing_cfg_item_limits(self):
        from tools.generate_hia_sqlite_store import document
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        for component,source in (('driver',SOURCE),('agent',ROOT/'examples/hia_bootstrap/sqlite_agent_transaction.hepta'),
                                 ('policy',ROOT/'examples/hia_bootstrap/sqlite_rollback_policy.hepta')):
            program=document(component)
            self.assertEqual(source.read_text(),render_assembly(program))
            self.assertEqual(assemble_program(source.read_bytes()).as_dict(),program)
            self.assertLessEqual(len(program['functions']),128)
            instructions=0
            for function in program['functions']:
                self.assertLessEqual(len(function['params']),16)
                for block in function['blocks']:
                    self.assertLessEqual(len(block['params']),16)
                    for operation in block['ops']:
                        instructions+=1
                        self.assertLessEqual(len(operation['args']),16)
                    term=block['term']
                    edges=[term] if term['op']=='jump' else (
                        [term['then'],term['else']] if term['op']=='branch' else [])
                    for edge in edges:
                        self.assertLessEqual(len(edge['args']),16)
            self.assertLessEqual(instructions,8192)

    def test_vm_refuses_wrapped_field_lengths_without_partial_effect_publication(self):
        raw=packet(0,(b'/private/state.sqlite3',))
        changes=[]
        for index,value in ((12,0),(13,(1<<64)-1),(14,1),(15,1)):
            copy=bytearray(raw)
            struct.pack_into('<Q',copy,index*8,value)
            changes.append(bytes(copy))
        copy=bytearray(raw)
        struct.pack_into('<Q',copy,128,(1<<64)-1)
        changes.append(bytes(copy))
        changes.extend(raw[:size] for size in (0,1,127,128,135,len(raw)-1))
        for case in changes:
            with self.subTest(length=len(case),sha=__import__('hashlib').sha256(case).hexdigest()):
                vm=VM()
                count,out=vm.call(case)
                self.assertIn(count,(4294967293,4294967295))
                self.assertEqual(out,b'\xa5'*len(out))
                self.assertEqual(vm.state,bytearray(len(vm.state)))

    def test_vm_initial_effect_and_stale_resource_events_have_no_sql_authority(self):
        vm=VM()
        count,out=vm.call(packet(0,(b'/private/state.sqlite3',)))
        words,fields=decode_packet(out[:count],EFFECT_MAGIC)
        self.assertEqual((words[1],words[2],words[4:7],fields),
                         (11,1,(0,0,0),(b'/private',)))
        state=bytes(vm.state)
        for changed,value in ((0,0),(2,2),(4,1),(5,1),(6,1)):
            event=list(words)
            event[0]=EVENT_MAGIC
            event[3]=0
            event[7]=1000
            event[8]=0o40700
            event[9]=1000
            event[10]=17
            event[11]=19
            event[12]=0
            event[13]=1
            event[changed]=value
            raw=HEADER.pack(*event)+struct.pack('<Q',0)
            with self.subTest(word=changed):
                vm.state[:]=state
                count,output=vm.call(raw)
                self.assertEqual(count,4294967295)
                self.assertEqual(output,b'\xa5'*len(output))
                self.assertEqual(bytes(vm.state),state)

        # Isolate every rejection above so an implementation defect cannot turn
        # later cases into incidental sequence-mismatch observations.
        # These VM-only private states have two live connections and a live
        # statement. A valid token for a different role is still not authority
        # to answer the outstanding opcode/phase.
        from tools.generate_hia_sqlite_store import STATE_MAGIC
        tokens={0:(0,0,0,0),1:(1,0,11,0),2:(2,1,17,0),3:(3,2,7,1)}
        vm=VM()
        cases=((11,70,0),(10,23,0),(10,24,0),
               (2,50,2),(2,51,1),(3,3,1),(3,9,2),
               (9,63,1),(9,64,2),(9,27,1),
               (5,100,3),(6,100,3),(7,100,3),(8,100,3))
        for opcode,phase,expected in cases:
            for supplied,token in tokens.items():
                if supplied==expected:
                    continue
                vm.state[:]=bytearray(len(vm.state))
                for offset,value in {0:STATE_MAGIC,8:41,16:opcode,24:phase,
                                     56:7,64:11,72:17,80:1,320:7,328:1}.items():
                    struct.pack_into('<Q',vm.state,offset,value)
                before=bytes(vm.state)
                words=[EVENT_MAGIC,opcode,41,0,*token,0,0,0,0,0,1,0,0]
                raw=HEADER.pack(*words)+struct.pack('<Q',0)
                with self.subTest(opcode=opcode,phase=phase,supplied_role=supplied):
                    count,output=vm.call(raw)
                    self.assertEqual(count,4294967295)
                    self.assertEqual(output,b'\xa5'*len(output))
                    self.assertEqual(bytes(vm.state),before)


    def test_vm_exact_workspace_and_large_output_capacity_do_not_publish_partial_effects(self):
        # Resource-only VM fixture: no filesystem or SQLite call occurs.
        # A long captured path makes both boundaries exceed a small page.
        path=b'/'+b'p'*8191+b'/state.sqlite3'
        raw=packet(0,(path,))
        workspace=1024+len(path)
        parent=path.rsplit(b'/',1)[0]
        output=136+len(parent)
        self.assertGreater(output,8192)
        short=VM(workspace=workspace-1)
        count,raw_output=short.call(raw,capacity=output)
        self.assertEqual(count,4294967293)
        self.assertEqual(raw_output,b'\xa5'*output)
        self.assertEqual(short.state,bytearray(workspace-1))
        for capacity in (255,256,output-1):
            with self.subTest(capacity=capacity):
                vm=VM(workspace=workspace)
                count,raw_output=vm.call(raw,capacity=capacity)
                self.assertEqual(count,4294967293)
                self.assertEqual(raw_output,b'\xa5'*capacity)
                # No effect was published; a failed invocation is never retried.
                self.assertEqual(struct.unpack_from('<Q',vm.state,8)[0],0)
        exact=VM(workspace=workspace)
        count,raw_output=exact.call(raw,capacity=output)
        self.assertEqual(count,output)
        words,fields=decode_packet(raw_output,EFFECT_MAGIC)
        self.assertEqual((words[1],words[2],fields),(11,1,(parent,)))
        self.assertEqual(exact.state[1024:],path)
        self.assertEqual(struct.unpack_from('<Q',exact.state,136)[0],workspace)


    def test_vm_preserves_each_current_sqlite_error_and_commit_boundary_without_stale_codes(self):
        from tools.generate_hia_sqlite_store import STATE_MAGIC

        def configured(phase,opcode,role,generation,rc,extra=None):
            # VM-only private-state fixtures model a completed C call. They are
            # not presented as executed SQLite operations or public receipts.
            vm=VM()
            state={0:STATE_MAGIC,8:41,16:opcode,24:phase,64:11,72:17,
                   312:1811,328:1}
            if extra:
                state.update(extra)
            for offset,value in state.items():
                struct.pack_into('<Q',vm.state,offset,value)
            slot=2 if role==3 else role-1 if role else 0
            words=[EVENT_MAGIC,opcode,41,rc,role,slot,generation,
                   1 if role==3 else 0,0,0,0,0,0,1,0,0]
            return vm,words

        for phase,opcode,role,generation,rc in (
                (2,1,1,0,14),(8,1,2,0,7),(3,3,1,11,21),
                (9,3,2,17,10),(50,2,2,17,5),(51,2,1,11,6)):
            with self.subTest(phase=phase,rc=rc):
                vm,words=configured(phase,opcode,role,generation,rc)
                count,raw=vm.call(HEADER.pack(*words)+struct.pack('<Q',0))
                response,fields=decode_packet(raw[:count],EFFECT_MAGIC)
                self.assertEqual((response[1],response[8],response[9],fields),(0,5,rc,(b'',)))
                self.assertEqual(struct.unpack_from('<Q',vm.state,312)[0],rc)
        vm,words=configured(27,9,1,11,0,{568:4096,576:1,120:2})
        words[8]=1
        vm.state[4096]=ord('9')
        count,raw=vm.call(HEADER.pack(*words)+struct.pack('<Q',0))
        response,fields=decode_packet(raw[:count],EFFECT_MAGIC)
        self.assertEqual((response[8],response[9],fields),(0,0,(b'9',)))

        vm=VM()
        path=b'/private/state.sqlite3'
        for offset,value in {0:STATE_MAGIC,64:11,72:17,128:len(path),
                             136:1024+len(path),312:1811,328:1}.items():
            struct.pack_into('<Q',vm.state,offset,value)
        vm.state[1024:1024+len(path)]=path
        raw=capture_lease({'id':'lease','slot':'slot','generation':'1','artifact':{}})
        count,output=vm.call(raw)
        response,fields=decode_packet(output[:count],EFFECT_MAGIC)
        self.assertEqual((response[1],fields),(11,(path,)))
        self.assertEqual(struct.unpack_from('<Q',vm.state,312)[0],0)

        for transaction,statement in ((1,5),(2,2)):
            with self.subTest(transaction=transaction):
                vm,words=configured(100,8,3,7,0,{32:statement,40:4,56:7,
                    80:1,120:transaction,240:10})
                count,raw=vm.call(HEADER.pack(*words)+struct.pack('<Q',0))
                response,fields=decode_packet(raw[:count],EFFECT_MAGIC)
                if transaction==1:
                    self.assertEqual((response[1],fields),(4,(b'ROLLBACK',)))
                    self.assertEqual(struct.unpack_from('<Q',vm.state,312)[0],10)
                else:
                    self.assertEqual((response[1],response[8],response[9],fields),
                                     (0,5,10,(b'',)))
                    self.assertEqual(struct.unpack_from('<Q',vm.state,264)[0],1)

        vm=VM()
        def invoke_close(label,raw,state):
            vm.state[:]=state
            count,output=vm.call(raw)
            return count,output,bytes(vm.state)
        close_protocol_controls(self,invoke_close)


def close_protocol_controls(case,invoke):
    """Declared private states; no result here is an executed SQLite call.

    invoke calls the actual VM or admitted native driver once and returns
    (return value, complete allocated output, complete state).
    """
    from tools.generate_hia_sqlite_store import STATE_MAGIC
    observations=[]
    def seed(transaction,statement=7):
        state=bytearray(65536)
        for at,value in {0:STATE_MAGIC,8:41,56:statement,64:11,72:17,80:1,
                         120:transaction,264:1,312:1811,320:7,328:1}.items():
            struct.pack_into('<Q',state,at,value)
        return bytes(state)
    def reply(words,rc=0,*,prepared=False):
        result=list(words)
        result[0]=EVENT_MAGIC;result[3]=rc;result[12]=0;result[13]=1
        if prepared:
            result[4:8]=[3,2,8,1]
        return HEADER.pack(*result)+struct.pack('<Q',0)
    for label,transaction in (('open-lookup',1),('uncertain-commit',2),('already-clean',0)):
        with case.subTest(close_scenario=label):
            state=seed(transaction,0 if transaction==0 else 7)
            sequence=[]
            def step(raw,expected,fields=(b'',)):
                nonlocal state
                count,output,after=invoke(label+'-'+str(len(sequence)),raw,state)
                case.assertLessEqual(count,len(output))
                words,actual=decode_packet(output[:count],EFFECT_MAGIC)
                case.assertEqual(words[1],expected)
                case.assertEqual(actual,fields)
                case.assertEqual(output[count:],b'\xa5'*(len(output)-count))
                case.assertEqual(struct.unpack_from('<Q',after,264)[0],1)
                sequence.append({'opcode':words[1],'sequence':words[2],
                                 'resource':list(words[4:8]),'phase':struct.unpack_from('<Q',after,24)[0]})
                state=after
                return words
            words=step(packet(2),2 if transaction==0 else 8)
            if transaction!=0:
                case.assertEqual(words[4:8],(3,2,7,1))
                if transaction==1:
                    words=step(reply(words),4,(b'ROLLBACK',))
                    case.assertEqual(words[4:7],(1,0,11))
                    words=step(reply(words,prepared=True),6)
                    case.assertEqual(words[4:8],(3,2,8,1))
                    words=step(reply(words,101),8)
                    words=step(reply(words),2)
                    case.assertEqual(struct.unpack_from('<Q',state,120)[0],0)
                else:
                    words=step(reply(words),2)
                    case.assertEqual(struct.unpack_from('<Q',state,120)[0],2)
            case.assertEqual(words[4:7],(2,1,17))
            words=step(reply(words),2)
            case.assertEqual(words[4:7],(1,0,11))
            words=step(reply(words),12)
            case.assertEqual(words[4:8],(0,0,0,0))
            case.assertEqual(tuple(struct.unpack_from('<Q',state,at)[0] for at in (56,64,72)),(0,0,0))
            case.assertEqual([row['opcode'] for row in sequence],
                             [8,4,6,8,2,2,12] if transaction==1 else
                             [8,2,2,12] if transaction==2 else [2,2,12])
            observations.append({'label':label,'sequence':sequence,'fence_preserved':True,
                                 'transaction_state':struct.unpack_from('<Q',state,120)[0]})
    for label,statement,rc in (('finalize-error',7,19),('rollback-prepare-error',0,14)):
        with case.subTest(close_scenario=label):
            state=seed(1,statement)
            count,out,state=invoke(label+'-request',packet(2),state)
            words,fields=decode_packet(out[:count],EFFECT_MAGIC)
            case.assertEqual((words[1],fields),(8,(b'',)) if statement else (4,(b'ROLLBACK',)))
            count,out,after=invoke(label+'-error',reply(words,rc),state)
            words,fields=decode_packet(out[:count],EFFECT_MAGIC)
            case.assertEqual((words[1],words[8],words[9],fields),(0,5,rc,(b'',)))
            case.assertEqual(out[count:],b'\xa5'*(len(out)-count))
            case.assertEqual(tuple(struct.unpack_from('<Q',after,at)[0] for at in (56,120,264,312)),(0,1,1,rc))
            observations.append({'label':label,'actual_error_code':rc,'fence_preserved':True})
    for role,token in ((0,(0,0,0,0)),(1,(1,0,11,0)),(2,(2,1,17,0))):
        with case.subTest(close_finalize_wrong_role=role):
            state=bytearray(seed(1))
            for at,value in ((16,8),(24,52)):
                struct.pack_into('<Q',state,at,value)
            state=bytes(state)
            raw=HEADER.pack(EVENT_MAGIC,8,41,0,*token,0,0,0,0,0,1,0,0)+struct.pack('<Q',0)
            count,out,after=invoke('close-finalize-wrong-role-'+str(role),raw,state)
            case.assertEqual(count,4294967295)
            case.assertEqual(out,b'\xa5'*len(out))
            case.assertEqual(after,state)
            observations.append({'label':'close-finalize-wrong-role-'+str(role),
                                 'refused_before_authority':True})
    return observations


def actual_build():
    value=os.environ.get('HIA_SQLITE_PLATFORM_TEST_BUILD')
    if not value:
        raise RuntimeError('actual HIA_SQLITE_PLATFORM_TEST_BUILD is required; no native skip/seed')
    path=Path(value).resolve(strict=True)
    development=os.environ.get('HIA_SQLITE_PLATFORM_TEST_DEVELOPMENT')=='1'
    metadata=json.loads(path.read_bytes())
    if metadata.get('current_source_cold_qualified') is False and not development:
        raise RuntimeError('development build needs explicit development test configuration')
    return path,development


class SqliteStoreNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest,cls.development=actual_build()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='hia-sqlite-store-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        supplied=os.environ.get('HIA_SQLITE_PLATFORM_EVIDENCE')
        self.evidence=(Path(supplied)/'native'/self._testMethodName if supplied else self.root/'evidence')
        self.evidence.mkdir(mode=0o700,parents=True)
        store=AgentStore(self.root/'state')
        self.artifact=store.put(b'fixture bytes','sqlite-platform-row-fixture')
        self.lease={'id':'lease-fixture','slot':'slot-fixture','generation':'9','artifact':self.artifact}
        with store.transaction():
            store.db.execute('INSERT INTO leases VALUES(?,?,?,?,1)',
                (self.lease['id'],self.lease['slot'],self.lease['generation'],wire(self.artifact).decode()))
        self.database=store.database
        store.close()

    def open_native(self,name):
        return NativeSqliteStore(self.manifest,self.database,evidence=self.evidence/name,
                                 allow_development=self.development)

    def rows(self):
        with sqlite3.connect(self.database) as connection:
            names=[row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            return {name:connection.execute('SELECT * FROM "'+name+'" ORDER BY rowid').fetchall()
                    for name in names}

    def test_real_native_release_changes_only_the_retained_lease_and_survives_restart(self):
        before=self.rows()
        with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
            with self.open_native('first') as native:
                result=native.release_slot(self.lease)
        self.assertEqual(result,{'released':True,'generation':'9','artifact_retained':True})
        after=self.rows()
        expected=deepcopy(before)
        expected['leases']=[tuple((*row[:-1],0)) if row[0]==self.lease['id'] else row
                            for row in expected['leases']]
        self.assertEqual(after,expected)
        with self.open_native('restart') as native:
            with self.assertRaises(AgentRejected) as caught:
                native.release_slot(self.lease)
            self.assertEqual(caught.exception.code,'E_HIA_LEASE')
        self.assertEqual(self.rows(),expected)
        trace=trace_records((self.evidence/'first/native-trace.bin').read_bytes())
        sql=[row['fields'][0] for row in trace if row['kind']==2 and row['words'][1]==4]
        self.assertEqual(sql[-4:],[b'BEGIN IMMEDIATE',
            b'SELECT id,slot,generation,artifact,active FROM leases WHERE id=?',
            b'UPDATE leases SET active=0 WHERE id=?',b'COMMIT'])

    def test_original_field_basic_identity_and_full_descriptor_rejections_precede_update(self):
        before=self.rows()
        cases=[(None,'E_HIA_FIELDS'),({**self.lease,'extra':True},'E_HIA_FIELDS'),
               ({**self.lease,'id':'unknown'},'E_HIA_LEASE'),
               ({**self.lease,'slot':'other'},'E_HIA_LEASE'),
               ({**self.lease,'generation':9},'E_HIA_LEASE'),
               ({**self.lease,'artifact':{**self.artifact,'extra':True}},'E_HIA_LEASE'),
               ({**self.lease,'artifact':{**self.artifact,'uri':'other'}},'E_HIA_LEASE')]
        with self.open_native('rejections') as native:
            for value,code in cases:
                with self.subTest(value=value),self.assertRaises(AgentRejected) as caught:
                    native.release_slot(value)
                self.assertEqual(caught.exception.code,code)
        self.assertEqual(self.rows(),before)
        trace=trace_records((self.evidence/'rejections/native-trace.bin').read_bytes())
        sql=[row['fields'][0] for row in trace if row['kind']==2 and row['words'][1]==4]
        self.assertEqual(sql.count(b'ROLLBACK'),len(cases))
        self.assertNotIn(b'UPDATE leases SET active=0 WHERE id=?',sql)
        self.assert_actual_driver_resource_rejections()
        self.assert_actual_close_protocol()

    def assert_actual_driver_resource_rejections(self):
        """Run explicit bad-event fixtures on the actual source-bound HIA image.

        These are private protocol-state controls. They do not pretend that
        forged events came from SQLite, and never dispatch an effect to the
        assembly bridge or add a production loader entry.
        """
        import ctypes
        from hashlib import sha256
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.generate_hia_sqlite_store import STATE_MAGIC
        manifest_raw=self.manifest.read_bytes()
        metadata=json.loads(manifest_raw)
        self.assertEqual(metadata['runtime_source_sha256'][
            'examples/hia_bootstrap/sqlite_store.hepta'],sha256(SOURCE.read_bytes()).hexdigest())
        item=metadata['images']['driver']
        self.assertEqual(Path(item['path']).name,item['path'])
        image_path=self.manifest.parent/item['path']
        image_raw=image_path.read_bytes()
        self.assertEqual(len(image_raw),item['bytes'])
        self.assertEqual(sha256(image_raw).hexdigest(),item['sha256'])
        image=NativeHiaJsonImage(image_raw,item['sha256'])
        evidence=self.evidence/'driver-resource-cases'
        evidence.mkdir(mode=0o700)
        blobs=evidence/'bytes'
        blobs.mkdir(mode=0o700)
        records=[]

        def saved(raw):
            digest=sha256(raw).hexdigest()
            path=blobs/digest
            if path.exists():
                self.assertEqual(path.read_bytes(),raw)
            else:
                with path.open('xb') as stream:
                    stream.write(raw)
            return {'sha256':digest,'bytes':len(raw),'path':'bytes/'+digest}

        def invoke(label,raw,state,*,rejection):
            pad=32
            canary=b'\xa7'*pad
            output=b'\xa5'*4096
            source_buffer=ctypes.create_string_buffer(canary+raw+canary,len(raw)+2*pad)
            output_buffer=ctypes.create_string_buffer(canary+output+canary,len(output)+2*pad)
            state_buffer=ctypes.create_string_buffer(canary+state+canary,len(state)+2*pad)
            returned=int(image._entry(ctypes.byref(source_buffer,pad),len(raw),
                ctypes.byref(output_buffer,pad),len(output),
                ctypes.byref(state_buffer,pad),len(state)))
            source_after=source_buffer.raw[pad:-pad]
            output_after=output_buffer.raw[pad:-pad]
            state_after=state_buffer.raw[pad:-pad]
            row={'label':label,'return_u64':returned,
                 'request_before':saved(raw),'request_after':saved(source_after),
                 'output_before':saved(output),'output_after':saved(output_after),
                 'state_before':saved(state),'state_after':saved(state_after),
                 'guard_bytes':pad,'fixture_private_state':True,
                 'sqlite_call_performed_by_this_control':False}
            records.append(row)
            for buffer in (source_buffer,output_buffer,state_buffer):
                self.assertEqual(buffer.raw[:pad],canary)
                self.assertEqual(buffer.raw[-pad:],canary)
            self.assertEqual(source_after,raw)
            if rejection:
                self.assertEqual(returned,4294967295)
                self.assertEqual(output_after,output)
                self.assertEqual(state_after,state)
            return returned,output_after,state_after

        try:
            initial=bytes(65536)
            count,output,state=invoke('initial-lstat',
                packet(0,(b'/private/state.sqlite3',)),initial,rejection=False)
            words,fields=decode_packet(output[:count],EFFECT_MAGIC)
            self.assertEqual((words[1],words[2],words[4:7],fields),
                             (11,1,(0,0,0),(b'/private',)))
            for changed,value in ((0,0),(2,2),(4,1),(5,1),(6,1)):
                event=list(words)
                event[0]=EVENT_MAGIC
                event[3]=0
                event[7]=1000
                event[8]=0o40700
                event[9]=1000
                event[10]=17
                event[11]=19
                event[12]=0
                event[13]=1
                event[changed]=value
                raw=HEADER.pack(*event)+struct.pack('<Q',0)
                with self.subTest(actual_driver_bad_word=changed):
                    invoke('initial-bad-word-'+str(changed),raw,state,rejection=True)
            tokens={0:(0,0,0,0),1:(1,0,11,0),2:(2,1,17,0),3:(3,2,7,1)}
            cases=((11,70,0),(10,23,0),(10,24,0),
                   (2,50,2),(2,51,1),(3,3,1),(3,9,2),
                   (9,63,1),(9,64,2),(9,27,1),
                   (5,100,3),(6,100,3),(7,100,3),(8,100,3))
            for opcode,phase,expected in cases:
                for supplied,token in tokens.items():
                    if supplied==expected:
                        continue
                    workspace=bytearray(65536)
                    for offset,value in {0:STATE_MAGIC,8:41,16:opcode,24:phase,
                                         56:7,64:11,72:17,80:1,320:7,328:1}.items():
                        struct.pack_into('<Q',workspace,offset,value)
                    words=[EVENT_MAGIC,opcode,41,0,*token,0,0,0,0,0,1,0,0]
                    raw=HEADER.pack(*words)+struct.pack('<Q',0)
                    with self.subTest(actual_driver_opcode=opcode,phase=phase,supplied_role=supplied):
                        invoke('op-%d-phase-%d-role-%d'%(opcode,phase,supplied),
                               raw,bytes(workspace),rejection=True)
            self.assertEqual(len(records),48)
        finally:
            mapping=bytes(image._mapping)
            self.assertEqual(mapping,image_raw)
            self.assertEqual(image_path.read_bytes(),image_raw)
            self.assertEqual(self.manifest.read_bytes(),manifest_raw)
            (evidence/'observations.json').write_text(json.dumps({
                'schema':'hepta.hia.sqlite-driver-resource-observations.v1',
                'image_sha256':item['sha256'],'image_bytes':len(image_raw),
                'mapping_sha256_after':sha256(mapping).hexdigest(),
                'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
                'loader':'existing NativeHiaJsonImage',
                'native_driver_executed':True,'bridge_sqlite_dispatch_performed':False,
                'private_protocol_state_fixtures':True,'observations':records,
            },indent=2,sort_keys=True)+'\n')

    def assert_actual_close_protocol(self):
        """Actual driver calls over declared states, with complete byte custody."""
        import ctypes
        from hashlib import sha256
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        manifest_raw=self.manifest.read_bytes()
        metadata=json.loads(manifest_raw)
        source_raw=SOURCE.read_bytes()
        self.assertEqual(metadata['runtime_source_sha256']['examples/hia_bootstrap/sqlite_store.hepta'],
                         sha256(source_raw).hexdigest())
        item=metadata['images']['driver']
        self.assertEqual(Path(item['path']).name,item['path'])
        image_path=self.manifest.parent/item['path']
        image_raw=image_path.read_bytes()
        self.assertEqual((len(image_raw),sha256(image_raw).hexdigest()),(item['bytes'],item['sha256']))
        image=NativeHiaJsonImage(image_raw,item['sha256'])
        evidence=self.evidence/'close-driver-controls'
        evidence.mkdir(mode=0o700)
        observations=[]
        guard=bytes(range(64))
        def save(label,raw):
            path=evidence/label
            with path.open('xb') as stream:stream.write(raw)
            self.assertEqual(path.read_bytes(),raw)
            return {'path':label,'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
        def invoke(label,raw,state):
            output=b'\xa5'*4096
            source=ctypes.create_string_buffer(raw+guard,len(raw)+len(guard))
            destination=ctypes.create_string_buffer(output+guard,len(output)+len(guard))
            workspace=ctypes.create_string_buffer(state+guard,len(state)+len(guard))
            count=image._entry(source,len(raw),destination,len(output),workspace,len(state))
            source_after=ctypes.string_at(source,len(raw)+len(guard))
            all_output=ctypes.string_at(destination,len(output)+len(guard))
            all_state=ctypes.string_at(workspace,len(state)+len(guard))
            self.assertEqual(source_after,raw+guard)
            self.assertEqual(all_output[len(output):],guard)
            self.assertEqual(all_state[len(state):],guard)
            observed={'label':label,'returned':count,
                      'request':save(label+'.request.bin',raw),
                      'state_before':save(label+'.state-before.bin',state),
                      'state_after':save(label+'.state-after.bin',all_state[:len(state)]),
                      'output':save(label+'.output.bin',all_output[:len(output)]),
                      'guards_preserved':True}
            observations.append(observed)
            return count,all_output[:len(output)],all_state[:len(state)]
        try:
            cases=close_protocol_controls(self,invoke)
        finally:
            mapping=bytes(image._mapping)
            self.assertEqual(mapping,image_raw)
            self.assertEqual(image_path.read_bytes(),image_raw)
            self.assertEqual(SOURCE.read_bytes(),source_raw)
            self.assertEqual(self.manifest.read_bytes(),manifest_raw)
            (evidence/'observations.json').write_text(json.dumps({
                'schema':'hepta.hia.sqlite-close-driver-controls.v1',
                'actual_native_driver':True,'bridge_sqlite_dispatch_performed':False,
                'private_protocol_state_fixtures':True,'image_sha256':item['sha256'],
                'mapping_sha256_after':sha256(mapping).hexdigest(),
                'source_sha256':sha256(source_raw).hexdigest(),'observations':observations,
                'cases':locals().get('cases'),
            },indent=2,sort_keys=True)+'\n')


    def test_real_engine_constraint_failure_rolls_back_without_host_compensation(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("CREATE TRIGGER release_failure BEFORE UPDATE ON leases "
                               "BEGIN SELECT RAISE(ABORT,'real release failure'); END")
        before=self.rows()
        with self.open_native('constraint') as native:
            with self.assertRaises(sqlite3.IntegrityError) as caught:
                native.release_slot(self.lease)
            self.assertEqual(caught.exception.sqlite_errorcode&255,19)
        self.assertEqual(self.rows(),before)
        rows=trace_records((self.evidence/'constraint/native-trace.bin').read_bytes())
        sql=[row['fields'][0] for row in rows if row['kind']==2 and row['words'][1]==4]
        self.assertEqual(sql[-1],b'ROLLBACK')
        self.assertNotEqual(sql[-1],b'COMMIT')
        self.assert_actual_component_refusal_closes_fenced_transaction()

    def assert_actual_component_refusal_closes_fenced_transaction(self):
        """A real phase-5 cached BLOB refusal, followed by explicit close.

        The corrupt BLOB is a declared retained-row fixture. The original
        service issued the row; no native receipt or SQLite event is fabricated.
        This tests lifecycle cleanup, not public cached-error equivalence.
        """
        import sys
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import digest
        arguments={'request_key':'sqlite-real-cached-codec-refusal'}
        request=wire({'tool':'hia_rollback','arguments':arguments})
        catalog=(ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
        frame=packet(3,(request,catalog,b'',b'',
                        struct.pack('<QQ',sys.get_int_max_str_digits(),0)))
        with patch.dict(os.environ):
            os.environ.pop('HEPTA_HIA_AGENT_JOURNAL_MANIFEST',None)
            service=HIAAgentService(self.root/'state')
            try:
                issued=service.call('hia_rollback',deepcopy(arguments))
                self.assertEqual(issued['status'],'rejected')
                key=digest({'tool':'hia_rollback','key':arguments['request_key']})
                row=service.store.db.execute('SELECT * FROM requests WHERE key=?',(key,)).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row['state'],'completed')
                service.store.db.execute('UPDATE requests SET response=? WHERE key=?',(b'\xff',key))
                observed=service.store.db.execute(
                    'SELECT typeof(response),response FROM requests WHERE key=?',(key,)).fetchone()
                self.assertEqual(tuple(observed),('blob',b'\xff'))
            finally:
                service.close()
        before=self.rows()
        response=None;fenced=None
        evidence=self.evidence/'cached-codec-close'
        with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
            with self.open_native('cached-codec-close') as native:
                with native._lock:
                    native._check()
                    native._write(frame)
                    response=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
                    words,fields=decode_packet(response,EFFECT_MAGIC)
                    self.assertEqual((words[1],words[8],words[9],fields),(0,14,0,(b'',)))
                    # The failure remains fenced. Another business request may
                    # not use the connection before the explicit close.
                    native._write(frame)
                    fenced=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
                    words,fields=decode_packet(fenced,EFFECT_MAGIC)
                    self.assertEqual((words[1],words[8],words[9],fields),(0,6,0,(b'',)))
            self.assertTrue(native._closed)
            self.assertEqual(native.process.returncode,0)
        self.assertEqual(self.rows(),before)
        trace=trace_records((evidence/'native-trace.bin').read_bytes())
        codec=[row for row in trace if row['kind']==2 and row['words'][1]==14
               and row['words'][8]==10]
        self.assertEqual(len(codec),1)
        self.assertEqual(codec[0]['fields'][0][512:],b'\xff')
        self.assertEqual(struct.unpack_from('<Q',codec[0]['fields'][0],8)[0],5)
        reply=next(row for row in trace if row['kind']==3 and row['words'][1]==14
                   and row['words'][2]==codec[0]['words'][2])
        self.assertEqual(reply['words'][3],0xffffffe7)
        self.assertEqual(struct.unpack_from('<3Q',reply['fields'][0]),(0,1,1))
        close_index=next(i for i,row in enumerate(trace) if row['kind']==1 and row['words'][1]==2)
        sql=[row['fields'][0] for row in trace if row['kind']==2 and row['words'][1]==4]
        self.assertEqual(sql[-3:],[b'BEGIN IMMEDIATE',b'SELECT * FROM requests WHERE key=?',b'ROLLBACK'])
        close_sql=[row['fields'][0] for row in trace[close_index:] if row['kind']==2 and row['words'][1]==4]
        self.assertEqual(close_sql,[b'ROLLBACK'])
        close_events=[row for row in trace[close_index:] if row['kind']==3 and row['words'][1]==2]
        self.assertEqual([(row['words'][4],row['words'][3]) for row in close_events],[(2,0),(1,0)])
        self.assertFalse(any(row['kind']==4 for row in trace[close_index:]))
        self.assertEqual((trace[-1]['kind'],trace[-1]['words'][1]),(2,12))
        (evidence/'request.bin').write_bytes(frame)
        (evidence/'component-refusal.bin').write_bytes(response)
        (evidence/'fenced-business.bin').write_bytes(fenced)
        (evidence/'observations.json').write_text(json.dumps({
            'schema':'hepta.hia.sqlite-real-component-refusal-close.v1',
            'actual_native_process_sqlite':True,'actual_cached_phase':5,
            'actual_component_error':0xffffffe7,'request_row_issued_by_original_service':True,
            'declared_response_blob_hex':'ff','fence_blocks_business':True,
            'explicit_close_rollback':True,'all_database_tables_preserved':True,
            'close_stdout_eof_exit_zero_and_final_opcode12_observed':True,
            'public_cached_error_equivalence_claimed':False,
            'whole_rollback_transaction_completed':False,
        },indent=2,sort_keys=True)+'\n')


    def test_blob_json_and_original_short_circuit_keep_the_same_issued_descriptor(self):
        with sqlite3.connect(self.database) as connection:
            encoded=json.dumps(self.artifact,ensure_ascii=True,indent=2).encode()
            connection.execute('UPDATE leases SET artifact=?',(encoded,))
            self.assertEqual(connection.execute('SELECT typeof(artifact) FROM leases').fetchone()[0],'blob')
        with self.open_native('blob') as native:
            self.assertTrue(native.release_slot(self.lease)['released'])
        with sqlite3.connect(self.database) as connection:
            connection.execute('UPDATE leases SET artifact=?',(b'\xffnot-json',))
        with self.open_native('inactive-corrupt') as native:
            with self.assertRaises(AgentRejected) as caught:
                native.release_slot(self.lease)
            self.assertEqual(caught.exception.code,'E_HIA_LEASE')


    def test_canonical_scratch_and_accumulated_rows_cover_small_deep_dense_and_large_values(self):
        # These are declared database transport fixtures, not fabricated public
        # proof receipts. The separate integration suite uses issued descriptors.
        nested='leaf'
        for _ in range(128):
            nested=[nested]
        dense={f'k{index:04d}':'v' for index in reversed(range(2048))}
        large={'id':'lease-'+('i'*65536),'slot':'slot-'+('s'*65536),
               'generation':'9'*131072,'artifact':dense}
        cases=[deepcopy(self.lease),
               {'id':'lease-deep','slot':'deep','generation':'10','artifact':nested},
               {'id':'lease-dense','slot':'dense','generation':'11','artifact':dense},
               large]
        with sqlite3.connect(self.database) as connection:
            for lease in cases[1:]:
                # Retain original insertion order and escaped JSON; native HIA
                # must independently decode, sort and emit the whole value.
                data=json.dumps(lease['artifact'],ensure_ascii=True,
                                separators=(',',':')).encode()
                connection.execute('INSERT INTO leases VALUES(?,?,?,?,1)',
                    (lease['id'],lease['slot'],lease['generation'],data))
        before=self.rows()
        with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
            with self.open_native('capacity') as native:
                for lease in cases:
                    with self.subTest(id=lease['id'][:32]):
                        result=native.release_slot(lease)
                        self.assertEqual(result,{'released':True,
                            'generation':lease['generation'],'artifact_retained':True})
        expected=deepcopy(before)
        ids={lease['id'] for lease in cases}
        expected['leases']=[tuple((*row[:-1],0)) if row[0] in ids else row
                            for row in expected['leases']]
        self.assertEqual(self.rows(),expected)
        records=trace_records((self.evidence/'capacity/native-trace.bin').read_bytes())
        canonical=[row for row in records if row['kind']==3 and row['words'][1]==10]
        self.assertEqual(len(canonical),2*len(cases))
        for index,lease in enumerate(cases):
            expected_wire=wire(lease['artifact'])
            for record in canonical[2*index:2*index+2]:
                self.assertEqual(record['words'][3],0)
                self.assertEqual(record['fields'],(expected_wire,))
        columns=[row for row in records if row['kind']==3
                 and row['words'][1]==7 and row['words'][9]==5]
        self.assertEqual(len(columns),5*len(cases))
        self.assertGreater(max(len(row['fields'][0]) for row in columns),65536)
        successes=[row for row in records if row['kind']==4
                   and row['words'][1]==0 and row['words'][8]==0]
        self.assertIn((large['generation'].encode(),),[row['fields'] for row in successes])
        # A second process still sees the exact completed state; no oversized
        # pending row/canonical data leaks into a later request.
        with self.open_native('capacity-restart') as native:
            for lease in cases:
                with self.assertRaises(AgentRejected) as caught:
                    native.release_slot(lease)
                self.assertEqual(caught.exception.code,'E_HIA_LEASE')
        self.assertEqual(self.rows(),expected)
        self.assert_actual_agent_lookup_capacity()
        self.assert_actual_column_utf8_codec()
        self.assert_actual_request_row_capacity_and_conflict_order()
        self.assert_actual_request_text_materialization_and_lookup_budget()
        self.assert_actual_rollback_schema_and_terminal_sql()
        self.assert_actual_artifact_fd_and_sha_chain()
        self.assert_actual_artifact_metadata_chain()


    def assert_actual_agent_lookup_capacity(self):
        """Private-state capacity controls on the actual bound agent image.

        These frames are deliberately declared HIA state fixtures, not SQLite
        observations. The separate process control below reads an actual row.
        """
        import ctypes
        from hashlib import sha256
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.generate_hia_sqlite_store import STATE_MAGIC
        manifest_raw=self.manifest.read_bytes()
        metadata=json.loads(manifest_raw)
        agent_source=ROOT/'examples/hia_bootstrap/sqlite_agent_transaction.hepta'
        source_raw=agent_source.read_bytes()
        self.assertEqual(metadata['runtime_source_sha256'][
            'examples/hia_bootstrap/sqlite_agent_transaction.hepta'],sha256(source_raw).hexdigest())
        item=metadata['images']['agent']
        self.assertEqual(Path(item['path']).name,item['path'])
        image_path=self.manifest.parent/item['path']
        image_raw=image_path.read_bytes()
        self.assertEqual((len(image_raw),sha256(image_raw).hexdigest()),
                         (item['bytes'],item['sha256']))
        image=NativeHiaJsonImage(image_raw,item['sha256'])
        evidence=self.evidence/'agent-capacity-cases'
        evidence.mkdir(mode=0o700)
        blobs=evidence/'bytes'
        blobs.mkdir(mode=0o700)
        records=[]

        def saved(raw):
            digest=sha256(raw).hexdigest()
            path=blobs/digest
            if path.exists():
                self.assertEqual(path.read_bytes(),raw)
            else:
                with path.open('xb') as stream:
                    stream.write(raw)
            return {'sha256':digest,'bytes':len(raw),'path':'bytes/'+digest}

        def state_for(columns,capacity):
            path=b'/private/state/journal.sqlite3'
            request=packet(3,(b'{}',b'{}',b'',b'',struct.pack('<QQ',4300,0)))
            base=1024+len(path)
            state_at=(base+len(request)+7)&~7
            state=bytearray(capacity)
            self.assertGreaterEqual(capacity,state_at+4096+sum(map(len,columns)))
            state[1024:base]=path
            state[base:base+len(request)]=request
            words={0:STATE_MAGIC,8:41,16:8,24:250,32:20,40:4,
                   56:9,64:7,120:1,128:len(path),136:base,
                   144:len(request),152:base+len(request),264:0,
                   320:9,328:1,368:state_at}
            for offset,value in words.items():
                struct.pack_into('<Q',state,offset,value)
            for offset,value in {24:4300,32:0,80:217,96:1,104:6}.items():
                struct.pack_into('<Q',state,state_at+offset,value)
            at=state_at+4096
            for index,column in enumerate(columns):
                struct.pack_into('<3Q',state,state_at+128+24*index,3,at,len(column))
                state[at:at+len(column)]=column
                at+=len(column)
            struct.pack_into('<Q',state,160,at)
            return bytes(state),at,request,path

        def invoke(label,columns,work_capacity,output_capacity,expect):
            initial,start,request,path=state_for(columns,work_capacity)
            header=[EVENT_MAGIC,8,41,0,3,2,9,1,0,0,0,0,0,1,0,0]
            raw=HEADER.pack(*header)+struct.pack('<Q',0)
            pad=32
            canary=b'\xa7'*pad
            output=b'\xa5'*output_capacity
            source_buffer=ctypes.create_string_buffer(canary+raw+canary,len(raw)+2*pad)
            output_buffer=ctypes.create_string_buffer(canary+output+canary,output_capacity+2*pad)
            state_buffer=ctypes.create_string_buffer(canary+initial+canary,len(initial)+2*pad)
            returned=int(image._entry(ctypes.byref(source_buffer,pad),len(raw),
                ctypes.byref(output_buffer,pad),output_capacity,
                ctypes.byref(state_buffer,pad),len(initial)))
            source_after=source_buffer.raw[pad:-pad]
            output_after=output_buffer.raw[pad:-pad]
            state_after=state_buffer.raw[pad:-pad]
            expected=wire({'digest':columns[1].decode('utf-8'),
                           'state':columns[3].decode('utf-8')})
            observation={'label':label,'return_u64':returned,
                'private_protocol_state_fixture':True,'sqlite_dispatch_performed':False,
                'request':saved(raw),'source_after':saved(source_after),
                'state_before':saved(initial),'state_after':saved(state_after),
                'output_before':saved(output),'output_after':saved(output_after),
                'expected_lookup':saved(expected),'actual_column_extents':list(map(len,columns)),
                'lookup_start':start,'required_live_end':start+len(expected),
                'output_capacity':output_capacity,'work_capacity':work_capacity}
            records.append(observation)
            for buffer in (source_buffer,output_buffer,state_buffer):
                self.assertEqual(buffer.raw[:pad],canary)
                self.assertEqual(buffer.raw[-pad:],canary)
            self.assertEqual(source_after,raw)
            if expect=='complete':
                words,fields=decode_packet(output_after[:returned],EFFECT_MAGIC)
                self.assertEqual((words[1],words[2],words[4:7],words[8]),
                                 (14,42,(0,0,0),1))
                self.assertEqual(len(fields),1)
                self.assertEqual(fields[0][512:],expected)
                self.assertEqual(returned,len(expected)+648)
                self.assertEqual(state_after[start:start+len(expected)],expected)
                self.assertEqual(output_after[returned:],output[returned:])
            elif expect=='output-short':
                self.assertEqual(returned,4294967293)
                self.assertEqual(output_after,output)
            elif expect=='work-short':
                words,fields=decode_packet(output_after[:returned],EFFECT_MAGIC)
                expected_words=(EFFECT_MAGIC,0,42,0,0,0,0,0,14,0,0,0,0,1,0,0)
                self.assertEqual(words,expected_words)
                self.assertEqual(fields,(b'',))
                self.assertEqual(returned,HEADER.size+8)
                expected_frame=HEADER.pack(*expected_words)+struct.pack('<Q',0)
                self.assertEqual(output_after,expected_frame+output[returned:])
                self.assertEqual(struct.unpack_from('<Q',state_after,264)[0],1)
                self.assertEqual(struct.unpack_from('<Q',state_after,24)[0],0)
                self.assertEqual(struct.unpack_from('<Q',state_after,16)[0],0)
                self.assertEqual(struct.unpack_from('<Q',state_after,8)[0],42)
                # This is a deliberately insufficient private buffer, not an
                # equivalent public request-conflict or JSON-budget rejection.
                observation['public_error_equivalence_claimed']=False
            else:
                self.fail('unknown capacity expectation')
            return observation

        try:
            width=131072
            columns=(b'k'*64,b'\0'*width,b't'*width,b'\1'*width,
                     b'{}'+b' '*(width-2),b'0'*width)
            probe,at,request,path=state_for(columns,8<<20)
            observed=max(len(request),len(path)+136,max(map(len,columns))+136,648)
            work=32*observed+65536
            output=16*observed+4096
            old_work=(16*observed+65536+4095)&~4095
            old_output=(2*observed+4096+4095)&~4095
            expected=wire({'digest':columns[1].decode(),'state':columns[3].decode()})
            self.assertLessEqual(len(expected),8<<20)
            self.assertGreater(at+len(expected),old_work)
            self.assertGreater(len(expected)+648,old_output)
            invoke('long-control-complete',columns,work,output,'complete')
            invoke('exact-output',columns,work,len(expected)+648,'complete')
            invoke('one-byte-short-output',columns,work,len(expected)+647,'output-short')
            invoke('old-output-insufficient',columns,work,old_output,'output-short')
            invoke('old-work-insufficient',columns,old_work,output,'work-short')
            mixed=('ascii\x00\b\t\n\f\r\x1f"\\\x7f\u00e9\U0001f642'*128).encode()
            columns=(b'key',mixed,b'tool',mixed,b'{}',b'0')
            invoke('mixed-valid-utf8',columns,1<<20,1<<20,'complete')
            self.assertEqual(len(records),6)
        finally:
            mapping=bytes(image._mapping)
            self.assertEqual(mapping,image_raw)
            self.assertEqual(image_path.read_bytes(),image_raw)
            self.assertEqual(agent_source.read_bytes(),source_raw)
            self.assertEqual(self.manifest.read_bytes(),manifest_raw)
            (evidence/'observations.json').write_text(json.dumps({
                'schema':'hepta.hia.sqlite-agent-capacity-observations.v1',
                'image_sha256':item['sha256'],'mapping_sha256_after':sha256(mapping).hexdigest(),
                'source_sha256':sha256(source_raw).hexdigest(),
                'loader':'existing NativeHiaJsonImage','native_driver_executed':True,
                'bridge_sqlite_dispatch_performed':False,'observations':records,
            },indent=2,sort_keys=True)+'\n')

    def assert_actual_column_utf8_codec(self):
        """Actual agent image over column fixtures; no forged SQLite result claim."""
        import ctypes
        from hashlib import sha256
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.generate_hia_sqlite_store import STATE_MAGIC
        manifest_raw=self.manifest.read_bytes()
        metadata=json.loads(manifest_raw)
        source_path=ROOT/'examples/hia_bootstrap/sqlite_agent_transaction.hepta'
        source_raw=source_path.read_bytes()
        self.assertEqual(metadata['runtime_source_sha256'][
            'examples/hia_bootstrap/sqlite_agent_transaction.hepta'],sha256(source_raw).hexdigest())
        item=metadata['images']['agent']
        self.assertEqual(Path(item['path']).name,item['path'])
        image_path=self.manifest.parent/item['path']
        image_raw=image_path.read_bytes()
        self.assertEqual((len(image_raw),sha256(image_raw).hexdigest()),(item['bytes'],item['sha256']))
        image=NativeHiaJsonImage(image_raw,item['sha256'])
        evidence=self.evidence/'inline-column-codec'
        evidence.mkdir(mode=0o700)
        guard=bytes(range(64));observations=[]
        cases=(b'ascii\0\b\t\n\f\r\x1f"\\\x7f'+('é🙂').encode(),
               b'\xc2\x80',b'\xed\x9f\xbf',b'\xf4\x8f\xbf\xbf',
               b'\xff',b'prefix\xc3(',b'completed\xf0\x9f',
               b'visible\0hidden\xff',('é'*80).encode()+b'\xff',
               b'a'*256+b'\xff',b'\x01\t\xc3\xa9\xff',
               b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80')
        def saved(label,raw):
            path=evidence/label
            with path.open('xb') as stream:stream.write(raw)
            self.assertEqual(path.read_bytes(),raw)
            return {'path':label,'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
        try:
            for index,data in enumerate(cases):
                with self.subTest(inline_codec=index):
                    state=bytearray(65536);base=4096;at=8192
                    for offset,value in {0:STATE_MAGIC,8:41,16:7,24:250,32:20,40:3,
                        56:7,64:11,72:17,80:1,120:1,160:at,320:7,328:1,368:base}.items():
                        struct.pack_into('<Q',state,offset,value)
                    for offset,value in {80:217,96:1,104:2}.items():
                        struct.pack_into('<Q',state,base+offset,value)
                    journal=bytearray(512)
                    struct.pack_into('<7Q',journal,0,int.from_bytes(b'HIAJRN02','little'),1,11,0,1,0,2)
                    journal[64:128]=b'd'*64;journal[128:192]=b'k'*64
                    journal[192:258]=b'r-'+b'a'*64
                    state[base+1024:base+1536]=journal
                    before=bytes(state)
                    frame=HEADER.pack(EVENT_MAGIC,7,41,0,3,2,7,1,3,6,0,0,
                                      len(data),1,0,0)+struct.pack('<Q',len(data))+data
                    output=b'\xa5'*4096
                    source=ctypes.create_string_buffer(frame+guard,len(frame)+len(guard))
                    destination=ctypes.create_string_buffer(output+guard,len(output)+len(guard))
                    workspace=ctypes.create_string_buffer(before+guard,len(before)+len(guard))
                    returned=image._entry(source,len(frame),destination,len(output),workspace,len(before))
                    source_after=ctypes.string_at(source,len(frame)+len(guard))
                    output_after=ctypes.string_at(destination,len(output)+len(guard))
                    state_after=ctypes.string_at(workspace,len(before)+len(guard))
                    self.assertEqual(source_after,frame+guard)
                    self.assertEqual(output_after[len(output):],guard)
                    self.assertEqual(state_after[len(before):],guard)
                    self.assertLessEqual(returned,len(output))
                    words,fields=decode_packet(output_after[:returned],EFFECT_MAGIC)
                    self.assertEqual(fields,(b'',))
                    self.assertEqual(words[4:8],(3,2,7,1))
                    self.assertEqual(output_after[returned:len(output)],output[returned:])
                    self.assertEqual(state_after[at:at+len(data)],data)
                    self.assertEqual(state_after[base+1024:base+1536],bytes(journal))
                    expected_error=None
                    try:data.decode('utf-8')
                    except UnicodeDecodeError as error:
                        reason={'invalid start byte':1,'invalid continuation byte':2,
                                'unexpected end of data':3}[error.reason]
                        expected_error=(error.start,error.end,reason)
                        self.assertEqual(words[1],8)
                        self.assertEqual(struct.unpack_from('<3Q',state_after,base+640),expected_error)
                    else:
                        self.assertEqual((words[1],words[8]),(7,3))
                        self.assertEqual(struct.unpack_from('<3Q',state_after,base+640),(0,0,0))
                    observations.append({'index':index,'expected_codec_error':expected_error,
                        'input':saved(str(index)+'.column.bin',data),
                        'frame':saved(str(index)+'.frame.bin',frame),
                        'state_before':saved(str(index)+'.state-before.bin',before),
                        'state_after':saved(str(index)+'.state-after.bin',state_after[:len(before)]),
                        'output':saved(str(index)+'.output.bin',output_after[:len(output)]),
                        'returned':returned,'full_journal_phase1_state_preserved':True,
                        'buffer_guards_preserved':True})
            self.assertEqual(len(observations),len(cases))
        finally:
            mapping=bytes(image._mapping)
            self.assertEqual(mapping,image_raw)
            self.assertEqual(image_path.read_bytes(),image_raw)
            self.assertEqual(source_path.read_bytes(),source_raw)
            self.assertEqual(self.manifest.read_bytes(),manifest_raw)
            (evidence/'observations.json').write_text(json.dumps({
                'schema':'hepta.hia.sqlite-inline-column-codec.v1',
                'actual_native_agent':True,'bridge_sqlite_dispatch_performed':False,
                'private_protocol_state_fixtures':True,'image_sha256':item['sha256'],
                'source_sha256':sha256(source_raw).hexdigest(),
                'mapping_sha256_after':sha256(mapping).hexdigest(),'observations':observations,
            },indent=2,sort_keys=True)+'\n')


    def assert_actual_request_row_capacity_and_conflict_order(self):
        """Compare a real old-service refusal with the private native prefix.

        The original service issues the request row. Subsequent long column
        values are explicit SQL fixtures. They are not proof receipts, and this
        internal prefix does not activate the ordinary rollback API.
        """
        import sys
        from hashlib import sha256
        from hepta.hia_agent_service import HIAAgentService
        catalog=(ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
        arguments={'request_key':'sqlite-agent-capacity-conflict'}
        original=wire({'tool':'hia_rollback','arguments':arguments})
        frame=packet(3,(original,catalog,b'',b'',
                        struct.pack('<QQ',sys.get_int_max_str_digits(),0)))
        width=max(131072,len(frame)+4096)
        self.assertLessEqual(12*width+24,8<<20)
        evidence=self.evidence/'actual-request-row-capacity'
        evidence.mkdir(mode=0o700)
        with patch.dict(os.environ):
            os.environ.pop('HEPTA_HIA_AGENT_JOURNAL_MANIFEST',None)
            service=HIAAgentService(self.root/'state')
            try:
                issued=service.call('hia_rollback',deepcopy(arguments))
                self.assertEqual(issued['status'],'rejected')
                rows=service.store.db.execute('SELECT * FROM requests').fetchall()
                self.assertEqual(len(rows),1)
                key=rows[0]['key']
                columns=(key,'\0'*width,'t'*width,'\1'*width,
                         '{}'+(' '*(width-2)),'0'*width)
                service.store.db.execute('UPDATE requests SET digest=?,tool=?,state=?,response=?,started_ns=? WHERE key=?',
                    (*columns[1:],key))
                before_oracle=self.rows()
                expected=service.call('hia_rollback',deepcopy(arguments))
                after_oracle=self.rows()
                self.assertEqual(expected['status'],'rejected')
                self.assertEqual(expected['error']['code'],'E_HIA_REQUEST_CONFLICT')
                self.assertEqual(expected['error']['message'],
                    'request key is already bound to different arguments')
                # Preserve the oracle's real costs/artifacts, then restore only
                # the explicitly declared six-column input fixture for native.
                service.store.db.execute('UPDATE requests SET digest=?,tool=?,state=?,response=?,started_ns=? WHERE key=?',
                    (*columns[1:],key))
            finally:
                service.close()
        lookup=wire({'digest':columns[1],'state':columns[3]})
        self.assertLessEqual(len(lookup),8<<20)
        expected_columns=tuple(value.encode('utf-8') for value in columns)
        before=self.rows()
        (evidence/'request.bin').write_bytes(frame)
        (evidence/'expected-lookup.bin').write_bytes(lookup)
        with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
            with self.open_native('agent-row-capacity') as native:
                with native._lock:
                    native._check()
                    native._write(frame)
                    size=struct.unpack('<Q',native._read_exact(8))[0]
                    returned=native._read_exact(size)
        (evidence/'response.bin').write_bytes(returned)
        words,fields=decode_packet(returned,EFFECT_MAGIC)
        self.assertEqual((words[1],words[8],fields),(0,14,(struct.pack('<Q',2),)))
        self.assertEqual(self.rows(),before)
        records=trace_records((self.evidence/'agent-row-capacity/native-trace.bin').read_bytes())
        actual_columns=[row for row in records if row['kind']==3
                        and row['words'][1]==7 and row['words'][9]==6]
        self.assertEqual(tuple(row['fields'][0] for row in actual_columns),expected_columns)
        self.assertTrue(all(row['words'][8]==3 for row in actual_columns))
        effects=[row for row in records if row['kind']==2 and row['words'][1]==14
                 and row['words'][8]==1]
        self.assertEqual(len(effects),1)
        self.assertEqual(effects[0]['fields'][0][512:],lookup)
        replies=[row for row in records if row['kind']==3 and row['words'][1]==14
                 and row['words'][8]==1]
        self.assertEqual(len(replies),1)
        self.assertEqual(replies[0]['words'][3],11)
        self.assertEqual(struct.unpack_from('<Q',replies[0]['fields'][0],56)[0],2)
        sql=[row['fields'][0] for row in records if row['kind']==2 and row['words'][1]==4]
        self.assertEqual(sql[-3:],[b'BEGIN IMMEDIATE',b'SELECT * FROM requests WHERE key=?',b'ROLLBACK'])
        self.assertNotIn(b'INSERT INTO requests VALUES (?,?,?,?,?,?)',sql)
        def blob_evidence(value):
            if type(value) is bytes:
                return {'sqlite_blob_hex':value.hex()}
            raise TypeError('unexpected row observation type '+type(value).__name__)
        (evidence/'observations.json').write_text(json.dumps({
            'schema':'hepta.hia.sqlite-agent-row-capacity-observations.v1',
            'ordinary_reference_response':expected,'original_seed_response':issued,
            'oracle_tables_before':before_oracle,'oracle_tables_after':after_oracle,
            'native_tables_before':before,'native_tables_after':self.rows(),
            'actual_native_process_sqlite':True,'actual_columns_read':len(actual_columns),
            'raw_column_extents':[len(value) for value in expected_columns],
            'lookup_bytes':len(lookup),'lookup_sha256':sha256(lookup).hexdigest(),
            'actual_journal_action':11,'actual_journal_refusal_reason':2,
            'ordinary_public_native_adapter_exposed':False,
            'whole_rollback_transaction_completed':False,
        },indent=2,sort_keys=True,default=blob_evidence)+'\n')


    def assert_actual_request_text_materialization_and_lookup_budget(self):
        """Actual SQLite rows with route-specific original error oracles.

        Invalid TEXT uses the unmodified ordinary service call. Lookup encoding
        limits use the original selected-journal lookup method before its native
        call; that is deliberately not described as the reference-call route.
        The private prefix returns only an error object, not a completed public
        call/cost/journal implementation.
        """
        import sys
        from hashlib import sha256
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_journal_native import JournalSession
        from hepta.hia_program_tools import HIAEditRejected
        catalog=(ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
        evidence=self.evidence/'request-row-materialization'
        evidence.mkdir(mode=0o700)
        blobs=evidence/'bytes'
        blobs.mkdir(mode=0o700)
        observations=[]

        def saved(raw):
            self.assertIs(type(raw),bytes)
            digest=sha256(raw).hexdigest()
            path=blobs/digest
            if path.exists():
                self.assertEqual(path.read_bytes(),raw)
            else:
                with path.open('xb') as stream:
                    stream.write(raw)
            return {'bytes':len(raw),'sha256':digest,'path':'bytes/'+digest}

        def raw_rows():
            # Inspection preserves bad TEXT bytes and records each storage
            # class. It does not change the service's default str factory.
            with sqlite3.connect(self.database) as connection:
                connection.text_factory=bytes
                names=[r[0].decode('ascii') for r in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                result={}
                for name in names:
                    quote=lambda value:'"'+value.replace('"','""')+'"'
                    columns=[r[1].decode('utf-8') for r in connection.execute(
                        'PRAGMA table_info('+quote(name)+')')]
                    query='SELECT '+','.join([quote(c) for c in columns]+[
                        'typeof('+quote(c)+')' for c in columns])+' FROM '+quote(name)+' ORDER BY rowid'
                    result[name]={'columns':columns,'rows':connection.execute(query).fetchall()}
                return result

        def observed_rows(value):
            if type(value) is bytes:
                return {'raw_bytes':saved(value)}
            if type(value) is tuple or type(value) is list:
                return [observed_rows(item) for item in value]
            if type(value) is dict:
                return {key:observed_rows(item) for key,item in value.items()}
            return value

        def update_fixture(service,key,columns):
            self.assertEqual(len(columns),6)
            self.assertEqual(columns[0],key.encode('ascii'))
            self.assertTrue(all(type(column) is bytes for column in columns))
            service.store.db.execute(
                'UPDATE requests SET digest=CAST(? AS TEXT),tool=CAST(? AS TEXT),'
                'state=CAST(? AS TEXT),response=CAST(? AS TEXT),started_ns=CAST(? AS TEXT) WHERE key=?',
                (*columns[1:],key))
            classes=service.store.db.execute(
                'SELECT typeof(key),typeof(digest),typeof(tool),typeof(state),typeof(response),'
                'typeof(started_ns) FROM requests WHERE key=?',(key,)).fetchone()
            self.assertEqual(tuple(classes),('text',)*6)

        class NoNativeLookupExpected:
            def _entry(self,*arguments):
                raise AssertionError('wire-budget oracle unexpectedly reached a native image')

        def run_case(label,replacements,*,first_bad=None,budget_message=None,exact_lookup=False):
            arguments={'request_key':'sqlite-agent-materialization-'+label}
            request_raw=wire({'tool':'hia_rollback','arguments':arguments})
            frame=packet(3,(request_raw,catalog,b'',b'',
                            struct.pack('<QQ',sys.get_int_max_str_digits(),0)))
            with patch.dict(os.environ):
                os.environ.pop('HEPTA_HIA_AGENT_JOURNAL_MANIFEST',None)
                service=HIAAgentService(self.root/'state')
                try:
                    issued=service.call('hia_rollback',deepcopy(arguments))
                    self.assertEqual(issued['status'],'rejected')
                    from hepta.hia_agent_store import digest
                    key=digest({'tool':'hia_rollback','key':arguments['request_key']})
                    issued_row=service.store.db.execute(
                        'SELECT * FROM requests WHERE key=?',(key,)).fetchone()
                    self.assertIsNotNone(issued_row)
                    columns=tuple(value.encode('utf-8') if type(value) is str else value
                                  for value in tuple(issued_row))
                    self.assertTrue(all(type(value) is bytes for value in columns))
                    columns=list(columns)
                    # A mismatched digest would reject before other business
                    # decisions, but only after every SQLite column materializes.
                    columns[1]=b'x'*64
                    for index,value in replacements.items():
                        columns[index]=value
                    columns=tuple(columns)
                    update_fixture(service,key,columns)
                    oracle_before=raw_rows()
                    if budget_message is not None:
                        # The original method encodes the real SQLite Row
                        # before invoking _run. No fabricated native receipt or
                        # replacement SQL decision participates in this oracle.
                        actual_row=service.store.db.execute(
                            'SELECT * FROM requests WHERE key=?',(key,)).fetchone()
                        session=JournalSession(NoNativeLookupExpected())
                        with self.assertRaises(HIAEditRejected) as caught:
                            session.lookup(actual_row)
                        self.assertEqual(str(caught.exception),budget_message)
                        expected=service._error('r-'+digest(
                            {'tool':'hia_rollback','arguments':arguments}),caught.exception)
                        route='original JournalSession.lookup pre-native wire and service._error'
                    else:
                        expected=service.call('hia_rollback',deepcopy(arguments))
                        route='original ordinary HIAAgentService.call with reference journal'
                    oracle_after=raw_rows()
                    self.assertEqual(expected['status'],'rejected')
                    if first_bad is not None:
                        self.assertEqual(expected['error']['code'],'E_HIA_REJECTED')
                        self.assertTrue(expected['error']['message'].startswith(
                            'Could not decode to UTF-8 column '))
                    elif budget_message is None:
                        self.assertEqual(expected['error']['code'],'E_HIA_REQUEST_CONFLICT')
                    # Keep every oracle effect, restoring only this declared row.
                    update_fixture(service,key,columns)
                finally:
                    service.close()
            before=raw_rows()
            case_dir=evidence/label
            case_dir.mkdir(mode=0o700)
            (case_dir/'request.bin').write_bytes(frame)
            with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
                with self.open_native('materialization-'+label) as native:
                    with native._lock:
                        native._check()
                        native._write(frame)
                        returned=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
            (case_dir/'response.bin').write_bytes(returned)
            words,fields=decode_packet(returned,EFFECT_MAGIC)
            self.assertEqual(words[1],0)
            self.assertEqual(words[9],0)
            if first_bad is not None or budget_message is not None:
                self.assertEqual((words[8],len(fields)),(15,1))
                actual=json.loads(fields[0])
                self.assertEqual(actual,expected['error'])
                self.assertEqual(fields[0],wire(expected['error']))
            else:
                self.assertEqual((words[8],fields),(14,(struct.pack('<Q',2),)))
            after=raw_rows()
            self.assertEqual(after,before)
            records=trace_records((self.evidence/('materialization-'+label)/'native-trace.bin').read_bytes())
            column_rows=[row for row in records if row['kind']==3 and row['words'][1]==7
                         and row['words'][9]==6]
            read_count=first_bad+1 if first_bad is not None else 6
            self.assertEqual(len(column_rows),read_count)
            self.assertEqual(tuple(row['fields'][0] for row in column_rows),columns[:read_count])
            self.assertTrue(all(row['words'][8]==3 for row in column_rows))
            utf8_effects=[row for row in records if row['kind']==2 and row['words'][1]==14
                          and row['words'][8]==10]
            # Every row TEXT is checked inside the actual agent. The journal
            # remains in phase 1; cached-only stage 10 must not be forged here.
            self.assertEqual(utf8_effects,[])
            utf8_replies=[row for row in records if row['kind']==3 and row['words'][1]==14
                          and row['words'][8]==10]
            self.assertEqual(utf8_replies,[])
            lookup=[row for row in records if row['kind']==2 and row['words'][1]==14
                    and row['words'][8]==1]
            if first_bad is not None or budget_message is not None:
                self.assertEqual(lookup,[])
            else:
                self.assertEqual(len(lookup),1)
                expected_lookup=wire({'digest':columns[1].decode('utf-8'),
                                      'state':columns[3].decode('utf-8')})
                self.assertEqual(lookup[0]['fields'][0][512:],expected_lookup)
                prepared=next(row for row in records if row['kind']==3
                              and row['words'][1]==14 and row['words'][8]==0)
                self.assertEqual(struct.unpack_from('<Q',prepared['fields'][0],8)[0],1)
                self.assertEqual(lookup[0]['fields'][0][:512],prepared['fields'][0][:512])
                if exact_lookup:
                    self.assertEqual(len(expected_lookup),8<<20)
            # A valid six-column row completes Python fetchone's next step
            # before returning the row; invalid TEXT stops before that step.
            selection=next(i for i,row in enumerate(records)
                           if row['kind']==2 and row['words'][1]==4
                           and row['fields']==(b'SELECT * FROM requests WHERE key=?',))
            finalized=next(i for i in range(selection+1,len(records))
                           if records[i]['kind']==2 and records[i]['words'][1]==8)
            step_events=[row for row in records[selection:finalized]
                         if row['kind']==2 and row['words'][1]==6]
            self.assertEqual(len(step_events),1 if first_bad is not None else 2)
            sql=[row['fields'][0] for row in records if row['kind']==2 and row['words'][1]==4]
            self.assertEqual(sql[-3:],[b'BEGIN IMMEDIATE',b'SELECT * FROM requests WHERE key=?',b'ROLLBACK'])
            self.assertNotIn(b'INSERT INTO requests VALUES (?,?,?,?,?,?)',sql)
            observations.append({
                'label':label,'oracle_route':route,'original_seed_response':issued,
                'ordinary_or_helper_reference_response':expected,'first_invalid_text_column':first_bad,
                'source_columns':[saved(value) for value in columns],
                'actual_columns_read':read_count,'actual_inline_utf8_columns':read_count,
                'actual_cached_stage10_invocations_during_lookup':len(utf8_effects),
                'actual_fetchone_step_calls':len(step_events),
                'native_response':saved(returned),
                'oracle_tables_before':observed_rows(oracle_before),
                'oracle_tables_after':observed_rows(oracle_after),
                'native_tables_before':observed_rows(before),'native_tables_after':observed_rows(after),
                'actual_native_process_sqlite':True,'public_call_adapter_exposed':False,
                'whole_rollback_transaction_completed':False,'cost_finalization_completed':False,
            })

        try:
            utf8_cases=(
                ('digest-start-byte',{1:b'\xff'},1),
                ('tool-continuation',{2:b'prefix\xc3('},2),
                ('state-truncated-sequence',{3:b'completed\xf0\x9f'},3),
                ('response-nul-before-error',{4:b'visible\0hidden\xff'},4),
                ('started-ascii-replacement',{5:('é'*80).encode()+b'\xff'},5),
                ('first-of-two-bad-columns',{2:b'\xff',4:b'\xfe'},2),
                ('message-truncation',{4:b'a'*256+b'\xff'},4),
                ('message-c0-and-replacement',{4:b'\x01\t\xc3\xa9\xff'},4),
            )
            for label,replacements,first_bad in utf8_cases:
                with self.subTest(materialization=label):
                    run_case(label,replacements,first_bad=first_bad)
            with self.subTest(materialization='valid-text-nul-and-unicode'):
                run_case('valid-text-nul-and-unicode',{2:b'tool\0suffix',
                    3:'running\x00\t\x7fé🙂'.encode(),4:b'non-json\0',5:b'0'})
            maximum=8<<20
            fragment_exact=b'\0'*((maximum-2)//6)
            self.assertEqual(len(json.dumps(fragment_exact.decode(),ensure_ascii=False).encode()),maximum)
            oversized=fragment_exact+b'\0'
            string_message='E_HIA_EDIT: JSON string exceeds byte budget before encoding'
            total_message='E_HIA_EDIT: JSON encoding exceeds byte budget'
            for label,replacements,message in (
                ('state-string-over-budget',{3:oversized},string_message),
                ('digest-string-over-budget',{1:oversized},string_message),
                ('lookup-total-over-budget',{3:fragment_exact},total_message),
            ):
                with self.subTest(materialization=label):
                    run_case(label,replacements,budget_message=message)
            extent=maximum-24-64
            exact_state=b'\0'*(extent//6)+b'a'*(extent%6)
            self.assertEqual(len(wire({'digest':'x'*64,'state':exact_state.decode()})),maximum)
            with self.subTest(materialization='exact-eight-mib-lookup'):
                run_case('exact-eight-mib-lookup',{3:exact_state},exact_lookup=True)
            self.assertEqual(len(observations),13)
        finally:
            (evidence/'observations.json').write_text(json.dumps({
                'schema':'hepta.hia.sqlite-request-materialization-observations.v1',
                'observations':observations,'python_version':sys.version,
                'sqlite_library_version':sqlite3.sqlite_version,
                'invalid_key_column_real_lookup_reachability_claimed':False,
                'generic_protocol_error_used_as_domain_oracle':False,
                'current_source_cold_qualified':False,
            },indent=2,sort_keys=True)+'\n',encoding='utf-8')



    def assert_actual_rollback_schema_and_terminal_sql(self):
        """Full original rejection bytes and actual native journal/cost effects.

        The valid business continuation remains separately marked unfinished.
        Every oracle below is a real original service call in another private
        database, before that owner is closed. The tested process opens its own
        official database; the host cannot connect while native executes.
        """
        import sys
        from hashlib import sha256
        from hepta.hia_agent_service import HIAAgentService
        catalog=(ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
        digest=sha256(catalog).hexdigest()
        good={'catalog_sha256':digest,'context':{'id':'context','sha256':'a'*64},
              'request_key':'rollback-schema','target_slot':'slot',
              'expected_current':{'generation':'0','epoch':'0'},
              'retained_generation':'0','reason':'test'}
        cases=[
            ('root-null',None),('root-array',[]),('root-float',1.0),
            ('all-missing',{}),('missing-order',{'request_key':'claim','reason':'x'}),
            ('context-missing',{**good,'context':{}}),
            ('current-missing',{**good,'expected_current':{}}),
            ('context-type',{**good,'context':[]}),
            ('digest-type',{**good,'catalog_sha256':True}),
            ('digest-pattern',{**good,'catalog_sha256':'F'*64}),
            ('catalog-stale',{**good,'catalog_sha256':'a'*64}),
            ('digest-final-newline',{**good,'catalog_sha256':digest+'\n'}),
            ('id-final-newline-before-reason',{**good,'context':{**good['context'],'id':'x\n'},'reason':''}),
            ('decimal-final-newline-before-reason',{**good,'expected_current':{'generation':'0\n','epoch':'0'},'reason':''}),
            ('decimal-leading-zero',{**good,'retained_generation':'00'}),
            ('key-array',{**good,'request_key':[]}),
            ('key-unicode',{**good,'request_key':'🙂'}),
            ('reason-empty',{**good,'reason':''}),
            ('reason-2049-nonbmp',{**good,'reason':'🙂'*2049}),
            ('reason-2048-nonbmp-stale',{**good,'reason':'🙂'*2048,'catalog_sha256':'a'*64}),
            ('unknown-before-known',{**good,'!unknown':'x'}),
            ('unknown-long-codepoints',{**good,'x'+'🙂'*5000:None}),
        ]
        evidence=self.evidence/'rollback-schema-terminal'
        evidence.mkdir(mode=0o700)
        observations=[]
        def rows(database):
            with sqlite3.connect(database) as connection:
                names=[row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                return {name:connection.execute('SELECT * FROM "'+name+'" ORDER BY rowid').fetchall()
                        for name in names}
        try:
            for label,arguments in cases:
                with self.subTest(rollback_schema=label):
                    case=evidence/label;case.mkdir(mode=0o700)
                    with patch.dict(os.environ):
                        os.environ.pop('HEPTA_HIA_AGENT_JOURNAL_MANIFEST',None)
                        oracle=HIAAgentService(self.root/('oracle-'+label))
                        try:
                            expected=oracle.call('hia_rollback',deepcopy(arguments))
                            self.assertEqual(expected['status'],'rejected')
                            self.assertIn(expected['error']['code'],('E_HIA_SCHEMA','E_HIA_CATALOG_STALE'))
                        finally:oracle.close()
                        seed=HIAAgentService(self.root/('native-'+label))
                        database=seed.store.database
                        seed.close()
                    original=wire({'tool':'hia_rollback','arguments':arguments})
                    frame=packet(4,(original,catalog,b'',b'',
                        struct.pack('<QQ',sys.get_int_max_str_digits(),0)))
                    before=rows(database)
                    (case/'request.bin').write_bytes(frame)
                    with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
                        with NativeSqliteStore(self.manifest,database,evidence=case/'native',
                                allow_development=self.development) as native:
                            with native._lock:
                                native._write(frame)
                                returned=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
                    words,fields=decode_packet(returned,EFFECT_MAGIC)
                    self.assertEqual((words[1],words[8],words[9],len(fields)),(0,0,0,1))
                    self.assertEqual(fields[0],wire(expected))
                    (case/'response.bin').write_bytes(returned)
                    (case/'oracle-response.bin').write_bytes(wire(expected))
                    after=rows(database)
                    for name in before:
                        if name not in ('requests','costs','sqlite_sequence'):
                            self.assertEqual(after[name],before[name])
                    self.assertEqual(len(after['costs']),1)
                    cost=after['costs'][0]
                    self.assertEqual((cost[1],cost[2],cost[3],cost[5]),(None,'hia_rollback',expected['request_id'],'rejected'))
                    self.assertTrue(type(cost[4]) is str and cost[4].isascii() and cost[4].isdecimal())
                    self.assertEqual(json.loads(cost[6]),{'error':expected['error'],'replayed':False})
                    key=arguments.get('request_key') if type(arguments)is dict else None
                    claimed=type(key)is str and 1<=len(key)<=192
                    self.assertEqual(len(after['requests']),int(claimed))
                    if claimed:
                        self.assertEqual(after['requests'][0][2:5],
                            ('hia_rollback','completed',fields[0].decode('utf-8')))
                    records=trace_records((case/'native/native-trace.bin').read_bytes())
                    sql=[row['fields'][0] for row in records if row['kind']==2 and row['words'][1]==4]
                    self.assertEqual(sql.count(b'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)'),1)
                    self.assertEqual(sql.count(b"UPDATE requests SET state='completed',response=? WHERE key=?"),int(claimed))
                    policy=[row for row in records if row['kind']==2 and row['words'][1]==16]
                    self.assertEqual(len(policy),1)
                    self.assertEqual(policy[0]['fields'],(original,))
                    if claimed:
                        insertion=sql.index(b'INSERT INTO requests VALUES (?,?,?,?,?,?)')
                        commit=sql.index(b'COMMIT',insertion)
                        costs=sql.index(b'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)')
                        terminal=sql.index(b"UPDATE requests SET state='completed',response=? WHERE key=?")
                        self.assertLess(insertion,commit);self.assertLess(commit,costs);self.assertLess(costs,terminal)
                        before_replay=rows(database)
                        with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')):
                            with NativeSqliteStore(self.manifest,database,evidence=case/'replay',
                                    allow_development=self.development) as native:
                                with native._lock:
                                    native._write(frame)
                                    replay=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
                        self.assertEqual(decode_packet(replay,EFFECT_MAGIC)[1],fields)
                        self.assertEqual(rows(database),before_replay)
                    self.assertEqual(records[-1]['words'][1],12)
                    observations.append({'label':label,'response':expected,'claimed':claimed,
                        'actual_native_sqlite':True,'original_reference_service':True,
                        'native_tables_before':before,'native_tables_after':after,
                        'full_response_bytes_equal':True,'terminal_costs_and_request_sql':True,
                        'ordinary_public_adapter_exposed':False,'valid_rollback_business_complete':False})
        finally:
            (evidence/'observations.json').write_text(json.dumps({
                'schema':'hepta.hia.sqlite-rollback-schema-terminal.v1',
                'observations':observations,'cases_declared':len(cases),
                'current_source_cold_qualified':False},indent=2,sort_keys=True)+'\n',encoding='utf-8')


    def assert_actual_artifact_metadata_chain(self):
        """Real Store.get bytes, then native default JSON order and actual bits."""
        from hashlib import sha256
        import sys
        from hepta import hia_agent_store as reference_store
        from hepta.hia_agent_data_json_native import materialize_data,NativeAgentDataJson,SOURCE as DATA_SOURCE
        build=json.loads(Path(self.manifest).read_bytes())
        image_record=build['images']['data-json']
        image_raw=(Path(self.manifest).parent/image_record['path']).read_bytes()
        self.assertEqual(sha256(DATA_SOURCE.read_bytes()).hexdigest(),build['runtime_source_sha256']['examples/hia_bootstrap/agent_data_json.hepta'])
        self.assertEqual(len(image_raw),image_record['bytes'])
        self.assertEqual(sha256(image_raw).hexdigest(),image_record['sha256'])
        raw_decoder_oracle=NativeAgentDataJson(image_raw,image_record['sha256'])
        evidence=self.evidence/'artifact-metadata-chain'
        evidence.mkdir(mode=0o700)
        huge=b'1'*641
        maximum=b'"'+b'a'*((8<<20)-2)+b'"'
        cases=(
            ('mixed',b'{"z":1.25,"a":-0.0,"sub":5e-324,"under":-1e-4000,"int":-0,"v":[null,true,false],"s":"\\u007f\\u00e9\\ud83d\\ude42\\u0000"}','text',None),
            ('blob',b'{"n":0.10000000000000001,"v":[1,-1,2.2250738585072014e-308]}','blob',None),
            ('malformed',b'{','text',None),
            ('utf8-start',b'\xff','blob',None),
            ('utf8-continuation',b'"\xe2A"','blob',None),
            ('utf8-tail',b'"\xf0\x9f','blob',None),
            ('utf8-before-syntax',b'{\xff','blob',None),
            ('utf8-before-byte-budget',b' '*(8<<20)+b'\xff','blob',None),
            ('byte-budget',b' '*((8<<20)+1),'text',None),
            ('maximum-bytes',maximum,'text',None),
            ('grammar-before-overflow',b'[1e999,]','text',None),
            ('duplicate-before-overflow',b'{"x":1e999,"x":2}','text',None),
            ('escaped-duplicate',b'{"a":1,"\\u0061":2}','text',None),
            ('high-surrogate',b'"\\ud800"','text',None),
            ('low-surrogate',b'"\\udc00"','text',None),
            ('number-looking-strings',b'["1e999","a\\\"2.3\\\\4e5",-1.2e+3,0.0]','text',None),
            ('incomplete-fraction',b'1.','text',None),
            ('incomplete-exponent',b'1e+','text',None),
            ('grammar-before-int-limit',b'['+huge+b',]','text',640),
            ('int-before-overflow',b'['+huge+b',1e999]','text',640),
            ('overflow-before-int',b'[1e999,'+huge+b']','text',640),
            ('source-order-not-sorted-wire',b'{"z":'+huge+b',"a":1e999}','text',640),
            ('int-limit-exact',b'1'*640,'text',640),
            ('unlimited-int',b'1'*5000,'text',0),
            ('depth-before-overflow',b'['*129+b'1e999'+b']'*129,'text',None),
            ('maximum-nodes',b'['+b'null,'*262142+b'null]','text',None),
            ('node-budget',b'['+b'null,'*262143+b'null]','text',None),
            ('integer-storage',17,'integer',None),
            ('float-storage',1.25,'real',None),
            ('null-storage',None,'null',None),
            ('digest-before-metadata',b'{','text',None),

            ('double-minus-root',b'--1.2','text',None),
            ('merged-int-root',b'123-1.2','text',None),
            ('merged-int-array',b'[123-1.2]','text',None),
            ('merged-int-object',b'{"x":123-1.2}','text',None),
            ('overflow-before-late-syntax',b'[1e309,--1.2]','text',None),
            ('int-limit-before-late-syntax',b'['+huge+b',--1.2]','text',640),
            ('late-syntax-before-overflow',b'[--1.2,1e309]','text',None),
            ('unicode-line-json-position','{"é":"𝄞",\r\n"x":1-1.2}'.encode('utf-8'),'text',None),
            ('raw-escape-json-position',b'{"x":"\\n\\u0061",\r\n"z":--1.2}','text',None),
            ('int-limit-before-merged-extra',b'['+huge+b'-1.2]','text',640),
            ('negative-merged-extra',b'-123-1.2','text',None),
        )
        def rows(database):
            with sqlite3.connect(database) as connection:
                names=[row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                return {name:connection.execute('SELECT * FROM "'+name+'" ORDER BY rowid').fetchall()
                        for name in names}
        observed=[]
        original_limit=sys.get_int_max_str_digits()
        selectors=('HEPTA_HIA_AGENT_DATA_JSON_MANIFEST','HEPTA_HIA_AGENT_BINARY64_MANIFEST','HEPTA_HIA_JSON_PREFLIGHT_MANIFEST')
        try:
            for label,raw,storage,limit in cases:
                with self.subTest(artifact_metadata=label):
                    if limit is not None:sys.set_int_max_str_digits(limit)
                    else:sys.set_int_max_str_digits(original_limit)
                    actual_limit=sys.get_int_max_str_digits()
                    case=evidence/label;case.mkdir(mode=0o700)
                    store=AgentStore(self.root/('metadata-'+label))
                    data=b'actual metadata artifact '+label.encode('ascii')
                    ref=store.put(data,'program',{})
                    # Declared negative fixtures must carry actual SQLite classes.
                    # TEXT affinity would otherwise stringify int/float, and the
                    # official NOT NULL column cannot physically hold NULL.
                    if storage in ('integer','real','null'):
                        store.db.execute('CREATE TABLE artifacts_observed (id TEXT PRIMARY KEY,sha256 TEXT NOT NULL,uri TEXT UNIQUE NOT NULL,kind TEXT NOT NULL,metadata,content_key TEXT UNIQUE NOT NULL)')
                        store.db.execute('INSERT INTO artifacts_observed SELECT * FROM artifacts')
                        store.db.execute('DROP TABLE artifacts')
                        store.db.execute('ALTER TABLE artifacts_observed RENAME TO artifacts')
                    value=raw.decode('utf-8')if storage=='text'else sqlite3.Binary(raw)if storage=='blob'else raw
                    store.db.execute('UPDATE artifacts SET metadata=? WHERE id=?',(value,ref['id']))
                    actual_storage=store.db.execute('SELECT typeof(metadata) FROM artifacts WHERE id=?',(ref['id'],)).fetchone()[0]
                    self.assertEqual(actual_storage,storage)
                    if label=='digest-before-metadata':
                        path=store.artifacts/ref['sha256']
                        path.chmod(0o600);path.write_bytes(b'!'+data[1:]);path.chmod(0o400)
                    checked=[]
                    original_preflight=reference_store.preflight_hia_json
                    def actual_preflight(text,**budgets):
                        checked.append((text.encode('utf-8'),dict(budgets)))
                        return original_preflight(text,**budgets)
                    expected_error=None;expected_value=None
                    with patch.dict(os.environ,{name:''for name in selectors}),patch.object(reference_store,'preflight_hia_json',actual_preflight):
                        try:
                            actual_data,expected_value=store.get(ref,kind='program')
                            self.assertEqual(actual_data,data)
                        except (ValueError,TypeError,OverflowError,OSError,sqlite3.Error)as error:
                            expected_error={'code':getattr(error,'code','E_HIA_REJECTED'),'message':str(error)}
                    database=store.database;store.close()
                    before=rows(database)
                    fields=tuple(ref[key].encode('utf-8')for key in('id','sha256','uri'))+(b'program',struct.pack('<QQ',1,actual_limit))
                    request=packet(6,fields);(case/'request.bin').write_bytes(request)
                    with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')), \
                         patch('hepta.hia_agent_store.AgentStore.get',side_effect=AssertionError('host artifact owner forbidden')), \
                         patch('hepta.hia_agent_store.stable_read',side_effect=AssertionError('host file policy forbidden')), \
                         patch('hepta.hia_agent_store.decode_data',side_effect=AssertionError('host JSON owner forbidden')):
                        with NativeSqliteStore(self.manifest,database,evidence=case/'native',allow_development=self.development)as native:
                            with native._lock:
                                native._write(request)
                                response=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
                    (case/'response.bin').write_bytes(response)
                    words,result=decode_packet(response,EFFECT_MAGIC)
                    records=trace_records((case/'native/native-trace.bin').read_bytes())
                    effects=[r for r in records if r['kind']==2]
                    self.assertEqual(records[-1]['words'][1],12)
                    self.assertEqual(rows(database),before)
                    self.assertEqual(words[1],0);self.assertEqual(words[9],0)
                    preflight=[r for r in effects if r['words'][1]==30]
                    self.assertEqual(len(preflight),len(checked))
                    for call,(wire,budgets)in zip(preflight,checked):
                        self.assertEqual(call['fields'],(wire,))
                        self.assertEqual(call['words'][8:10],(budgets['max_nodes'],budgets['max_depth']))
                    decoders=[r for r in effects if r['words'][1]==31]
                    floats=[r for r in effects if r['words'][1]==32]
                    if expected_error is not None:
                        self.assertEqual(words[8],18)
                        actual=json.loads(result[0])
                        self.assertEqual({key:actual[key]for key in('code','message')},expected_error)
                    else:
                        self.assertEqual(words[8],19)
                        self.assertEqual(len(result),1)
                        output=result[0]
                        header=struct.unpack_from('<16Q',output)
                        self.assertEqual(header[0:2],(int.from_bytes(b'HIASAF02','little'),2))
                        self.assertEqual(header[2:5],(len(data),len(raw),3 if storage=='text'else 4))
                        self.assertEqual(header[10],1);self.assertEqual(header[14],actual_limit);self.assertEqual(header[15],0)
                        self.assertEqual(header[13],header[12]*8)
                        cursor=128
                        self.assertEqual(output[cursor:cursor+len(data)],data);cursor+=len(data)
                        self.assertEqual(output[cursor:cursor+len(raw)],raw);cursor+=len(raw)
                        for index,key in enumerate(('id','sha256','uri','kind')):
                            expected=b'program' if key=='kind' else ref[key].encode('utf-8')
                            self.assertEqual(header[5+index],len(expected))
                            self.assertEqual(output[cursor:cursor+len(expected)],expected);cursor+=len(expected)
                        arena=output[cursor:cursor+header[11]];cursor+=header[11]
                        bits=output[cursor:cursor+header[13]];cursor+=header[13]
                        self.assertEqual(cursor,len(output))
                        self.assertEqual(materialize_data(arena,raw),expected_value)
                        self.assertEqual(len(decoders),1);self.assertEqual(decoders[0]['fields'],(checked[0][0],))
                        expected_arena=raw_decoder_oracle.arena(raw,max_nodes=262144,max_depth=128)
                        self.assertEqual(arena,expected_arena)
                        self.assertEqual(bytes(raw_decoder_oracle._mapping),image_raw)
                        float_spans=[]
                        for index in range(header[12]):
                            tag,parent,sibling,start,extent,key,key_size=struct.unpack_from('<7Q',arena,64+index*56)
                            actual_bits=bits[index*8:index*8+8]
                            if tag==7:
                                span=raw[start:start+extent]
                                self.assertEqual(actual_bits,struct.pack('<d',float(span.decode('ascii'))))
                                float_spans.append(span)
                            else:self.assertEqual(actual_bits,b'\0'*8)
                        self.assertEqual([r['fields'][0]for r in floats],float_spans)
                        (case/'arena.bin').write_bytes(arena);(case/'number-bits.bin').write_bytes(bits)
                    self.assertTrue(all(r['words'][1] != 10 for r in effects))
                    observed.append({'label':label,'actual_int_max_str_digits':actual_limit,
                        'error':expected_error,'actual_default_Store_get_oracle':True,
                        'real_SQL_file_SHA_then_metadata':True,'preflight_actual_wire_equal':True,
                        'actual_decimal_component_calls':len(floats),'all_database_tables_preserved':True,
                        'successful_arena_equals_actual_raw_decoder_bytes':expected_error is None,
                        'whole_rollback_complete':False,'ordinary_public_adapter_exposed':False})
        finally:
            sys.set_int_max_str_digits(original_limit)
            (evidence/'observations.json').write_text(json.dumps({'schema':'hepta.hia.sqlite-artifact-metadata-chain.v1',
                'cases_declared':len(cases),'observations':observed},indent=2,sort_keys=True)+'\n')

    def assert_actual_artifact_fd_and_sha_chain(self):
        """Actual SQL rows and fd/SHA effects; metadata/Core stay explicit raw dependencies."""
        from hashlib import sha256
        import stat
        import threading
        from hepta.hia_agent_store import stable_read
        evidence=self.evidence/'artifact-file-chain'
        evidence.mkdir(mode=0o700)
        labels=(
            ('small',19),('empty',0),('chunk-minus',65535),('chunk',65536),
            ('chunk-plus',65537),('maximum',64<<20),
            ('identity-before-file',29),('kind-before-file',31),
            ('missing',37),('symlink',41),('directory',43),('fifo',47),
            ('over-limit',53),('corrupt-before-metadata',59),
            ('raw-metadata-dependency',61),('blob-metadata-dependency',67),
            ('metadata-text-before-identity',71),('ignored-column-text',73),
            ('changed-while-read',16<<20),
        )
        observations=[]
        for label,extent in labels:
            with self.subTest(artifact_fd=label):
                case=evidence/label
                case.mkdir(mode=0o700)
                root=self.root/('artifact-'+label)
                store=AgentStore(root)
                data=(bytes(range(256))*((extent+255)//256))[:extent]
                metadata={'label':label,'finite':1.25,'negative_zero':-0.0,
                          'unicode':'\u007f\u00e9\U0001f642','nested':[True,None,17]}
                ref=store.put(data,'program',metadata)
                request_ref=deepcopy(ref)
                kind='program'
                path=store.artifacts/ref['sha256']
                stop=threading.Event()
                watcher=None
                watcher_errors=[]
                if label=='identity-before-file':
                    request_ref['uri']+='-not-issued'
                    path.unlink()
                elif label=='kind-before-file':
                    kind='native'
                    path.unlink()
                elif label=='missing':
                    path.unlink()
                elif label=='symlink':
                    actual=path.with_name('actual-'+path.name)
                    path.rename(actual);path.symlink_to(actual.name)
                elif label=='directory':
                    path.unlink();path.mkdir()
                elif label=='fifo':
                    path.unlink();os.mkfifo(path,0o400)
                elif label=='over-limit':
                    path.chmod(0o600)
                    with path.open('wb')as stream:stream.truncate((64<<20)+1)
                    path.chmod(0o400)
                elif label=='corrupt-before-metadata':
                    path.chmod(0o600);path.write_bytes(b'!'+data[1:]);path.chmod(0o400)
                    store.db.execute('UPDATE artifacts SET metadata=? WHERE id=?',('{',ref['id']))
                elif label=='raw-metadata-dependency':
                    store.db.execute('UPDATE artifacts SET metadata=? WHERE id=?',('{',ref['id']))
                elif label=='blob-metadata-dependency':
                    store.db.execute('UPDATE artifacts SET metadata=? WHERE id=?',
                                     (sqlite3.Binary(b'{"decimal":1.25,"negative":-0.0}'),ref['id']))
                elif label in ('metadata-text-before-identity','ignored-column-text'):
                    column='metadata'if label.startswith('metadata')else'content_key'
                    store.db.execute("UPDATE artifacts SET "+column+"=CAST(x'61ff62' AS TEXT) WHERE id=?",(ref['id'],))
                    request_ref['uri']+='-also-wrong'
                expected=None
                if label=='changed-while-read':
                    original_fstat=os.fstat
                    changed=[False]
                    def observed_fstat(fd):
                        result=original_fstat(fd)
                        if stat.S_ISREG(result.st_mode)and result.st_size==extent and not changed[0]:
                            changed[0]=True
                            os.utime(path,ns=(result.st_atime_ns,result.st_mtime_ns+1))
                        return result
                    try:
                        with patch('hepta.hia_agent_store.os.fstat',observed_fstat):
                            store.get(request_ref,kind=kind)
                    except (ValueError,TypeError,OSError,sqlite3.Error)as error:
                        expected={'code':getattr(error,'code','E_HIA_REJECTED'),'message':str(error)}
                    self.assertTrue(changed[0])
                    self.assertEqual(expected,{'code':'E_HIA_ARTIFACT_CHANGED','message':'artifact changed while it was read'})
                else:
                    try:
                        original_data,original_metadata=store.get(request_ref,kind=kind)
                        self.assertEqual(original_data,data)
                        expected={'data_sha256':sha256(original_data).hexdigest(),
                                  'metadata':original_metadata}
                    except (ValueError,TypeError,OSError,sqlite3.Error)as error:
                        expected={'code':getattr(error,'code','E_HIA_REJECTED'),'message':str(error)}
                # Save the actual storage class and bytes as fixture evidence,
                # never supply this row or a chosen SQL statement to the driver.
                row=store.db.execute('SELECT id,sha256,uri,kind,metadata,content_key FROM artifacts WHERE id=?',(ref['id'],))
                try:
                    saved_row=row.fetchone()
                except sqlite3.Error:
                    saved_row=None
                database=store.database
                store.close()
                frame=packet(5,tuple(request_ref[key].encode('utf-8')for key in('id','sha256','uri'))+
                             (kind.encode('utf-8'),struct.pack('<Q',1)))
                (case/'request.bin').write_bytes(frame)
                if label=='changed-while-read':
                    def mutate_after_actual_fstat():
                        trace_path=case/'native/native-trace.bin'
                        offset=0
                        pending=b''
                        try:
                            while not stop.wait(0.001):
                                if not trace_path.exists():continue
                                with trace_path.open('rb')as stream:
                                    stream.seek(offset);chunk=stream.read()
                                offset+=len(chunk);pending+=chunk
                                while len(pending)>=16:
                                    tag,size=struct.unpack_from('<QQ',pending)
                                    if len(pending)<16+size:break
                                    item=pending[16:16+size];pending=pending[16+size:]
                                    if tag==3 and len(item)>=280:
                                        words,fields=decode_packet(item,EVENT_MAGIC)
                                        if words[1]==18 and words[3]==0 and len(fields[0])==144:
                                            saved=struct.unpack_from('<Q',fields[0],48)[0]
                                            if saved==extent:
                                                current=path.stat()
                                                os.utime(path,ns=(current.st_atime_ns,current.st_mtime_ns+1))
                                                stop.set();return
                            raise AssertionError('actual first artifact fstat was not observed')
                        except BaseException as error:
                            watcher_errors.append(repr(error));stop.set()
                    watcher=threading.Thread(target=mutate_after_actual_fstat)
                    watcher.start()
                try:
                    with patch('sqlite3.connect',side_effect=AssertionError('host SQLite owner forbidden')), \
                         patch('hepta.hia_agent_store.stable_read',side_effect=AssertionError('host artifact reader forbidden')), \
                         patch.object(AgentStore,'get',side_effect=AssertionError('host Store.get owner forbidden')):
                        with NativeSqliteStore(self.manifest,database,evidence=case/'native',
                                allow_development=self.development)as native:
                            with native._lock:
                                native._write(frame)
                                returned=native._read_exact(struct.unpack('<Q',native._read_exact(8))[0])
                finally:
                    if watcher is not None:
                        stop.set();watcher.join(timeout=10)
                        self.assertFalse(watcher.is_alive())
                        self.assertEqual(watcher_errors,[])
                words,fields=decode_packet(returned,EFFECT_MAGIC)
                self.assertEqual((words[1],words[9],words[4:8],len(fields)),(0,0,(0,0,0,0),1))
                if words[8]==17:
                    self.assertIsNotNone(saved_row)
                    payload=fields[0]
                    header=struct.unpack_from('<12Q',payload)
                    self.assertEqual(header[0],int.from_bytes(b'HIASAF01','little'))
                    self.assertEqual((header[1],header[10],header[11]),(1,0,0))
                    self.assertEqual(header[2],len(data))
                    meta=saved_row[4]
                    meta_bytes=meta.encode('utf-8')if type(meta)is str else bytes(meta)
                    self.assertEqual((header[3],header[4]),(len(meta_bytes),3 if type(meta)is str else 4))
                    self.assertEqual(header[5:9],tuple(len(value.encode('utf-8'))for value in saved_row[:4]))
                    self.assertEqual(header[9],3)
                    self.assertEqual(payload[96:],data+meta_bytes+b''.join(value.encode('utf-8')for value in saved_row[:4]))
                    if label=='raw-metadata-dependency':
                        self.assertIn('code',expected)
                        self.assertEqual(meta_bytes,b'{')
                    else:
                        self.assertEqual(expected['data_sha256'],ref['sha256'])
                    # Prefix evidence never claims JSON metadata/whole Core admission.
                    complete=False
                else:
                    self.assertEqual(words[8],18)
                    observed=json.loads(fields[0])
                    self.assertEqual({key:observed[key]for key in('code','message')},expected)
                    complete=False
                (case/'response.bin').write_bytes(returned)
                records=trace_records((case/'native/native-trace.bin').read_bytes())
                effects=[record for record in records if record['kind']==2]
                self.assertEqual(effects[-1]['words'][1],12)
                sql=[record['fields'][0]for record in effects if record['words'][1]==4]
                self.assertEqual(sql[-1],b'SELECT * FROM artifacts WHERE id=?')
                self.assertFalse(any(value.startswith((b'INSERT INTO ',b'UPDATE ',b'DELETE '))for value in sql))
                opened=[record for record in effects if record['words'][1]==17]
                reads=[record for record in effects if record['words'][1]==19]
                hashes=[record for record in effects if record['words'][1]==28]
                closed=[record for record in effects if record['words'][1]==24]
                if label in ('identity-before-file','kind-before-file','metadata-text-before-identity','ignored-column-text'):
                    self.assertEqual((opened,reads,hashes,closed),([],[],[],[]))
                if words[8]==17:
                    self.assertEqual(len(opened),1);self.assertEqual(len(closed),1)
                    self.assertEqual([record['words'][8]for record in hashes][0],0)
                    self.assertEqual([record['words'][8]for record in hashes][-1],2)
                    self.assertTrue(all(0<record['words'][8]<=65536 for record in reads))
                    final_hash=next(i for i,record in enumerate(effects)if record['words'][1]==28 and record['words'][8]==2)
                    final_close=next(i for i,record in enumerate(effects)if record['words'][1]==24)
                    self.assertLess(final_close,final_hash)
                if label=='over-limit':
                    self.assertEqual(reads,[]);self.assertEqual(hashes,[])
                if label=='maximum':
                    self.assertEqual(len(reads),1025)
                    self.assertEqual(sum(record['words'][8]for record in reads),67108865)
                observations.append({'label':label,'extent':extent,'native_status':words[8],
                    'expected':expected,'request_sha256':sha256(frame).hexdigest(),
                    'response_sha256':sha256(returned).hexdigest(),
                    'actual_sqlite_selects':sql[-1].decode(),'real_file_effects':len(opened),
                    'read_effects':len(reads),'sha_effects':len(hashes),'close_effects':len(closed),
                    'whole_store_get_and_core_dependency_complete':complete,
                    'actual_native_file_prefix':True})
                (case/'observation.json').write_text(json.dumps(observations[-1],indent=2,sort_keys=True)+'\n')
                del records,effects,returned,fields,data
        (evidence/'observations.json').write_text(json.dumps({'cases':observations,
            'declared_cases':len(labels),'ordinary_call_adapter_exposed':False,
            'current_source_cold_qualified':False},indent=2,sort_keys=True)+'\n')


if __name__=='__main__':
    unittest.main()
