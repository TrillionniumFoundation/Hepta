"""Twenty new tiny-file source/IO controls, never provider or product work."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import io as memory_io
import json
import os
import struct
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('v92_view_common', ROOT / 'control/common.py')
c = importlib.util.module_from_spec(spec); sys.modules[spec.name] = c; spec.loader.exec_module(c)
fmt = c.module('v92_view_format', ROOT / 'control/view_format.py')
launch = c.module('v92_view_launch', ROOT / 'control/launch.py')

def digest(raw): return hashlib.sha256(raw).hexdigest()
def write(path, raw):
    path.write_bytes(raw); path.chmod(0o600); return path
def original_bytes():
    stream = memory_io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as z:
        z.writestr('nonselected.bin', b'complete-not-selected-original\0' * 13)
        z.writestr(fmt.PREFIX + 'callers-owner/stdout.log', b'actual fixture log\n')
        z.writestr('hia-cold.json', b'{"fixture":true}\n')
    return stream.getvalue()
def tiny_limits():
    return {'container': 4 << 20, 'selected': 4 << 20, 'metadata': 4 << 20,
            'parent': 4 << 20, 'reserve': 0, 'inodes': 0}
def fixture(root, raw=None):
    raw = original_bytes() if raw is None else raw
    pieces = [raw[:len(raw)//3], raw[len(raw)//3:2*len(raw)//3], raw[2*len(raw)//3:]]
    parts, observed, cursor = [], [], 0
    for i, piece in enumerate(pieces):
        p = {'ordinal': i, 'name': 'part-%02d.bin' % i, 'offset': cursor, 'bytes': len(piece), 'sha256': digest(piece)}
        parts.append(p); observed.append({**p, 'retained': {'bytes': len(piece), 'sha256': digest(piece)}}); cursor += len(piece)
    old = {'status': 'FULL_ZIP_CUSTODY_HOLD', 'parts': observed}
    old_raw = c.io.wire(old)
    controls = {'controls/fixed-%02d.json' % i: c.io.wire({'fixture': i}) for i in range(11)}
    policy = {'original_artifact': {'id': 901, 'bytes': len(raw), 'sha256': digest(raw)},
              'receiver': {'run_id': 902, 'workflow_commit': 'a'*40, 'control_commit': 'b'*40, 'policy_sha256': 'c'*64},
              'diagnostics': dict(fmt.LIMITS)}
    paths = []
    for i, (part, piece) in enumerate(zip(parts, pieces)):
        record = {'schema': 'hia.v92-original-zip-part.v1', 'artifact': policy['original_artifact'],
                  'expected': {k: part[k] for k in ('ordinal','name','offset','bytes')}, 'observed': old['parts'][i],
                  'status': 'FULL_ZIP_CUSTODY_HOLD', 'run_id': 902, 'run_attempt': 1,
                  'workflow_commit': 'a'*40, 'control_commit': 'b'*40, 'policy_sha256': 'c'*64,
                  'qualification_executed': False, 'artifact_upload_not_yet_observed': True}
        mapping = {**controls, 'FINAL.json': old_raw, 'PART.json': c.io.wire(record), 'slice.bin': piece}
        path = root / ('container-%d.zip' % i)
        paths.append(path); emit(path, mapping)
        body = path.read_bytes(); part['artifact'] = {'id': 910+i, 'bytes':len(body), 'sha256':digest(body)}
    return {'raw':raw, 'parts':parts, 'old':old_raw, 'controls':controls, 'policy':policy, 'paths':paths}
def emit(path, mapping, descriptor=False, compressed_slice=False):
    class Streaming(memory_io.BytesIO):
        def seekable(self): return False
        def seek(self, *_): raise OSError('synthetic nonseekable sink')
    target = Streaming() if descriptor else memory_io.BytesIO()
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED) as z:
        for name, raw in mapping.items():
            z.writestr(name,raw,compress_type=zipfile.ZIP_DEFLATED if compressed_slice and name=='slice.bin' else zipfile.ZIP_STORED)
    return write(path,target.getvalue())
def revise_pin(f, index=0):
    b=f['paths'][index].read_bytes();f['parts'][index]['artifact'].update(bytes=len(b),sha256=digest(b))
def mapping(path):
    with zipfile.ZipFile(path) as z:return {x.filename:z.read(x) for x in z.infolist()}
def outer(f,index=0):
    return fmt.outer_container(f['paths'][index],f['parts'][index],f['old'],f['controls'],f['policy'],time.monotonic()+20)
def specs(f):
    result=[]
    for i,p in enumerate(f['parts']):
        row=outer(f,i)
        result.append({'ordinal':i,'path':str(f['paths'][i]),'offset':p['offset'],'bytes':p['bytes'],
                       'data_offset':row['range']['physical_data_offset'],'identity':row['container']['identity']})
    return result
def roots_budgets(root):
    roots={key:root/key for key in ('tmp','workspace')}
    for path in [*roots.values(),roots['tmp']/'selected',roots['workspace']/'readback']:path.mkdir(mode=0o700)
    budgets={key:c.VolumeBudget(path,tiny_limits()) for key,path in roots.items()}
    return roots,budgets

class StoredContainerControls(unittest.TestCase):
    def test_01_cross_boundary_seek_exact_whole_original(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d)); s=specs(f)
            with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:
                self.assertEqual(v.whole_hash(),{'bytes':len(f['raw']),'sha256':digest(f['raw'])})
                for point in [0,s[1]['offset']-1,s[1]['offset'],s[2]['offset']-1,len(f['raw'])-1]:
                    v.seek(point);self.assertEqual(v.read(7),f['raw'][point:point+7])
                v.seek(0,2);self.assertEqual(v.read(1),b'')

    def test_02_all_fourteen_bodies_and_signed_descriptors(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));emit(f['paths'][0],mapping(f['paths'][0]),descriptor=True);revise_pin(f)
            row=outer(f);self.assertEqual(len(row['members']),14);self.assertTrue(row['whole_original_container_read'])

    def test_03_duplicate_container_member_refused(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with zipfile.ZipFile(f['paths'][0],'a') as z:z.writestr('PART.json',b'{}')
            revise_pin(f)
            with self.assertRaises(c.io.Refusal):outer(f)

    def test_04_descriptor_crc_mismatch_refused(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));emit(f['paths'][0],mapping(f['paths'][0]),descriptor=True)
            raw=bytearray(f['paths'][0].read_bytes());at=raw.index(b'PK\x07\x08');raw[at+4]^=1
            write(f['paths'][0],raw);revise_pin(f)
            with self.assertRaises(c.io.Refusal):outer(f)

    def test_05_trailing_container_bytes_refused(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));write(f['paths'][0],f['paths'][0].read_bytes()+b'not-an-end-record');revise_pin(f)
            with self.assertRaises(c.io.Refusal):outer(f)

    def test_06_central_local_name_disagreement_refused(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));raw=bytearray(f['paths'][0].read_bytes());raw[30]^=1;write(f['paths'][0],raw);revise_pin(f)
            with self.assertRaises((c.io.Refusal,zipfile.BadZipFile)):outer(f)

    def test_07_compressed_slice_never_becomes_a_view(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));emit(f['paths'][0],mapping(f['paths'][0]),compressed_slice=True);revise_pin(f)
            with self.assertRaises(c.io.Refusal):outer(f)

    def test_08_range_sha_not_inherited_from_parent_statement(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));m=mapping(f['paths'][0]);m['slice.bin']=bytes([m['slice.bin'][0]^1])+m['slice.bin'][1:]
            emit(f['paths'][0],m);revise_pin(f)
            with self.assertRaises(c.io.Refusal):outer(f)

    def test_09_part_bool_or_other_run_cannot_equal_original_int(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));original=mapping(f['paths'][0])
            for field,value in [('run_attempt',True),('run_id',999)]:
                m=dict(original);record=json.loads(m['PART.json']);record[field]=value;m['PART.json']=c.io.wire(record)
                emit(f['paths'][0],m);revise_pin(f)
                with self.subTest(field=field),self.assertRaises(c.io.Refusal):outer(f)

    def test_10_view_rejects_gap_overlap_reordering_and_bool(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));old=specs(f)
            variants=[]
            for delta in (-1,1):
                s=copy.deepcopy(old);s[1]['offset']+=delta;variants.append(s)
            s=copy.deepcopy(old);s[0]['offset']=False;variants.append(s)
            s=copy.deepcopy(old);s[0],s[1]=s[1],s[0];variants.append(s)
            for s in variants:
                with self.assertRaises(c.io.Refusal):fmt.StoredView(s,len(f['raw']),time.monotonic()+20)

    def test_11_truncated_held_container_never_reads_zero_fill(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));s=specs(f)
            with self.assertRaises(c.io.Refusal):
                with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:
                    with f['paths'][0].open('r+b') as out:out.truncate(32)
                    v.whole_hash()

    def test_12_full_original_selection_and_explicit_missing_readback(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);f=fixture(root);s=specs(f);roots,budgets=roots_budgets(root)
            with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:
                actual=fmt.inspect_original(v,f['policy'],roots,budgets,time.monotonic()+20)
            self.assertEqual(actual['members'],3);self.assertEqual(len(actual['selected']),2)
            self.assertIn(fmt.PREFIX+'callers/integer-report.json',actual['missing_expected'])
            with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:
                reread=fmt.inspect_original(v,f['policy'],roots,budgets,time.monotonic()+20,verify=True)
            self.assertEqual(actual,reread)

    def test_13_nonselected_original_crc_is_not_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);raw=bytearray(original_bytes());at=raw.index(b'complete-not-selected-original');raw[at]^=1
            f=fixture(root,bytes(raw));s=specs(f);roots,budgets=roots_budgets(root)
            with self.assertRaises((c.io.Refusal,zipfile.BadZipFile)):
                with fmt.StoredView(s,len(raw),time.monotonic()+20) as v:fmt.inspect_original(v,f['policy'],roots,budgets,time.monotonic()+20)
            index=json.loads((roots['workspace']/'readback/INDEX.json').read_bytes())
            self.assertEqual(index['status'],'HOLD');self.assertFalse(index['complete_all_member_bodies'])

    def test_14_truncated_or_duplicate_inventory_refused(self):
        for mutate in ('truncate','duplicate'):
            with self.subTest(mutate=mutate),tempfile.TemporaryDirectory() as d:
                root=Path(d);f=fixture(root);s=specs(f);roots,budgets=roots_budgets(root)
                with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:fmt.inspect_original(v,f['policy'],roots,budgets,time.monotonic()+20)
                path=roots['workspace']/'readback/FULL-INVENTORY.jsonl';raw=path.read_bytes()
                write(path,raw[:-1] if mutate=='truncate' else raw+raw.splitlines(keepends=True)[-1])
                with self.assertRaises(c.io.Refusal):
                    with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:fmt.inspect_original(v,f['policy'],roots,budgets,time.monotonic()+20,verify=True)

    def test_15_single_deadline_expiration_refuses_after_seek(self):
        with tempfile.TemporaryDirectory() as d:
            f=fixture(Path(d));s=specs(f)
            with fmt.StoredView(s,len(f['raw']),time.monotonic()+20) as v:
                v.seek(0)
                with patch.object(c.io.time,'monotonic',return_value=v.deadline+1),self.assertRaises(c.io.Refusal):v.read(1)
        for value in (True,float('inf'),float('nan'),-1,721):
            with self.assertRaises(c.io.Refusal):c.io.require_elapsed(value,720)

    def test_16_future_capacity_is_not_freed_by_a_reservation(self):
        with tempfile.TemporaryDirectory() as d:
            limits={'container':100,'selected':50,'metadata':10,'parent':10,'reserve':512,'inodes':4}
            budget=c.VolumeBudget(Path(d),limits)
            fake=types.SimpleNamespace(f_bavail=682,f_frsize=1,f_favail=4)
            with patch.object(c.os,'statvfs',return_value=fake):
                budget.reserve(100,'container');self.assertEqual(budget.capacity()['remaining_reserved_bytes'],170)
                fake.f_bavail=681
                with self.assertRaises(c.io.Refusal):budget.capacity()
                fake.f_bavail=632;budget.written['container']=50
                self.assertEqual(budget.capacity()['remaining_reserved_bytes'],120)
                fake.f_favail=3
                with self.assertRaises(c.io.Refusal):budget.capacity()

    def test_17_closed_nonzero_not_unknown_and_not_natural(self):
        req={'command':['fixed'],'cwd':'/fixed','source_identities':{'a':'b'}};policy={'lifecycle_implementation_sha256':'c'}
        life={'qualification_seconds':900,'cleanup_seconds':3,'subreaper_enabled':True,'event_overflow':False,
              'cleanup':{'complete':True,'observed_echild':True,'leader_reaped':True,'remaining_direct_children':[],
                         'deadline_exceeded':False,'errors':[]},'status':'QUALIFICATION_FAILED','returncode':1}
        guard={'schema':'hepta.hia.external-qualification-guardian.v1','command':req['command'],'cwd':req['cwd'],
               'source_identities_before':req['source_identities'],'external_controller_seconds':900,
               'lifecycle_implementation_sha256':'c','lifecycle':life}
        self.assertTrue(launch.bound_closed(guard,req,policy));self.assertFalse(launch.natural(guard,req,1))
        life['cleanup']['remaining_direct_children']=[123]
        self.assertFalse(launch.bound_closed(guard,req,policy))
        bad=copy.deepcopy(req);bad['cwd']='/other'
        with self.assertRaises(c.io.Refusal):launch.bound_closed(guard,bad,policy)

    def test_18_parent_chain_symlink_and_file_alias_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'real').mkdir();write(root/'real/data',b'original');(root/'link').symlink_to('real',target_is_directory=True)
            with self.assertRaises(OSError):c.seal(root/'link/data',100)
            os.link(root/'real/data',root/'alias')
            with self.assertRaises(c.io.Refusal):c.seal(root/'real/data',100)

    def test_19_source_selection_is_unchanged_and_filename_canonical(self):
        self.assertTrue(fmt.selected('hia-cold.json'));self.assertTrue(fmt.selected(fmt.PREFIX+'x/a.stderr.log'))
        self.assertFalse(fmt.selected('elsewhere/report.json'));self.assertFalse(fmt.selected(fmt.PREFIX+'image.bin'))
        for name in ('../x','/x','x//y','x/./y','x/../y','x\\y','x\0y'):
            with self.assertRaises(c.io.Refusal):fmt.name_ok(name)
        self.assertEqual(fmt.LIMITS['maximum_selected_bytes'],128<<20)
        self.assertEqual(fmt.LIMITS['maximum_expanded_bytes'],8<<30)

    def test_20_single_failed_fake_get_has_safe_receipt_and_no_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);volume=c.VolumeBudget(root,tiny_limits());adapter=c.DownloadBudget(volume,root,3)
            sentinel=c.io.urllib.error.URLError('https://fixture-secret.invalid/?token=fixture-secret')
            calls=[]
            class FakeClient:
                def open(self,*args,**kw):calls.append(1);raise sentinel
            with patch.object(c.io,'configured_provider_client',return_value=FakeClient()):
                try:c.io.download('https://sdmntprfixture.oaiusercontent.com/a?fixture',{'id':7,'bytes':3,'sha256':digest(b'abc')},root,adapter,time.monotonic()+20,{})
                except BaseException as actual:self.assertIs(actual,sentinel)
                else:self.fail('original fake GET error suppressed')
            raw=(root/'DOWNLOAD.json').read_bytes();record=json.loads(raw)
            self.assertEqual(calls,[1]);self.assertEqual(record['get_attempts'],1);self.assertEqual(record['status'],'HOLD')
            self.assertNotIn(b'fixture-secret',raw);self.assertFalse(record['direct_fallback_after_proxy_error'])
