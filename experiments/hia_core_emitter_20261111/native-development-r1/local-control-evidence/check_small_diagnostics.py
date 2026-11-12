"""Finite synthetic transport controls; no product/phase/context admission is run."""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('frozen_small_diagnostics',ROOT/'small_diagnostics.py')
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
EXPECTED={'control_commit':'0'*40,'workflow_commit':'1'*40,'run_id':1,'run_attempt':1,
          'policy_sha256':'2'*64,'candidate':{'commit':'3'*40,'tree':'4'*40,'leaves':4030}}
CHECKS=[]
def case(name, function):
    start=time.monotonic()
    function()
    CHECKS.append({'name':name,'status':'PASS','seconds':time.monotonic()-start})
def rejected(raw):
    try: M.decode_full(raw,EXPECTED)
    except Exception: return
    raise AssertionError('malformed synthetic stream was accepted')
def line(kind,value):
    return (M.FULL_PREFIX+kind+' '+json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def full(bodies=None,closed=True):
    bodies=dict(bodies or {})
    records=[line('DIAGNOSTIC_BEGIN',{'schema':'hia.core-emitter-native-diagnostic.v1',**EXPECTED,
        'maximum_original_raw_bytes':M.MAX_FULL_RAW,'maximum_stdout_bytes':M.MAX_FULL,
        'frame_bytes':M.FULL_FRAME_BYTES,'fixed_file_count':35,'directory_scans':0,
        'product_execution':False,'original_exit_status_modified':False,'frames_are_original_bytes':True})]
    boundary={'closed_current_phase_ECHILD':{'preparation':closed,'tests':closed},
              'error_type_by_phase':{},'natural_success_inferred':False}
    records.append(line('DIAGNOSTIC_BOUNDARY',boundary))
    observations={}
    total=0
    for name in M.fixed_names():
        phase=M.gated_phase(name)
        if phase and not closed:
            records.append(line('ORIGINAL_UNAVAILABLE',{'name':name,
                'status':'CLOSED_CURRENT_PHASE_NOT_PROVEN','phase':phase,
                'observed_sha256':None,'observed_bytes':None,'original_bytes_printed':0}))
            continue
        raw=bodies.get(name,b'{}' if name.endswith('.json') else b'synthetic\x00log\n')
        pin=M.pins(raw)
        count=(len(raw)+M.FULL_FRAME_BYTES-1)//M.FULL_FRAME_BYTES
        records.append(line('ORIGINAL_BEGIN',{'name':name,**pin,'frame_bytes':M.FULL_FRAME_BYTES,'frame_count':count}))
        for index,offset in enumerate(range(0,len(raw),M.FULL_FRAME_BYTES)):
            chunk=raw[offset:offset+M.FULL_FRAME_BYTES]
            records.append(line('ORIGINAL_FRAME',{'name':name,'index':index,'offset':offset,'bytes':len(chunk),
                'sha256':hashlib.sha256(chunk).hexdigest(),'base64':base64.b64encode(chunk).decode()}))
        records.append(line('ORIGINAL_END',{'name':name,'bytes':len(raw),'sha256':pin['sha256'],'frame_count':count}))
        observations[name]={'status':'COMPLETE_ORIGINAL_READ',**pin}
        total+=len(raw)
    records.append(line('DIAGNOSTIC_END',{'original_raw_byte_budget_reserved':total,
        'verified_original_bytes_read':total,'original_raw_bytes_printed':total,
        'maximum_raw_bytes':M.MAX_FULL_RAW,'maximum_stdout_bytes':M.MAX_FULL,
        'closed_current_phase_ECHILD':boundary['closed_current_phase_ECHILD'],
        'fixed_file_observations':observations,'original_exit_status_modified':False,
        'native_or_cold_qualification_claimed':False}))
    return b''.join(records)
VALID=full()
def mutate(kind, change):
    rows=VALID.splitlines(keepends=True)
    prefix=(M.FULL_PREFIX+kind+' ').encode()
    for index,row in enumerate(rows):
        if row.startswith(prefix):
            value=json.loads(row[len(prefix):])
            change(value)
            rows[index]=line(kind,value)
            return b''.join(rows)
    raise AssertionError('missing synthetic marker')
def normal():
    sources,ledger,boundary,end=M.decode_full(VALID,EXPECTED)
    assert len(sources)==len(ledger)==35 and all(boundary['closed_current_phase_ECHILD'].values())
    assert end['original_raw_bytes_printed']==sum(map(len,sources.values()))
case('complete_35_whole_originals',normal)
def empty():
    sources,_,_,_=M.decode_full(full({name:b'' for name in M.fixed_names()}),EXPECTED)
    assert len(sources)==35 and set(sources.values())=={b''}
case('zero_byte_original_frames',empty)
def multiple():
    body=bytes(range(256))*257
    sources,_,_,_=M.decode_full(full({'stage/prepare.stdout.log':body}),EXPECTED)
    assert sources['stage/prepare.stdout.log']==body
case('multi_frame_binary_exact_bytes',multiple)
def unclosed():
    sources,ledger,boundary,_=M.decode_full(full(closed=False),EXPECTED)
    assert not any(boundary['closed_current_phase_ECHILD'].values())
    assert all(not M.gated_phase(name) for name in sources)
    assert all(ledger[name]['full_channel_status']=='CLOSED_CURRENT_PHASE_NOT_PROVEN'
               for name in M.fixed_names() if M.gated_phase(name))
case('unclosed_phase_originals_unavailable',unclosed)
case('reject_wrong_operation',lambda:rejected(mutate('DIAGNOSTIC_BEGIN',lambda row:row.update(run_id=2))))
case('reject_frame_hash',lambda:rejected(mutate('ORIGINAL_FRAME',lambda row:row.update(sha256='0'*64))))
case('reject_frame_offset',lambda:rejected(mutate('ORIGINAL_FRAME',lambda row:row.update(offset=1))))
case('reject_whole_git_blob',lambda:rejected(mutate('ORIGINAL_BEGIN',lambda row:row.update(git_blob_sha1='0'*40))))
case('reject_wrong_fixed_file_name',lambda:rejected(mutate('ORIGINAL_BEGIN',lambda row:row.update(name='outside'))))
case('reject_missing_terminal',lambda:rejected(b''.join(VALID.splitlines(keepends=True)[:-1])))
case('reject_missing_final_newline',lambda:rejected(VALID[:-1]))
case('reject_duplicate_object_key',lambda:rejected(VALID.replace(b'"run_id":1',b'"run_id":1,"run_id":1',1)))
case('reject_invalid_utf8',lambda:rejected(VALID.replace(b'DIAGNOSTIC_BEGIN',b'DIAGNOSTIC_BEGI\xff',1)))
case('reject_extra_trailing_record',lambda:rejected(VALID+VALID.splitlines(keepends=True)[0]))
case('reject_oversize_original_header',lambda:rejected(mutate('ORIGINAL_BEGIN',lambda row:row.update(bytes=M.MAX_FULL_RAW+1))))
def interrupted():
    class Broken:
        def __init__(self): self.buffer=self;self.calls=0
        def write(self,raw): self.calls+=1;raise KeyboardInterrupt('synthetic partial-write interruption')
        def flush(self): pass
    original=sys.stdout
    sink=Broken()
    try:
        M.stdout_bytes_reserved=0
        sys.stdout=sink
        try:M.write_stdout(b'x'*M.MAX_STDOUT)
        except KeyboardInterrupt:pass
        else:raise AssertionError('interruption missing')
        assert M.stdout_bytes_reserved==M.MAX_STDOUT and sink.calls==1
        try:M.write_stdout(b'x')
        except RuntimeError:pass
        else:raise AssertionError('stdout budget replay allowed')
        assert sink.calls==1
    finally:
        sys.stdout=original
        M.stdout_bytes_reserved=0
case('stdout_reservation_survives_interruption',interrupted)
def selection():
    folder=ROOT/'synthetic-custody'
    folder.mkdir(mode=0o700)
    large=json.dumps({'padding':'x'*600000}).encode()
    owner=json.dumps({'padding':'y'*300000}).encode()
    (folder/(M.FULL_NAME+'.stdout.log')).write_bytes(full({
        'FINAL.json':large,'tests-guard/guardian.json':owner}))
    (folder/(M.FULL_NAME+'.stderr.log')).write_bytes(b'')
    class Capture:
        def __init__(self): self.buffer=io.BytesIO()
        def flush(self): pass
    saved_current=M.current
    saved_argv=sys.argv
    saved_stdout=sys.stdout
    sink=Capture()
    try:
        M.current=lambda args:(folder,{},EXPECTED)
        sys.argv=['synthetic','--policy-sha256','2'*64,'--control-commit','0'*40]
        sys.stdout=sink
        M.stdout_bytes_reserved=0
        rc=M.main()
    finally:
        M.current=saved_current
        sys.argv=saved_argv
        sys.stdout=saved_stdout
        M.stdout_bytes_reserved=0
    assert rc==0
    output=sink.buffer.getvalue()
    assert output==(folder/(M.SMALL_NAME+'.stdout.log')).read_bytes()
    assert len(output)<=M.MAX_STDOUT
    manifest=json.loads((folder/(M.SMALL_NAME+'.manifest.json')).read_bytes())
    result_raw=(folder/(M.SMALL_NAME+'.RESULT.json')).read_bytes()
    result=json.loads(result_raw)
    assert manifest['fixed_original_file_count']==35
    assert manifest['all_35_originals_claimed_in_small_channel'] is False
    assert manifest['native_or_cold_qualification_claimed'] is False
    assert manifest['whole_file_ledger']['FINAL.json']['small_channel_status']=='WHOLE_ORIGINAL_OMITTED_SMALL_RAW_BUDGET'
    assert manifest['whole_file_ledger']['FINAL.json']['sha256']==hashlib.sha256(large).hexdigest()
    assert all(row['name']!='FINAL.json' for row in manifest['selected_files'])
    assert sum(row['bytes'] for row in manifest['selected_files'])<=M.MAX_RAW
    assert manifest['selected_files'][0]['kind']=='DERIVED_PROJECTION_NOT_AN_ORIGINAL'
    last=json.loads(output.splitlines()[-1].split(b' ',1)[1])
    assert last['result_original']==M.pins(result_raw)
    assert result['prefix_stdout_sha256']==hashlib.sha256(output[:result['prefix_stdout_bytes']]).hexdigest()
case('whole_file_omission_and_late_end_real_limits',selection)
report={'schema':'hia.core-small-diagnostic-finite-controls.v1','status':'PASS',
    'python':sys.version,'control_source_sha256':hashlib.sha256((ROOT/'small_diagnostics.py').read_bytes()).hexdigest(),
    'checks':CHECKS,'count':len(CHECKS),'scope':'SYNTHETIC_TRANSPORT_ONLY',
    'current_environment_admission_mocked_only_for_selection_control':True,
    'actual_native_or_cold_qualification_claimed':False,'product_modules_executed':False,
    'original_native_or_caller_gates_executed':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
fd=os.open(ROOT/'SYNTHETIC-CONTROLS.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
with os.fdopen(fd,'wb') as out:out.write(raw)
print(json.dumps({'status':'PASS','controls':len(CHECKS),'report_sha256':hashlib.sha256(raw).hexdigest(),
                  'native_or_product_executed':False},sort_keys=True))
