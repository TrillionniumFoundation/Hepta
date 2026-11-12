"""Exercise v2 receiver with synthetic bytes only; no product result is inferred."""
import base64
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bounded_small_receiver',ROOT/'decode_small.py')
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
OUT=ROOT/'transport-checks-r1';OUT.mkdir(mode=0o700)
policy_raw=(ROOT/'control/policy.json').read_bytes()
target_raw=(ROOT/'control/diagnostic-targets.json').read_bytes()
targets=json.loads(target_raw)['targets']
data={targets[0]['name']:bytes(range(256))*70,targets[1]['name']:b''}
records=[{'name':r['name'],'status':'SELECTED_WHOLE_FILE',**decoder.pin(data[r['name']])}
         if r['name'] in data else {'name':r['name'],'status':'MISSING'} for r in targets]
index={'schema':'hepta.hia.bounded-read-small-channel-index.v1','fixed_targets':219,
    'selected_files':2,'selected_raw_bytes':sum(map(len,data.values())),
    'raw_limit':512<<10,'stdout_limit':1<<20,'observation_raw_bytes':sum(map(len,data.values())),
    'boundary':{'current_operation_bound':True,'closed_ECHILD':True,'guardian_sha256':'a'*64,
                'original_product_status_not_changed':True},
    'complete_original_artifact_transport_claimed':False,'product_status_changed':False,'records':records}
events=[('HIA_BOUNDED_READ_DIAGNOSTIC_BEGIN',{'schema':'hepta.hia.bounded-read-small-stream.v2',
    'run_id':99,'workflow_commit':'b'*40,'policy_sha256':sha256(policy_raw).hexdigest(),
    'raw_limit':512<<10,'stdout_limit':1<<20,'index_serialization':'sorted-compact-json-utf8-lf'}),
    ('HIA_BOUNDED_READ_DIAGNOSTIC_INDEX',index)]
frames=0
for row in records[:2]:
    events.append(('HIA_BOUNDED_READ_ORIGINAL_BEGIN',row));raw=data[row['name']]
    for offset in range(0,len(raw),8192):
        block=raw[offset:offset+8192]
        events.append(('HIA_BOUNDED_READ_ORIGINAL_FRAME',{'name':row['name'],'offset':offset,
            'bytes':len(block),'sha256':sha256(block).hexdigest(),'base64':base64.b64encode(block).decode()}))
        frames+=1
    events.append(('HIA_BOUNDED_READ_ORIGINAL_END',row))
events.append(('HIA_BOUNDED_READ_DIAGNOSTIC_END',{'status':'BOUNDED_WHOLE_FILE_CHANNEL_COMPLETE',
    'selected_files':2,'frames':frames,'selected_raw_bytes':sum(map(len,data.values())),
    'index_sha256':sha256(decoder.wire(index)).hexdigest(),'closed_ECHILD':True,
    'all_fixed_originals_transported':False,'complete_original_artifact_transport_claimed':False}))
def render(items):return ''.join('2026-11-12T00:00:00.0000000Z '+kind+' '+json.dumps(value,sort_keys=True,separators=(',',':'))+'\n'
                               for kind,value in items).encode()
raw=render(events)
(OUT/'synthetic-original.log').write_bytes(raw)
results=[]
decoded,actual=decoder.decode(raw,99,'b'*40,policy_raw,target_raw)
assert actual==data and decoded['product_result_interpreted']is False
results.append({'id':'binary_multiframe_and_empty_whole_file','status':'PASS'})
def refused(name,items,**kw):
    value=render(items)
    (OUT/(name+'.log')).write_bytes(value)
    try:decoder.decode(value,kw.get('run_id',99),kw.get('workflow_sha','b'*40),kw.get('policy',policy_raw),target_raw)
    except ValueError as error:results.append({'id':name,'status':'PASS','refusal':str(error)})
    else:raise AssertionError(name+' was admitted')
def copy():return json.loads(json.dumps(events))
test=copy();next(row[1] for row in test if row[0].endswith('_FRAME'))['offset']=1
refused('wrong_offset',test)
test=copy();next(row[1] for row in test if row[0].endswith('_FRAME'))['sha256']='0'*64
refused('wrong_frame_SHA',test)
refused('missing_late_END',events[:-1])
refused('duplicate_envelope',events[:1]+events)
refused('wrong_workflow',events,workflow_sha='c'*40)
refused('wrong_run',events,run_id=100)
test=copy();test[-1][1]['index_sha256']='0'*64
refused('wrong_complete_INDEX_SHA',test)
test=copy();test[1][1]['records'][-1]['status']='PASS'
refused('unknown_omission_state',test)
report={'schema':'hepta.hia.bounded-read-small-v2-synthetic-controls.v1',
    'status':'NINE_SYNTHETIC_TRANSPORT_CONTROLS_PASS_NOT_PRODUCT','checks':results,
    'decoder':decoder.pin((ROOT/'decode_small.py').read_bytes()),'policy':decoder.pin(policy_raw),
    'targets':decoder.pin(target_raw),'positive_log':decoder.pin(raw),
    'product_imported':False,'native_executed':False,'actual_run_claimed':False}
(OUT/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'checks':len(results)}))
