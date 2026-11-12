"""Decode only one exact v2 small stdout stream; never infer product PASS.

The complete provider log and every selected original are retained. Missing,
refused and whole-file omitted entries stay explicit. This does not replace
the full official artifact/typed archive readback.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1,sha256
import json
from pathlib import Path
import re

MAX_RAW=512<<10
MAX_STDOUT=1<<20
MAX_INDEX=64<<10
FRAME=8192

def require(value,message):
    if not value:raise ValueError(message)

def wire(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
            'git_blob_sha1':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def decode(log,run_id,workflow_sha,policy_raw,target_raw):
    policy=json.loads(policy_raw)
    targets=json.loads(target_raw)['targets']
    require(policy['schema']=='hia.bounded-read-product-install-actions-policy.v1'
            and policy['small_channel_schema']=='hepta.hia.bounded-read-small-stream.v2'
            and policy['small_index_serialization']=='sorted-compact-json-utf8-lf'
            and policy['diagnostic_targets']==len(targets)==219
            and policy['small_raw_bytes']==MAX_RAW and policy['small_stdout_bytes']==MAX_STDOUT
            and policy['small_index_bytes']==MAX_INDEX
            and policy['controls']['diagnostic-targets.json']==pin(target_raw),
            'fixed policy/complete target population differs')
    require(type(run_id)is int and run_id>0 and re.fullmatch('[0-9a-f]{40}',workflow_sha),
            'exact actual run/workflow identity required')
    known=[row['name'] for row in targets]
    require(len(set(known))==len(known) and all(not n.startswith('/') and '\\' not in n and '\0' not in n
        and all(p not in ('','.','..') for p in n.split('/')) for n in known),'fixed target names unsafe')
    events=[]
    protocol=bytearray()
    for line in log.decode('utf-8').splitlines():
        match=re.fullmatch(r'(?:\d{4}-\d\d-\d\dT[0-9:.]+Z )?(HIA_BOUNDED_READ_[A-Z_]+) (.*)',line)
        if match:
            kind,body=match.groups()
            value=json.loads(body)
            require(body==json.dumps(value,sort_keys=True,separators=(',',':')),
                    'stdout protocol is not exact compact JSON')
            protocol.extend((kind+' '+body+'\n').encode())
            require(len(protocol)<=MAX_STDOUT,'entire stdout protocol exceeds fixed bound')
            events.append((kind,value))
    require(len(events)>=3 and events[0][0]=='HIA_BOUNDED_READ_DIAGNOSTIC_BEGIN'
            and events[1][0]=='HIA_BOUNDED_READ_DIAGNOSTIC_INDEX'
            and events[-1][0]=='HIA_BOUNDED_READ_DIAGNOSTIC_END','one complete protocol envelope required')
    begin,index=events[0][1],events[1][1]
    require(begin=={'schema':'hepta.hia.bounded-read-small-stream.v2','run_id':run_id,
        'workflow_commit':workflow_sha,'policy_sha256':sha256(policy_raw).hexdigest(),
        'raw_limit':MAX_RAW,'stdout_limit':MAX_STDOUT,'index_serialization':'sorted-compact-json-utf8-lf'},
        'actual protocol operation identity differs')
    records=index['records']
    index_raw=wire(index)
    require(index['schema']=='hepta.hia.bounded-read-small-channel-index.v1'
            and index['fixed_targets']==219 and [row['name'] for row in records]==known
            and index['raw_limit']==MAX_RAW and index['stdout_limit']==MAX_STDOUT
            and index['complete_original_artifact_transport_claimed']is False
            and index['product_status_changed']is False and len(index_raw)<=MAX_INDEX,
            'complete original fixed index differs')
    allowed={'SELECTED_WHOLE_FILE','OMITTED_WHOLE_FILE_BUDGET','MISSING','REFUSED',
             'NOT_READ_UNCLOSED_PROCESS_BOUNDARY'}
    require(all(row['status']in allowed for row in records),'unknown fixed diagnostic disposition')
    selected=[row for row in records if row['status']=='SELECTED_WHOLE_FILE']
    require(index['selected_files']==len(selected)
            and index['selected_raw_bytes']==sum(row['bytes'] for row in selected)<=MAX_RAW,
            'whole-file raw budget or selected population differs')
    position=2;frames=0;originals={}
    for row in selected:
        require(position<len(events)-1 and events[position]==('HIA_BOUNDED_READ_ORIGINAL_BEGIN',row),
                'original begin differs from exact selected order')
        position+=1;raw=bytearray()
        while position<len(events)-1 and events[position][0]=='HIA_BOUNDED_READ_ORIGINAL_FRAME':
            frame=events[position][1]
            require(set(frame)=={'name','offset','bytes','sha256','base64'}
                    and frame['name']==row['name'] and frame['offset']==len(raw)
                    and type(frame['bytes'])is int and 0<frame['bytes']<=FRAME,
                    'frame population/order/extent differs')
            block=base64.b64decode(frame['base64'],validate=True)
            require(len(block)==frame['bytes'] and sha256(block).hexdigest()==frame['sha256']
                    and len(raw)+len(block)<=row['bytes'],'actual frame bytes differ')
            raw.extend(block);frames+=1;position+=1
        require(position<len(events)-1 and events[position]==('HIA_BOUNDED_READ_ORIGINAL_END',row),
                'original end missing or mismatched')
        position+=1;raw=bytes(raw)
        require(pin(raw)=={key:row[key] for key in ('bytes','sha256','git_blob_sha1')},
                'complete original full-byte SHA or Git blob differs')
        originals[row['name']]=raw
    require(position==len(events)-1,'extra frame/original/envelope entered fixed stream')
    end=events[-1][1]
    require(end=={'status':'BOUNDED_WHOLE_FILE_CHANNEL_COMPLETE','selected_files':len(selected),
        'frames':frames,'selected_raw_bytes':sum(len(raw) for raw in originals.values()),
        'index_sha256':sha256(index_raw).hexdigest(),'closed_ECHILD':index['boundary']['closed_ECHILD'],
        'all_fixed_originals_transported':len(selected)==219,'complete_original_artifact_transport_claimed':False},
        'late END does not match the complete actual stream')
    return {'schema':'hepta.hia.bounded-read-small-receiver.v2',
        'status':'EXACT_SMALL_TRANSPORT_RECOVERED_NOT_PRODUCT_PASS','run_id':run_id,
        'workflow_commit':workflow_sha,'provider_log':pin(log),'protocol_stdout':pin(bytes(protocol)),
        'policy':pin(policy_raw),'targets':pin(target_raw),'begin':begin,'index':index,'end':end,
        'selected_originals':{name:pin(raw) for name,raw in originals.items()},
        'complete_original_artifact_transport_claimed':False,'product_result_interpreted':False},originals

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log',type=Path,required=True)
    parser.add_argument('--run-id',type=int,required=True)
    parser.add_argument('--workflow-commit',required=True)
    parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--targets',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    log=args.log.read_bytes();require(len(log)<=8<<20,'provider log exceeds bounded receiver input')
    report,originals=decode(log,args.run_id,args.workflow_commit,args.policy.read_bytes(),args.targets.read_bytes())
    args.output.mkdir(mode=0o700)
    for name,raw in [('provider-job.log',log),('RECEIVER.json',(json.dumps(report,sort_keys=True,indent=2)+'\n').encode())]:
        with (args.output/name).open('xb') as stream:stream.write(raw)
    target=args.output/'originals';target.mkdir(mode=0o700)
    for name,raw in originals.items():
        path=target/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with path.open('xb') as stream:stream.write(raw)
    print(json.dumps({'status':report['status'],'selected_originals':len(originals),'product_PASS_claimed':False}))

if __name__=='__main__':main()
