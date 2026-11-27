"""Compare the native direct observation decoder with the unchanged full decoder.

Both HIA observers are compiled from the four pinned seed roots. Complete input,
native return code and complete 256-byte output are retained for every case.
The generic decoder remains the fallback and is never replaced by this observer.
"""
from __future__ import annotations
import argparse, ctypes, gzip, itertools, json, struct
from hashlib import sha256
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_request_audit_common import authored, C
from tools.generate_hia_mcp_request_audit_codec import SOURCE as CODEC, TEXT
from tools.generate_hia_mcp_request_audit_observation import SOURCE as OBSERVATION
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds

ROOT = Path(__file__).resolve().parents[1]
REJECT = 4294967295
SENTINEL = b'\xa5'*256
ID = '1'*64


def cases():
    rows=[]
    def add(label,raw,fast=None):
        rows.append({'case':label,'raw_hex':raw.hex(),'fast_expected':fast})
    base={'request_id':ID,'owner':'a'*64,'tool_name':'process_start','state':'completed',
          'accepted_unix_ms':17,'elapsed_ms':3}
    def encoded(value,**kwargs):
        return json.dumps(value,separators=(',',':'),**kwargs).encode()
    for i,order in enumerate(itertools.permutations(base)):
        value={key:base[key] for key in order}
        add('field-order-'+str(i),encoded(value),True)
        if i%37==0:
            add('field-order-spaced-'+str(i),b' \r\n\t'+json.dumps(value,indent=2).encode()+b'\t\r\n ',True)
    for state in ('unknown','completed','failed'):
        for number in (0,1,2**32-1,2**32,2**53-1,2**53,2**64-1,2**64,2**127,2**128-1):
            for elapsed in (None,0,2**32,2**64-1):
                value={**base,'state':state,'accepted_unix_ms':number,'elapsed_ms':elapsed}
                add(f'integer-{state}-{number}-{elapsed}',encoded(value),True)
    no_elapsed={key:value for key,value in base.items() if key!='elapsed_ms'}
    add('optional-elapsed-absent',encoded(no_elapsed),True)
    for size in (1,63,64):
        add('tool-boundary-'+str(size),encoded({**base,'tool_name':'x'*size}),True)
    raw=encoded(base)
    for pos in range(len(raw)):
        add('truncated-'+str(pos),raw[:pos],False)
        add('deleted-byte-'+str(pos),raw[:pos]+raw[pos+1:])
        for ch in (0,9,34,44,48,92,123,125,127,255):
            if raw[pos]!=ch:
                add(f'mutated-{pos}-{ch}',raw[:pos]+bytes([ch])+raw[pos+1:])
    for key in base:
        add('duplicate-'+key,raw[:-1]+b','+encoded({key:base[key]})[1:],False)
        missing={name:value for name,value in base.items() if name!=key}
        add('missing-'+key,encoded(missing),key=='elapsed_ms')
    for name,value in [('unknown-key',{**base,'extra':None}),('upper-id',{**base,'request_id':'A'*64}),
                       ('foreign-id',{**base,'request_id':'2'*64}),('upper-owner',{**base,'owner':'A'*64}),
                       ('invalid-tool',{**base,'tool_name':'process-start'}),('empty-tool',{**base,'tool_name':''}),
                       ('long-tool',{**base,'tool_name':'x'*65}),('state',{**base,'state':'accepted'}),
                       ('timestamp-overflow',{**base,'accepted_unix_ms':2**128}),
                       ('elapsed-overflow',{**base,'elapsed_ms':2**64}),
                       ('negative',{**base,'accepted_unix_ms':-1}),('float',{**base,'accepted_unix_ms':1.0})]:
        add(name,encoded(value),False)
    for replacement in (b'00',b'01',b'-0',b'+1',b'1e2',b'1.',b'.1',b'true',b'null',b'"17"'):
        add('timestamp-grammar-'+replacement.hex(),raw.replace(b'"accepted_unix_ms":17',b'"accepted_unix_ms":'+replacement),False)
    for name,value in [('escaped-id',raw.replace(ID.encode(),b'\\u0031'+b'1'*63,1)),
                       ('escaped-key',raw.replace(b'"owner"',b'"\\u006fwner"')),
                       ('escaped-tool',raw.replace(b'process_start',b'process_\\u0073tart')),
                       ('escaped-state',raw.replace(b'completed',b'\\u0063ompleted'))]:
        add(name,value,False)
    add('extra-object',raw+b'{}',False)
    add('trailing-comma',raw[:-1]+b',}',False)
    add('trailing-nul',raw+b'\0',False)
    add('record-exact-2048',raw+b' '*(2048-len(raw)),True)
    add('record-over-2048',raw+b' '*(2049-len(raw)),False)
    return rows


def harness(fast):
    guard='''def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > 2112 or length(w) < STATE_BYTES:
        return 4294967295
    if length(o) < 256:
        return 4294967294
    copy_input(s,w,0,INPUT,64)
'''
    if fast:
        body='''    copy_input(s,w,64,READ_DATA,length(s)-64)
    if observation_record(w,READ_DATA,length(s)-64,RECORD,INPUT) == False:
        return 4294967295
'''
    else:
        body='''    if json_ok(w,get(w,8)) == False or parse_record(w,RECORD,INPUT) == False:
        return 4294967295
'''
    tail='''    index = 0
    while index < 256:
        word_store(o,index,get(w,RECORD+index))
        index = index+8
    return 256
'''
    return authored(guard+body+tail+'\n'+CODEC+('\n'+OBSERVATION if fast else ''),text=TEXT)


def qualify(bootstrap,baseline,output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    seeds=HistorySeeds(ROOT,bootstrap,output/'compiler')
    report={'schema':'hepta.hia.record-observation-native.v1','passed':False,
            'scope':'direct native original-byte decoder and unchanged full JSON fallback',
            'whole_cold_qualified':False,'whole_runtime_qualified':False,'sources':{},'images':{}}
    for name in ('generate_hia_mcp_request_audit_observation.py','generate_hia_mcp_request_audit_codec.py',
                 'generate_hia_mcp_request_audit_common.py','generate_hia_mcp_request_audit_archive_query.py',
                 'qualify_hia_mcp_record_observation.py'):
        report['sources']['tools/'+name]=sha256((ROOT/'tools'/name).read_bytes()).hexdigest()
    baseline_report=json.loads((baseline/'qualification.json').read_bytes())
    json_image=(baseline/'json.flat').read_bytes()
    assert sha256(json_image).hexdigest()==baseline_report['parts']['json']['image_sha256']
    assert sha256((ROOT/baseline_report['parts']['json']['source']).read_bytes()).hexdigest()==baseline_report['parts']['json']['source_sha256']
    report['baseline_generic_decoder']={'source':baseline_report['parts']['json']['source_sha256'],
                                       'image':sha256(json_image).hexdigest()}
    images={};records=[]
    try:
        for name,fast in (('direct',True),('original',False)):
            source=render_assembly(document(harness(fast),'record_observation_'+name)).encode()
            (output/(name+'.hepta')).write_bytes(source)
            image=seeds.compile(source,'div-word');(output/(name+'.flat')).write_bytes(image)
            images[name]=NativeHiaJsonImage(image,sha256(image).hexdigest())
            report['images'][name]={'source_sha256':sha256(source).hexdigest(),'image_sha256':sha256(image).hexdigest(),'image_bytes':len(image)}
        decoder=NativeHiaJsonImage(json_image,sha256(json_image).hexdigest())
        workspace=ctypes.create_string_buffer(C['STATE_BYTES']);address=ctypes.addressof(workspace)
        output_buffer=ctypes.create_string_buffer(256)
        entries=cases();(output/'cases.json.gz').write_bytes(gzip.compress(json.dumps(entries,separators=(',',':')).encode(),mtime=0))
        accepted=fallback=0
        for row in entries:
            raw=bytes.fromhex(row['raw_hex']);wire=ID.encode()+raw;source=ctypes.create_string_buffer(wire)
            report['active_case']=row
            ctypes.memmove(output_buffer,SENTINEL,256)
            status=images['direct']._entry(source,len(wire),output_buffer,256,workspace,len(workspace))
            direct=output_buffer.raw
            report['active_native']={'direct_status':status,'direct_output_hex':direct.hex()}
            if row['fast_expected'] is not None:assert (status==256)==row['fast_expected'],(row['case'],status)
            assert status in (256,REJECT),(row['case'],status)
            if status==REJECT:assert direct==SENTINEL,row['case']
            ctypes.memmove(address+C['READ_DATA'],raw,len(raw))
            ctypes.memmove(address+72,struct.pack('<Q',C['READ_DATA']),8)
            ctypes.memmove(address+C['SCRATCH']+48,struct.pack('<2Q',4096,32),16)
            decoded=decoder._entry(address+C['READ_DATA'],len(raw),address+C['ARENA'],C['ARENA_BYTES'],address+C['SCRATCH'],C['SCRATCH_BYTES'])
            ctypes.memmove(address+8,struct.pack('<Q',decoded),8)
            ctypes.memmove(output_buffer,SENTINEL,256)
            original_status=images['original']._entry(source,len(wire),output_buffer,256,workspace,len(workspace))
            original=output_buffer.raw
            report['active_native'].update(json_status=decoded,original_status=original_status,original_output_hex=original.hex())
            if status==256:
                assert original_status==256 and direct==original,(row['case'],status,original_status,direct.hex(),original.hex())
                accepted+=1
            else:fallback+=1
            if original_status!=256:assert original==SENTINEL,row['case']
            records.append({'case':row['case'],'input_hex':wire.hex(),'direct_status':status,'direct_output_hex':direct.hex(),
                            'json_status':decoded,'original_status':original_status,'original_output_hex':original.hex()})
        assert accepted>=840 and fallback>1000,(accepted,fallback)
        raw=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in records)
        compressed=gzip.compress(raw,mtime=0);(output/'observations.jsonl.gz').write_bytes(compressed)
        report.update(passed=True,passed_count=len(records),direct_admitted=accepted,full_decoder_fallback=fallback,
                      raw_bytes=len(raw),raw_sha256=sha256(raw).hexdigest(),compressed_sha256=sha256(compressed).hexdigest())
        report.pop('active_case',None);report.pop('active_native',None)
        return report
    except BaseException as error:
        report['error']=repr(error)
        raw=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in records)
        (output/'partial-observations.jsonl.gz').write_bytes(gzip.compress(raw,mtime=0))
        report['complete_before_failure']=len(records)
        raise
    finally:
        seeds.save();(output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('bootstrap','baseline','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();report=qualify(args.bootstrap.resolve(),args.baseline.resolve(),args.output.resolve())
    print(json.dumps({key:report[key] for key in ('passed','passed_count','direct_admitted','full_decoder_fallback')}))


if __name__=='__main__':main()
