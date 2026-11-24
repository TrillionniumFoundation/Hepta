"""Compose current-source admission and fresh full independent HIA VM calls."""
import json
import struct
from tools.generate_hia_cold_qualification_plan import U64
from tools.hia_cold_qualification_plan_parts import call


def vm_reference(p,h,source,*,label,entry='f0',args=(),snapshots=b'',
                 snapshots_handle=None,max_steps=1_000_000,max_call_depth=256,
                 max_heap_bytes=16<<20,allocation_fail_at=0):
    core=call(p,h['assembly'],source,label=label+':fresh-independent-admission',argv=('child','--agent-compact'))
    left=p.literal(b'[');right=p.literal(b','+json.dumps(entry,ensure_ascii=True).encode()+b',1]')
    frame=p.concat(left,core,right)
    projected=call(p,h['projector'],frame,label=label+':independent-reference-projection')
    start=p.literal(b'HIAEVP01'+struct.pack('<Q',2));size=p.length(projected)
    argc=p.literal(struct.pack('<Q',len(args)))
    if snapshots_handle is None:
        snapshot=p.literal(snapshots)
    else:
        snapshot=snapshots_handle
    snapshot_size=p.length(snapshot)
    budget=p.literal(struct.pack('<5Q',max_steps,max_call_depth,max_heap_bytes,allocation_fail_at,0))
    arguments=p.literal(b''.join(struct.pack('<2Q',kind,value&U64) for kind,value in args))
    packet_input=p.concat(start,size,argc,snapshot_size,budget,arguments,projected,snapshot)
    packet=call(p,h['reference_packet'],packet_input,label=label+':actual-VM-frame')
    observed=call(p,h['vm'],packet,label=label+':fresh-full-independent-VM')
    p.drop(core,left,right,frame,projected,start,size,argc,snapshot_size,budget,arguments,packet_input,packet)
    if snapshots_handle is None:
        p.drop(snapshot)
    return observed


def assert_vm(p,observed,*,label,values=(),snapshots=b'',snapshots_handle=None,
              status=0,max_steps=1_000_000,closed_resources=True):
    if status and values:
        raise ValueError('a failed VM execution has no return values')
    p.word(observed,0,int.from_bytes(b'HIASPR01','little'),label=label+':actual-VM-header')
    p.word(observed,8,status,label=label+':actual-VM-status')
    bounded=p.number(observed,0,offset=16,maximum=max_steps+(status==5));p.drop(bounded)
    return_count=len(values) if status==0 else 0
    base=32+return_count*8
    for index,value in enumerate(values):
        p.word(observed,32+index*8,value,label=label+':actual-VM-value-'+str(index))
    if closed_resources:
        for a,b in ((3,4),(7,8)):
            first=p.slice(observed,base+a*8,8);second=p.slice(observed,base+b*8,8)
            p.compare(first,second,label=label+':VM-resource-conservation-'+str(a));p.drop(first,second)
        for index in (5,13):
            p.word(observed,base+index*8,0,label=label+':VM-zero-live-resource-'+str(index))
    expected=p.literal(snapshots) if snapshots_handle is None else snapshots_handle
    tail=p.slice(observed,base+112)
    p.compare(tail,expected,label=label+':complete-VM-view-snapshots')
    p.drop(tail)
    if snapshots_handle is None:
        p.drop(expected)
