"""Serialize the original observer pre-B0 reference and actual packing gates.

Expected bytes are computed by fresh complete independent HIA VM executions.
The original 128-byte windows, one-million-step ordinary budget and linked
thirty-million-step private budget are retained. No historic output is an
expectation. Python here only writes plan data; replay is entirely native.
"""
import json,struct
from tools.generate_hia_cold_qualification_plan import U64
from tools.hia_cold_qualification_plan_parts import call,build,observe,check_flat,utility,assert_gate


def project(p,h,source,entry,label):
    core=call(p,h['assembly'],source,label=label+':actual-source-admission',argv=('child','--agent-compact'))
    left=p.literal(b'[');right=p.literal(b','+json.dumps(entry).encode()+b',1]');request=p.concat(left,core,right)
    projected=call(p,h['projector'],request,label=label+':independent-projection')
    p.drop(core,left,right,request);return projected


def vm(p,h,projected,args,snapshots,*,label,linked=False):
    start=p.literal(b'HIAEVP01'+struct.pack('<Q',2));size=p.length(projected)
    count=p.literal(struct.pack('<Q',len(args)));snapshot_size=p.length(snapshots)
    budget=p.literal(struct.pack('<5Q',30000000 if linked else 1000000,128 if linked else 256,4<<20 if linked else 16<<20,0,0))
    words=[]
    for kind,value,is_handle in args:
        words.append(p.literal(struct.pack('<Q',kind)))
        words.append(p.slice(value) if is_handle else p.literal(struct.pack('<Q',value&U64)))
    arguments=p.concat(*words) if words else p.literal(b'')
    request=p.concat(start,size,count,snapshot_size,budget,arguments,projected,snapshots)
    packet=call(p,h['reference_packet_30m' if linked else 'reference_packet'],request,label=label+':complete-reference-packet')
    result=call(p,h['vm_30m' if linked else 'vm'],packet,label=label+':fresh-complete-VM')
    p.drop(start,size,count,snapshot_size,budget,*words,arguments,request,packet)
    return result


def vm_shape(p,result,returns,*,label,max_steps,snapshot_size):
    p.word(result,0,int.from_bytes(b'HIASPR01','little'),label=label+':VM-header')
    p.word(result,8,0,label=label+':VM-returned')
    bounded=p.number(result,0,offset=16,maximum=max_steps);p.drop(bounded)
    size=p.length(result)
    if isinstance(snapshot_size,int):p.word(size,0,32+8*returns+112+snapshot_size,label=label+':full-observation-size')
    else:
        expected=p.number(snapshot_size[0],32+8*returns+112);p.compare(size,expected,label=label+':full-observation-size');p.drop(expected)
    p.drop(size)
    base=32+8*returns
    for first,second in ((3,4),(7,8)):
        a=p.slice(result,base+first*8,8);b=p.slice(result,base+second*8,8)
        p.compare(a,b,label=label+':resource-conservation-'+str(first));p.drop(a,b)
    for field in (5,13):p.word(result,base+field*8,0,label=label+':zero-live-'+str(field))


def native_windows(p,h,cases):
    """Every original output byte comes from its fresh 128-byte VM window."""
    header=cases['native_packer_header'].encode();expected_header=p.literal(header)
    actual_header=p.slice(h['native_packer_source'],0,len(header));p.compare(actual_header,expected_header,label='native-observer:actual-source-module')
    p.drop(actual_header,expected_header);body=p.slice(h['native_packer_source'],len(header));empty=p.literal(b'')
    image_size=p.length(h['observer']);p.word(image_size,0,cases['native_image_bytes'])
    windows=[]
    for row in cases['windows']:
        begin,end=row['begin'],row['end'];count=end-begin;label='native-observer-window-'+str(begin)
        prefix=p.literal(row['prefix'].encode());source=p.concat(prefix,body)
        projected=project(p,h,source,'reference_entry',label)
        actual=vm(p,h,projected,(),empty,label=label)
        vm_shape(p,actual,1+count,label=label,max_steps=1000000,snapshot_size=0)
        returned=p.slice(actual,32,8);p.compare(returned,image_size,label=label+':actual-complete-image-extent');p.drop(returned)
        bytes_=[]
        for at in range(count):
            offset=40+at*8;p.word(actual,offset,0,mask=U64^255,label=label+':typed-u8-'+str(at));bytes_.append(p.slice(actual,offset,1))
        windows.append(p.concat(*bytes_));p.drop(*bytes_);p.drop(prefix,source,projected,actual)
    image=p.concat(*windows);p.compare(image,h['observer'],label='native-observer:all-window-bytes-equal-independent-root')
    p.drop(*windows,body,empty,image_size);return image


def linked_pack_reference(p,h,projected,policy,actual_object,*,label):
    policy_size=p.length(policy);object_size=p.length(actual_object)
    initial=utility(p,h['utility'],0,arg_word=object_size,label=label+':original-A5-output')
    snapshots=p.concat(policy,initial)
    result=vm(p,h,projected,((14,policy_size,True),(15,object_size,True),(15,0,False)),snapshots,label=label,linked=True)
    snapshot_size=p.length(snapshots);vm_shape(p,result,1,label=label,max_steps=30000000,snapshot_size=(snapshot_size,))
    returned=p.slice(result,32,8);p.compare(returned,object_size,label=label+':complete-object-return')
    actual_views=p.slice(result,152);expected_views=p.concat(policy,actual_object)
    p.compare(actual_views,expected_views,label=label+':every-actual-object-byte-and-immutable-input')
    p.drop(policy_size,object_size,initial,snapshots,result,snapshot_size,returned,actual_views,expected_views)


def patched_words(p,source,changes,size=512):
    if not changes:return p.slice(source)
    parts=[];cursor=0
    for offset,value in sorted(changes):
        if offset>cursor:parts.append(p.slice(source,cursor,offset-cursor))
        parts.append(p.literal(struct.pack('<Q',value)));cursor=offset+8
    if cursor<size:parts.append(p.slice(source,cursor,size-cursor))
    result=p.concat(*parts);p.drop(*parts);return result


def linked_policy_reference(p,h,projected):
    image=b'complete ELF remains opaque to policy';source=b'source\0\xff'
    request=b'HIAOBS03'+struct.pack('<6Q',len(image),len(source),17,40,90,(11<<32)|0xffffffff)+image+source
    empty=p.literal(b'');wire=p.literal(request)
    work=bytearray(512);struct.pack_into('<Q',work,8,1);workspace=p.literal(work);control=p.literal(bytes(512))
    steps=[(1,()),(2,((16,0),)),(3,((16,0),(24,7),(32,15))),(4,((16,0x12340000),)),(5,((16,0),(32,0x12340100))),(6,((16,0),)),(8,((16,0),(24,11),(32,999999990),(40,12),(48,10),(56,0xdeadbeef0000002a))),(7,((16,0),)),(0,((16,0),))]
    records=[];response_snapshot=None
    for index,(action,feedback) in enumerate(steps):
        label='linked-observer-private-action-'+str(action);input_=empty if index==0 else wire;length=0 if index==0 else len(request)
        patched=patched_words(p,workspace,feedback);snapshots=p.concat(input_,control,patched)
        result=vm(p,h,projected,((14,length,False),(15,512,False),(15,512,False)),snapshots,label=label,linked=True)
        vm_shape(p,result,1,label=label,max_steps=30000000,snapshot_size=length+1024)
        p.word(result,32,action,label=label+':original-continuation')
        immutable=p.slice(result,152,length);p.compare(immutable,input_,label=label+':immutable-request');p.drop(immutable)
        updated_control=p.slice(result,152+length,512);updated_workspace=p.slice(result,152+length+512,512)
        records.append(p.concat(updated_control,updated_workspace))
        if action==1:
            for offset,value in enumerate((5242937,10,256<<20,8<<20,16<<20,32,0,0)):p.word(updated_control,offset*8,value)
        if action in (3,4):
            expected=p.literal(b'/proc/self/fd/7\0' if action==3 else b'f0\0');actual=p.slice(updated_control,64,16 if action==3 else 3)
            p.compare(actual,expected,label=label+':original-name');p.drop(actual,expected)
        if action==8:
            p.word(updated_control,32,11);p.word(updated_control,40,18)
            response_snapshot=p.slice(updated_control,128,24);expected=p.literal(b'HIAOBR03'+struct.pack('<QQ',0xdeadbeef0000002a,20))
            p.compare(response_snapshot,expected,label=label+':full-time-and-return-framing');p.drop(expected)
        if action==7:
            actual=p.slice(updated_control,128,24);p.compare(actual,response_snapshot,label=label+':committed-response-unchanged');p.drop(actual,response_snapshot)
        if action==0:p.word(updated_control,0,0,label=label+':completion')
        p.drop(control,workspace,patched,snapshots,result);control,workspace=updated_control,updated_workspace
    head=p.literal(b'HIALOP01'+struct.pack('<Q',len(records)));bundle=p.concat(head,*records)
    p.drop(head,*records,control,workspace,empty,wire);return bundle


def reference_observers(p,h,cases):
    """Standalone pre-B0 phase; no target/successor image is imported."""
    native=native_windows(p,h,cases);p.publish(native,'reference-native-observer.bin');p.drop(native)
    packer=project(p,h,h['linked_packer_source'],'f0','linked-observer-packer')
    for index,policy in enumerate((b'\xc3',bytes(range(256))*17)):
        actual=p.literal(policy);obj=call(p,h['linked_packer_root'],actual,label='linked-independent-native-object-'+str(index))
        linked_pack_reference(p,h,packer,actual,obj,label='linked-packer-preB0-'+str(index));p.drop(actual,obj)
    policy=project(p,h,h['linked_policy_source'],'f0','linked-observer-policy')
    observations=linked_policy_reference(p,h,policy);p.publish(observations,'reference-linked-policy.bin');p.drop(policy,observations)
    p.publish(packer,'reference-linked-packer-wire.bin');p.drop(packer)
    sources=[p.sha256(h[k]) for k in ('native_packer_source','linked_policy_source','linked_packer_source')]
    pins=p.concat(*sources);p.publish(pins,'reference-observer-source-pins.bin');p.drop(*sources,pins)
    return ['reference-native-observer.bin','reference-linked-policy.bin','reference-linked-packer-wire.bin','reference-observer-source-pins.bin']


def linked_call(p,h,observer,dso,source,expected,*,label,result,cap=1,work=1):
    initial=utility(p,h['utility'],0,arg=cap,label=label+':output-preimage');shared=p.shared(initial)
    raw_snapshot=p.literal(bytes(cap+8));snapshot=p.snapshot(raw_snapshot)
    image_size,source_size=p.length(dso),p.length(source);output_fd=p.fdword(shared);snapshot_fd=p.fdword(snapshot)
    low=p.slice(output_fd,0,4);high=p.slice(snapshot_fd,0,4);descriptors=p.concat(low,high)
    header=p.literal(b'HIAOBS03');extent=p.literal(struct.pack('<3Q',cap,work,0))
    request=p.concat(header,image_size,source_size,extent,descriptors,dso,source)
    observation=p.run(observer,request,seconds=20,shared=shared,passed=(snapshot,),label=label+':actual-libc-startup-dlopen-exit')
    receipt=p.resultpart(observation,0);p.word(receipt,8,0,label=label+':exit-zero')
    stderr=p.resultpart(observation,2);empty=p.literal(b'');p.compare(stderr,empty,label=label+':stderr-empty')
    stdout=p.resultpart(observation,1);p.word(stdout,0,int.from_bytes(b'HIAOBR03','little'));p.word(stdout,8,result)
    work_expected=p.literal(bytes(work));expected_suffix=p.concat(source,expected,work_expected)
    actual_suffix=p.slice(stdout,24);p.compare(actual_suffix,expected_suffix,label=label+':full-source-output-workspace')
    live=p.resultpart(observation,3);p.compare(live,expected,label=label+':live-output')
    marker=p.literal(struct.pack('<Q',cap+1));expected_snapshot=p.concat(marker,expected);actual_snapshot=p.slice(snapshot)
    p.compare(actual_snapshot,expected_snapshot,label=label+':committed-return-snapshot')
    p.drop(initial,shared,raw_snapshot,snapshot,image_size,source_size,output_fd,snapshot_fd,low,high,descriptors,header,extent,request,observation,receipt,stderr,empty,stdout,work_expected,expected_suffix,actual_suffix,live,marker,expected_snapshot,actual_snapshot)


def qualify_observer_builds(p,h,compiler,*,label):
    """Actual current compiler packing, full VM equality, and native dlopen."""
    reference=p.imported('reference-native-observer.bin');projected=p.imported('reference-linked-packer-wire.bin');pins=p.imported('reference-observer-source-pins.bin')
    for index,key in enumerate(('native_packer_source','linked_policy_source','linked_packer_source')):
        actual=p.sha256(h[key]);prior=p.slice(pins,index*32,32);p.compare(actual,prior,label=label+':same-reference-source-'+key);p.drop(actual,prior)
    native_packer=build(p,h['observer'],h['check'],compiler,h['native_packer_source'],label=label+':compile-native-observer-packer')
    empty=p.literal(b'');native=build(p,h['observer'],h['check'],native_packer,empty,label=label+':actual-native-observer-emit')
    p.compare(native,reference,label=label+':every-native-observer-byte-from-preB0-VM')
    policy=build(p,h['observer'],h['check'],compiler,h['linked_policy_source'],label=label+':actual-policy-compile')
    packer=build(p,h['observer'],h['check'],compiler,h['linked_packer_source'],label=label+':actual-linked-packer-compile')
    obj=build(p,h['observer'],h['check'],packer,policy,label=label+':actual-linked-object-emit')
    linked_pack_reference(p,h,projected,policy,obj,label=label+':complete-actual-policy-VM-packing')
    linked=call(p,h['observer_linker'],obj,label=label+':pure-native-executable-link')
    # Real complete target shared object, scalar return and exact output/workspace.
    source=p.literal(b'hia-asm.v1 hepta.hia.program.v9 selfhost_elf\nfn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\nblock b0(s:readbuf,o:mutbuf,w:mutbuf)\n  at:usize = const() {"value":0}\n  value:u8 = buffer.load(s,at)\n  _ = buffer.store(o,at,value)\n  result:u32 = int.cast(value) {"mode":"wrap"}\n  ret(result)\nend\n')
    target=build(p,native,h['check'],compiler,source,label=label+':current-subject-object')
    text=utility(p,h['utility'],2,target,label=label+':closed-subject-ELF');p.drop(text)
    dso=call(p,h['linker'],target,label=label+':native-subject-shared-link')
    for index,byte in enumerate((0,128,255)):
        data=p.literal(bytes([byte]));expected=p.literal(bytes([byte]))
        linked_call(p,h,linked,dso,data,expected,label=label+':linked-byte-'+str(index),result=byte)
        p.drop(data,expected)
    p.publish(native,'native-observer.elf');p.publish(linked,'linked-observer.elf')
    p.drop(reference,projected,pins,native_packer,empty,policy,packer,obj,source,target,dso,native,linked)
    return ['native-observer.elf','linked-observer.elf']
