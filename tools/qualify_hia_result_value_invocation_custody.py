"""Kernel failure and concurrent custody gates for the real native invocation path."""
from pathlib import Path
import argparse, ctypes as C, errno, json, os, platform, queue, select, struct, threading, time
from tools.qualify_hia_result_value_invocations import Bound, Values, Engine, FRESH, echo_field, code_call, sweep, frame, word, ZERO
from tools.qualify_hia_native_callable_code_owner import listener, deny_native
from tools.qualify_hia_result_value_cleanup import Notification, Response, LIBC
from tools import generate_hia_result_value_invocations_packer as values_pack
from tools import generate_hia_native_callable_code_packer as code_pack

def ip_at(address,prefix):
    actual=bytearray(C.string_at(address,len(prefix.BRIDGE)))
    for at in prefix.HOLES:actual[at:at+4]=bytes(4)
    assert bytes(actual)==prefix.BRIDGE
    sites=[i+2 for i in range(len(prefix.BRIDGE)-1)if prefix.BRIDGE[i:i+2]==b'\x0f\x05']
    assert len(sites)==1
    return address+sites[0]

def bound(path):
    b=Bound(path);row=b.call(0);assert row['status']==0 and row['state']==2 and row['pending']==0,row
    assert word(b.owner.context,680)==62
    return b,Values(Engine(b))

def notified(v,request,ip,numbers,target,handle,output=None):
    ready=queue.Queue();result=queue.Queue();notices=[]
    def execute():
        try:
            ready.put(listener(ip,numbers))
            if output is None:result.put(v.engine.call(request))
            else:
                source=C.create_string_buffer(request)
                rc=int(v.engine.entry(source,len(request),output,16384,v.engine.context,256))
                assert source.raw==request+b'\0' and output.raw[16384:]==b'\xa5'*64+b'\0'
                result.put((rc,output.raw[:16384]))
        except BaseException as exc:ready.put(exc);result.put(exc)
    worker=threading.Thread(target=execute);worker.start()
    fd=ready.get(timeout=30)
    if isinstance(fd,BaseException):raise fd
    try:
        deadline=time.monotonic()+120
        while worker.is_alive():
            assert time.monotonic()<deadline,'native notification gate timed out'
            if not select.select([fd],[],[],0.2)[0]:continue
            notice=Notification()
            if LIBC.ioctl(fd,0xc0502100,C.byref(notice))<0:
                if C.get_errno()in(errno.EINTR,errno.ENOENT):continue
                raise OSError(C.get_errno(),'SECCOMP_IOCTL_NOTIF_RECV')
            assert notice.data.ip==ip and notice.data.nr in numbers
            error=handle(notice,len(notices))
            row=dict(number=notice.data.nr,ip=notice.data.ip,tid=notice.pid,args=list(notice.data.args),errno=error)
            notices.append(row);target.write_text(json.dumps(notices,indent=2)+'\n')
            reply=Response(notice.id,0,-error if error else 0,0 if error else 1)
            assert LIBC.ioctl(fd,0xc0182101,C.byref(reply))==0,C.get_errno()
        worker.join(1)
    finally:os.close(fd);worker.join(10)
    assert not worker.is_alive()
    pair=result.get_nowait()
    if isinstance(pair,BaseException):raise pair
    rc,out=pair
    target.with_suffix('.reply.bin').write_bytes(out)
    assert rc==0 and out[:8]==b'HIABVR01',(rc,out[:128].hex())
    return out,notices

def allocation_case(path,parent,label,component,nr,error,expected):
    b,v=bound(path);f=v.function(FRESH);arguments=v.tuple([])
    before=word(v.raw(47),48)
    ip=ip_at(b.value,values_pack)if component=='value'else ip_at(b.code,code_pack)
    reply,notes=notified(v,frame(70,a=f,b=arguments),ip,[nr],parent/(label+'.json'),lambda notice,index:error)
    assert notes and all(x['errno']==error for x in notes)
    assert word(reply,8)==expected and reply[24:48]==bytes(24)and word(reply,96)==0,reply[:128].hex()
    assert word(reply,80)==0 and word(v.raw(47),48)==before
    code=code_call(b,7);assert tuple(word(code,i)for i in(48,56,64,80))==(1,1,0,0)
    result=v.invoke(f,arguments);assert v.python_value(result)==[]
    sweep(v,b);b.close()
    return dict(case=label,actual_kernel_notifications=len(notes),status=expected,hidden_capabilities=0,actual_retry_execution=True)

def retirement_case(path,parent,label,component):
    b,v=bound(path);f=v.function(FRESH);arguments=v.tuple([]);before=word(v.raw(47),48)
    ip=ip_at(b.value,values_pack)if component=='value'else ip_at(b.code,code_pack)
    reply,notes=notified(v,frame(70,a=f,b=arguments),ip,[11],parent/(label+'.json'),lambda notice,index:errno.EIO)
    assert notes and all(x['errno']==errno.EIO for x in notes)
    assert (word(reply,8),word(reply,64),word(reply,80),word(reply,88),word(reply,96),word(reply,104))==(0,1,1,1,1,11),reply[:128].hex()
    result=v.keep(reply)
    # Read the native pending fact before any ordinary Value query can drain it.
    assert word(v.engine.context,184)==1
    arena=word(v.engine.context,16)
    head=word(C.string_at(arena+1096,8),0);assert head
    token=C.string_at(arena+head,96)
    assert word(token,40)==2 and word(token,80)and word(token,88)>=65536
    queued_record=word(token,80)
    record=C.string_at(queued_record,512)
    assert word(record,104)==1 and tuple(struct.unpack_from('<3Q',record,80))==result
    # One actual native entry performs retry, code cleanup, mapping retirement and ACK.
    v.raw(56)
    assert word(v.engine.context,184)==0
    assert word(v.raw(47),48)==before+1
    assert v.python_value(result)==[]
    code=code_call(b,7);assert tuple(word(code,i)for i in(48,56,64,80))==(1,1,0,0)
    assert not any(int(line.split('-')[0],16)<=queued_record<int(line.split()[0].split('-')[1],16)for line in Path('/proc/self/maps').read_text().splitlines())
    sweep(v,b);b.close()
    return dict(case=label,actual_kernel_notifications=len(notes),primary_delivered=True,real_pending_call_record=True,single_native_retry_and_ack=True,no_hidden_code_or_value=True)

def retention_case(path,parent):
    b,v=bound(path)
    env=v.lst([v.scalar('environment')]);f=v.function(echo_field(3),env=env)
    arguments=v.tuple([v.scalar(123),v.scalar('parameter')])
    observed={}
    def stop(notice,index):
        if index==0:
            assert word(v.engine.context,32)==0
            arena=word(v.engine.context,16);head=word(C.string_at(arena+1096,8),0)
            assert head
            token=C.string_at(arena+head,96)
            assert word(token,40)==1 and word(token,72)and word(token,80)
            record=C.string_at(word(token,80),512)
            assert word(record,16)==70 and word(record,192)and word(record,216)
            busy=b.call(1)
            assert busy['status']==6 and busy['state']==2,busy
            dropped=len(v.held)
            for cap in list(v.held):v.drop(cap)
            assert not v.held
            observed.update(caller_capabilities_dropped=dropped,actual_value_mutex=0,actual_call_token=True,sidecar_close_busy=True)
        return 0
    reply,notes=notified(v,frame(70,a=f,b=arguments),ip_at(b.code,code_pack),[39],parent/'concurrent-caller-drop.json',stop)
    assert (word(reply,8),word(reply,64),word(reply,80),word(reply,96),word(reply,104))==(0,1,0,1,0),reply[:128].hex()
    result=v.keep(reply);assert v.python_value(result)==(123,'parameter')
    code=code_call(b,7);assert tuple(word(code,i)for i in(48,56,64,80))==(0,0,0,0)
    assert word(v.engine.context,184)==0 and observed['caller_capabilities_dropped']>=5
    sweep(v,b);b.close()
    return dict(case='actual-code-stop-caller-drops-all-function-env-argument-caps',actual_kernel_notifications=len(notes),**observed)


def adoption_contention_case(path,parent):
    b,v=bound(path);f=v.function(FRESH);arguments=v.tuple([])
    before=word(v.raw(47),48)
    value_ip=ip_at(b.value,values_pack)
    output=C.create_string_buffer(b'\xa5'*(16384+64))
    blocked={};observed={};ready=queue.Queue();finished=queue.Queue()
    def hold_value():
        try:
            ready.put(listener(value_ip,[318]))
            finished.put(v.engine.call(frame(2,arg0=4,tail=b'lock holder')))
        except BaseException as exc:ready.put(exc);finished.put(exc)
    def call_record():
        arena=word(v.engine.context,16)
        head=word(C.string_at(arena+1096,8),0)
        if not head:return 0,None
        token=C.string_at(arena+head,96);address=word(token,80)
        return address,C.string_at(address,24576)if address else None
    def handle(notice,index):
        address,record=call_record()
        if notice.data.nr==39 and record is not None and word(record,2056)==89 and not blocked:
            assert word(record,8)==43 and word(v.engine.context,32)==0
            worker=threading.Thread(target=hold_value);worker.start()
            fd=ready.get(timeout=30)
            if isinstance(fd,BaseException):raise fd
            assert select.select([fd],[],[],30)[0]
            held=Notification()
            assert LIBC.ioctl(fd,0xc0502100,C.byref(held))==0
            assert held.data.nr==318 and held.data.ip==value_ip and word(v.engine.context,32)==1
            blocked.update(worker=worker,fd=fd,notice=held)
            observed.update(real_value_mutex_held=True,adopt_cap_untransferred=True)
        elif notice.data.nr==202 and blocked and 'denied'not in observed:
            assert notice.data.args[0]==C.addressof(b.owner.context)+544
            assert notice.data.args[1]==128 and record is not None and word(record,16384+128)==11
            observed['denied']=True
            return errno.EIO
        elif notice.data.nr==202 and observed.get('denied')and not observed.get('released'):
            assert word(output,128)==421 and record is not None and word(record,8)==640
            assert word(v.engine.context,32)==1
            held=blocked['notice'];reply=Response(held.id,0,0,1)
            assert LIBC.ioctl(blocked['fd'],0xc0182101,C.byref(reply))==0
            blocked['worker'].join(30);assert not blocked['worker'].is_alive()
            outcome=finished.get_nowait()
            if isinstance(outcome,BaseException):raise outcome
            rc,raw=outcome;assert rc==0 and raw[:8]==b'HIABVR01'and word(raw,8)==0
            blocked['cap']=v.keep(raw)
            observed.update(released=True,call_record_retained_before_outer_reacquisition=True)
        return 0
    try:
        reply,notes=notified(v,frame(70,a=f,b=arguments),value_ip,[39,202],parent/'adopt-contention.json',handle,output=output)
    finally:
        if blocked:
            if blocked['worker'].is_alive():
                held=blocked['notice'];resume=Response(held.id,0,0,1)
                LIBC.ioctl(blocked['fd'],0xc0182101,C.byref(resume));blocked['worker'].join(10)
            os.close(blocked['fd'])
    assert observed.get('released')and sum(x['errno']==errno.EIO for x in notes)==1
    assert (word(reply,8),word(reply,80),word(reply,88),word(reply,96),word(reply,104))==(11,1,1,0,11),reply[:128].hex()
    assert reply[24:48]==bytes(24)and word(v.engine.context,184)==1
    address,record=call_record();assert address and word(record,8)==640 and word(record,152)==1
    response=C.string_at(word(record,288),128);untransferred=word(response,24);assert untransferred
    arena=word(v.engine.context,16);node=C.string_at(arena+untransferred,96)
    assert word(node,40)==0 and word(node,8)!=0
    v.raw(56)
    assert word(v.engine.context,184)==0 and word(v.raw(47),48)==before+1
    code=code_call(b,7);assert tuple(word(code,i)for i in(48,56,64,80))==(1,1,0,0)
    sweep(v,b);b.close()
    return dict(case='real-futex-eio-before-temporary-cap-adoption',actual_kernel_notifications=len(notes),**observed,
                actual_unadopted_cap_preserved=True,single_native_retry_adopts_and_retires=True)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--owner',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert platform.python_version()=='3.14.4'
    args.output.mkdir(parents=True,exist_ok=False);rows=[]
    cases=[('value-random-eio','value',318,errno.EIO,11),('value-mapping-enomem','value',9,errno.ENOMEM,5),('code-mapping-enomem','code',9,errno.ENOMEM,5),('code-random-eio','code',318,errno.EIO,11)]
    for label,component,nr,error,status in cases:
        rows.append(allocation_case(args.owner,args.output,label,component,nr,error,status))
        (args.output/'partial.json').write_text(json.dumps(rows,indent=2)+'\n');print('INVOCATION_CUSTODY',label,flush=True)
    for label,component in [('code-retirement-eio','code'),('call-record-retirement-eio','value')]:
        rows.append(retirement_case(args.owner,args.output,label,component))
        (args.output/'partial.json').write_text(json.dumps(rows,indent=2)+'\n');print('INVOCATION_CUSTODY',label,flush=True)
    rows.append(retention_case(args.owner,args.output))
    rows.append(adoption_contention_case(args.owner,args.output))
    report=dict(schema='hia.native-invocation-custody.component.v1',component_qualified=True,groups=rows,actual_native_execution=True,actual_kernel_notifications=True,production_host_polling=False,whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(passed=True,groups=len(rows))))
if __name__=='__main__':main()
