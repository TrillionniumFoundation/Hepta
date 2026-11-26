"""Actual Future truth exception delivery when native call retirement is refused."""
from pathlib import Path
import argparse,ctypes as C,errno,json,os,platform,queue,select,struct,threading,time,traceback
from tools.qualify_hia_future_native_truth import ManagedFixture,echo_field,word,pin,save
from tools.qualify_hia_result_value_invocation_custody import ip_at,values_pack,code_pack
from tools.qualify_hia_result_value_invocations import code_call
from tools.qualify_hia_native_callable_code_owner import listener
from tools.qualify_hia_result_value_cleanup import Notification,Response,LIBC

def execute_notified(f,borrowed,value,ip,path):
    p=f.actual.public
    raw=bytearray(192);raw[:8]=b'HIABFP04';struct.pack_into('<Q',raw,8,22)
    for at,cap in((16,borrowed[0]),(40,borrowed[1]),(64,value)):struct.pack_into('<3Q',raw,at,*cap)
    struct.pack_into('<Q',raw,96,1)
    source=C.create_string_buffer(bytes(raw),192);output=C.create_string_buffer(b'\xa5'*65568,65568)
    ready=queue.Queue();result=queue.Queue();notes=[]
    def invoke():
        try:
            ready.put(listener(ip,[11]))
            result.put(p.image.entry(source,192,output,65536,p.ctx,256))
        except BaseException as error:ready.put(error);result.put(error)
    worker=threading.Thread(target=invoke);worker.start();fd=ready.get(timeout=30)
    if isinstance(fd,BaseException):raise fd
    try:
        deadline=time.monotonic()+120
        while worker.is_alive():
            assert time.monotonic()<deadline
            if not select.select([fd],[],[],0.2)[0]:continue
            n=Notification()
            if LIBC.ioctl(fd,0xc0502100,C.byref(n))<0:
                if C.get_errno()in(errno.EINTR,errno.ENOENT):continue
                raise OSError(C.get_errno(),'SECCOMP_IOCTL_NOTIF_RECV')
            assert n.data.ip==ip and n.data.nr==11
            notes.append(dict(number=n.data.nr,ip=n.data.ip,tid=n.pid,args=list(n.data.args),errno=errno.EIO))
            save(path,notes)
            response=Response(n.id,0,-errno.EIO,0)
            assert LIBC.ioctl(fd,0xc0182101,C.byref(response))==0,C.get_errno()
        worker.join(1)
    finally:os.close(fd);worker.join(10)
    assert not worker.is_alive()
    rc=result.get_nowait()
    if isinstance(rc,BaseException):raise rc
    reply=output.raw[:65536];path.with_suffix('.reply.bin').write_bytes(reply)
    assert rc==0 and reply[:8]==b'HIABFRP3'and source.raw==bytes(raw)and output.raw[65536:]==b'\xa5'*32
    assert notes
    return reply,notes

def run(path,out):
    out.mkdir(parents=True,exist_ok=False)
    assert platform.python_version()=='3.14.4'
    report=dict(schema='hia.future.truth-custody.component.v1',passed=False,product=pin(path.read_bytes()),
                whole_public_future_qualified=False,complete_future_regression_qualified=False)
    rows=[]
    try:
        for class_id,category in((24,1),(21,2)):
            for component in('code','value'):
                f=ManagedFixture(path);v=f.v;p=f.future;borrowed=p.make(f.factory)
                actual=v.exception(v.builtin(class_id),v.tuple([v.scalar('preserve actual raised object')]))
                cls=v.cls('NativeTruthRaises',[]);fn=v.function(echo_field(1,2),env=actual)
                v.attr(cls,'__bool__',fn);instance=v.instance(cls);none=v.scalar(None)
                p.call(23,*borrowed,value=instance,kind=1)
                before_code=tuple(word(code_call(f.bound,7),i)for i in(48,56,64,80))
                ip=ip_at(f.bound.code,code_pack)if component=='code'else ip_at(f.bound.value,values_pack)
                reply,notes=execute_notified(f,borrowed,none,ip,out/(component+'-'+str(category)+'.json'))
                assert (word(reply,8),word(reply,16),word(reply,120))==(category,200,(1<<64)-1),reply[:192].hex()
                primary=v.keep(reply,72)
                pending_records=word(v.engine.context,184)
                assert pending_records>0
                retained_addresses=sorted(set(n['args'][0]for n in notes))
                def mapped(address):
                    return any(int(line.split('-')[0],16)<=address<int(line.split()[0].split('-')[1],16)
                        for line in Path('/proc/self/maps').read_text().splitlines())
                assert all(mapped(address)for address in retained_addresses)
                v.raw(47)
                assert word(v.engine.context,176)==word(v.engine.context,184)==0
                assert not any(mapped(address)for address in retained_addresses)
                assert v.same(primary,actual)
                assert tuple(word(code_call(f.bound,7),i)for i in(48,56,64,80))==before_code
                f.finish()
                rows.append(dict(case='actual-Future-truth-primary-survives-native-'+component+'-munmap-EIO',
                    category=category,notifications=len(notes),pending_call_records=pending_records,
                    failed_mappings_retained_until_retry=len(retained_addresses),primary_object_identity_preserved=True,
                    classification_preserved=True,cleanup_independently_pending=True,
                    ordinary_native_entry_retries=True,all_native_custody_released=True))
                print('FUTURE_TRUTH_CUSTODY_PASS',component,category,len(notes),flush=True)
        report.update(passed=True,groups=rows,actual_native_binding=True,single_value_arena=True)
    except BaseException as error:
        report.update(error=repr(error),traceback=traceback.format_exc());raise
    finally:save(out/'report.json',report)
    return report

def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.owner,a.output)
if __name__=='__main__':main()
