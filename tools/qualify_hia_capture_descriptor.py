"""Explicit raw descriptor ABI controls, separate from public Python equivalence."""
from __future__ import annotations
import argparse,ctypes,errno,json,os,struct,sys,tempfile
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
CASES=('ordinary','negative-kernel-result','no-follow','invalid-packet','unconfirmed-open','unconfirmed-close')

def one(manifest,case,output):
    from hepta.hia_capture_descriptor_effects import (
        NativeCaptureDescriptor,DescriptorInvocation,DescriptorUnknown,OPENAT,FSTAT,READ,CLOSE)
    from tests.hia_store_file_capture_controls import write
    manifest=Path(manifest);manifest_raw=manifest.read_bytes();value=json.loads(manifest_raw)
    if (value['schema']!='hepta.hia.raw-capture-descriptor.v1'
            or value['scope']!='EXPLICIT_RAW_ABI_DEVELOPMENT'
            or value['architecture']!='linux-x86_64'):
        raise ValueError('raw descriptor manifest has an unsupported identity')
    name=value['image_path']
    if type(name)is not str or Path(name).name!=name or name in ('','.','..'):
        raise ValueError('descriptor image must be a sibling basename')
    raw=(manifest.parent/name).read_bytes();source=(ROOT/'tools/hia_capture_descriptor_syscalls.S').read_bytes()
    if sha256(raw).hexdigest()!=value['image_sha256']:raise ValueError('descriptor image changed')
    image=NativeCaptureDescriptor(raw,value['image_sha256'],assembly_source=source,
                                  assembly_sha256=value['source_sha256'])
    output=Path(output);output.mkdir(mode=0o700);rows=[]
    def invoke(op,fd,**kw):
        call=DescriptorInvocation(image,op,fd,**kw);result=call.finish()
        rows.append({'operation':op,'result':result.result,'payload':result.payload.hex(),
                     'state':result.state.hex(),'confirmed':call.record.retired})
        return result
    with tempfile.TemporaryDirectory(prefix='hia-raw-descriptor-') as temporary:
        root=Path(temporary);data=root/'data';data.write_bytes(b'actual raw descriptor\x00\xff')
        flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
        if case=='ordinary':
            directory=invoke(OPENAT,-100,flags=flags|os.O_DIRECTORY,path=os.fsencode(root)).result
            if directory<0:raise AssertionError(rows)
            fd=invoke(OPENAT,directory,flags=flags,path=b'data').result
            if fd<0:raise AssertionError(rows)
            try:
                stat=invoke(FSTAT,fd)
                if stat.result!=0 or len(stat.payload)!=144:raise AssertionError(rows)
                read=invoke(READ,fd,count=64)
                if read.result!=len(data.read_bytes()) or read.payload[:read.result]!=data.read_bytes():
                    raise AssertionError(rows)
            finally:
                if invoke(CLOSE,fd).result!=0:raise AssertionError('close was not confirmed')
                if invoke(CLOSE,directory).result!=0:raise AssertionError('directory close was not confirmed')
        elif case=='negative-kernel-result':
            if invoke(OPENAT,-100,flags=flags,path=os.fsencode(root/'absent')).result!=-errno.ENOENT:
                raise AssertionError(rows)
            if invoke(FSTAT,-1).result!=-errno.EBADF or invoke(CLOSE,-1).result!=-errno.EBADF:
                raise AssertionError(rows)
        elif case=='no-follow':
            link=root/'link';link.symlink_to(data)
            if invoke(OPENAT,-100,flags=flags,path=os.fsencode(link)).result!=-errno.ELOOP:
                raise AssertionError(rows)
        elif case=='invalid-packet':
            entry=image._entry
            request=struct.pack('<2Qq5Q',0,OPENAT,-100,flags,0,1,1,2)+b'\0'
            a=ctypes.create_string_buffer(request,len(request));b=ctypes.create_string_buffer(b'\xa5'*64,64)
            c=ctypes.create_string_buffer(64)
            code=entry(a,len(request),b,64,c,64)
            if code!=0xfffffffd or a.raw!=request or b.raw!=b'\xa5'*64 or c.raw!=b'\0'*64:
                raise AssertionError('invalid raw request changed an output or workspace')
            rows.append({'code':code,'request':a.raw.hex(),'output':b.raw.hex(),'state':c.raw.hex()})
        else:
            fault=RuntimeError('lost descriptor return');entry=image._entry;calls=[]
            if case=='unconfirmed-close':
                fd=invoke(OPENAT,-100,flags=flags,path=os.fsencode(data)).result
                if fd<0:raise AssertionError(rows)
                invocation=DescriptorInvocation(image,CLOSE,fd)
            else:
                invocation=DescriptorInvocation(image,OPENAT,-100,flags=flags,path=os.fsencode(data))
            def lost(*arguments):
                result=entry(*arguments);calls.append(result);raise fault
            image._entry=lost
            try:invocation.finish()
            except BaseException as error:
                if error is not fault:raise AssertionError('raw lost return error changed') from error
            else:raise AssertionError('lost descriptor return completed')
            if calls!=[64] or invocation.record.loss is None or invocation.record.retired:
                raise AssertionError('actual native descriptor outcome was not retained')
            state=invocation.workspace.raw[:invocation.extent]
            if struct.unpack_from('<Q',state)[0]!=2:raise AssertionError('actual kernel result not persisted')
            before=len(calls)
            try:invocation.finish()
            except DescriptorUnknown:pass
            else:raise AssertionError('unknown raw request replayed')
            if len(calls)!=before:raise AssertionError('unknown raw request entered again')
            rows.append({'case':case,'actual_entry_codes':calls,'same_exception':True,
                'loss_retained':True,'state':state.hex(),'process_exit_is_cleanup_boundary':True})
            # No replay, registry clearing, heuristic close or fabricated errno.
    if manifest.read_bytes()!=manifest_raw or (manifest.parent/name).read_bytes()!=raw:
        raise ValueError('raw descriptor image or manifest changed')
    if (ROOT/'tools/hia_capture_descriptor_syscalls.S').read_bytes()!=source:
        raise ValueError('raw descriptor source changed')
    write(output/'report.json',{'schema':'hepta.hia.raw-capture-descriptor-control.v1',
          'case':case,'status':'PASS','rows':rows,'manifest_sha256':sha256(manifest_raw).hexdigest(),
          'image_sha256':sha256(raw).hexdigest(),'source_sha256':sha256(source).hexdigest(),
          'public_os_or_stream_equivalence_claimed':False,'matching_cold_claimed':False})

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--case',choices=CASES)
    a=p.parse_args()
    if a.case:return one(a.manifest,a.case,a.output)
    from tests.hia_store_file_capture_controls import run_process,clean_environment,write
    a.output.mkdir(mode=0o700);commands=[];reports=[]
    for name in CASES:
        _,_,command=run_process(a.output,name,[Path(__file__),'--manifest',a.manifest,
             '--output',a.output/name,'--case',name],env=clean_environment(),timeout=60)
        raw=(a.output/name/'report.json').read_bytes();row=json.loads(raw)
        if row['case']!=name or row['status']!='PASS':raise ValueError('raw control did not complete')
        commands.append(command);reports.append({'case':name,'sha256':sha256(raw).hexdigest()})
    write(a.output/'report.json',{'schema':'hepta.hia.raw-capture-descriptor-controls.v1',
        'scope':'EXPLICIT_RAW_ABI_ONLY','status':'PASS','cases':list(CASES),
        'commands':commands,'reports':reports,'all_six_owned_children':True,
        'whole_file_capture_qualified':False,'same_cold_HIA_qualified':False})
if __name__=='__main__':main()
