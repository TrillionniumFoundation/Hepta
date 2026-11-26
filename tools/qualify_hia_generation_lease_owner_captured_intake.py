"""Real VFY capture to private canonical-Core intake; no constructor closure claim."""
from pathlib import Path
import argparse, ctypes as C, importlib.util, json, mmap, os, queue, struct, threading
from tools import qualify_hia_generation_lease_owner as q
from tools import generate_hia_generation_lease_owner_intake as author
from tools import generate_hia_multiversion_prepare_intake_packer as packer
from hepta.hia_program import verify_program
from hepta.hia_multiversion import _reference_scalar_profile

CLIENT=Path('/home/qian-qi/hia-followthrough-evidence-20261126-620a/verifier-explicit-release-v1/original-qa/explicit/client.py')
ROLES=('multiversion_prepare_process','multiversion_intake','core_admission',
       'json_canonical','native_scalar_proof_hash','multiversion_profile',
       'scalar_profile','multiversion_abi')
OUT=16793600
WORK=256<<20
BAD=0xfffffffd

def pin(raw):
    return dict(bytes=len(raw),sha256=q.sha(raw))

def wire(core,fd,totality=False,magic=b'HIAMVNQ2'):
    import time
    return struct.pack('<8s15Q',magic,int(totality),fd,time.monotonic_ns()+120000000000,
                       0,len(core),*([0]*10))+core

def invoke(image,raw):
    source=C.create_string_buffer(raw)
    with mmap.mmap(-1,OUT,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS) as output,\
         mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS) as work:
        output[:320]=b'\xa5'*320
        rc=image.entry(source,len(raw),q.address(output),OUT,q.address(work),WORK)
        assert source.raw==raw+b'\0'
        head=bytes(output[:320])
        n=320
        if head[:8]==b'HIAMVNP1' and q.get(head,8)==0:
            n+=q.get(head,32)+q.get(head,40)+q.get(head,48)
            assert n<=OUT
        return rc,bytes(output[:n])

def native_build(compiler,owner_build,output):
    author.main()
    source=(q.ROOT/q.BOOT/'generation_lease_owner_intake.hepta').read_bytes()
    policy=q.old.compiler_run(compiler,source,'generation_lease_owner_intake')
    (output/'generation_lease_owner_intake.flat').write_bytes(policy)
    raw_packer=(q.ROOT/q.BOOT/'multiversion_prepare_intake_packer.hepta').read_bytes()
    actual_packer=q.old.compiler_run(compiler,raw_packer,'multiversion_prepare_intake_packer')
    manifest=json.loads((owner_build/'build.json').read_bytes())
    frozen={Path(row['path']).stem:row for row in manifest['compile']}
    parts=[policy]
    dependencies={}
    for name in ROLES:
        raw=(owner_build/(name+'.flat')).read_bytes()
        assert len(raw)==frozen[name]['flat_bytes'] and q.sha(raw)==frozen[name]['flat_sha256']
        parts.append(raw)
        dependencies[name]=pin(raw)
    request=struct.pack('<11Q',packer.MAGIC,9,*map(len,parts))+b''.join(parts)
    actual=q.old.run_packer(actual_packer,request)
    assert actual==packer.reference_object(parts)
    (output/'intake-component.o').write_bytes(actual)
    sh=struct.unpack_from('<Q',actual,40)[0]
    off,size=struct.unpack_from('<2Q',actual,sh+64+24)
    flat=actual[off:off+size]
    (output/'intake-component.flat').write_bytes(flat)
    return q.Image(flat),dict(source=pin(source),policy=pin(policy),native_packer=pin(actual_packer),
                              native_object=pin(actual),flat=pin(flat),dependencies=dependencies,
                              double_compile_identical=True,native_pack_reference_equal=True)

def actual_producer_cases(image,client=CLIENT):
    spec=importlib.util.spec_from_file_location('actual_vfy_capture_client',client)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    verifier=module.Verify()
    before=set(os.listdir('/proc/self/fd'))
    raw=q.old.rawdoc(q.old.scalar_program(None))
    canonical=verify_program(raw).canonical_bytes
    selected=[('bytes',raw,False),('text',raw.decode(),False),
              ('dict',json.loads(raw),False),('vfy4-canonical-fields',canonical,True)]
    rows=[]
    last_core=None
    try:
        for label,value,verified in selected:
            cap=verifier.make(value)
            head,payload,context=verifier.call(cap,verified=verified)
            assert module.u(head,8)==0 and module.u(head,56)==0 and module.u(head,72)==0 and payload[0],head.hex()
            blob=verifier.payload.copy(payload,0,module.u(head,40))
            try:
                assert blob[:8]==b'HIAVCF01'
                assert module.u(blob,8)==module.u(blob,16)==module.u(blob,24)==module.u(blob,48)==module.u(blob,56)==0
                on,cn=module.u(blob,32),module.u(blob,40)
                assert len(blob)==64+on+cn and on==cn
                original,core=blob[64:64+on],blob[64+on:]
                assert original==core==canonical
                # Keep the actual native payload capability alive across all
                # consuming calls; no request-supplied verification flag exists.
                for totality in (False,True):
                    oracle=verify_program(core)
                    abi=_reference_scalar_profile(oracle,json.loads(core),prove_total=totality)
                    new_rc,new=invoke(image,wire(core,verifier.fd,totality))
                    old_rc,old=invoke(image,wire(core,verifier.fd,totality,b'HIAMVNQ1'))
                    assert new_rc==old_rc==0,(label,totality,new_rc,old_rc,new[:320].hex(),old[:320].hex())
                    assert new[:8]==old[:8]==b'HIAMVNP1'
                    assert q.get(new,248)==61 and q.get(old,248)==63
                    check=bytearray(new);struct.pack_into('<Q',check,248,63)
                    assert bytes(check)==old,(label,totality,'actual legacy/private output differs')
                    assert q.get(new,56)==len(abi) and q.get(new,64)==int(totality)
                    rows.append(dict(case=label,totality=totality,original_signatures=len(abi),
                                     native_vfy_payload=pin(blob),native_intake=pin(new),
                                     actual_legacy_equal_except_honest_process_mask=True))
                last_core=core
            finally:
                verifier.payload.drop(payload)
            verifier.reset_values()
        result=queue.Queue()
        def no_exec():
            try:
                q.deny_syscall(59,13)
                q.deny_syscall(322,13)
                rc,reply=invoke(image,wire(last_core,verifier.fd))
                assert rc==0 and q.get(reply,248)==61
                result.put(dict(case='private-intake-needs-no-second-normalizer',
                                actual_kernel_execve_and_execveat_denied=True,
                                passed=True))
            except BaseException as exc:
                result.put(exc)
        thread=threading.Thread(target=no_exec);thread.start();thread.join(45)
        assert not thread.is_alive(),'native intake did not finish'
        item=result.get_nowait()
        if isinstance(item,BaseException):raise item
        rows.append(item)
        controls=[]
        base=wire(last_core,verifier.fd)
        for label,offset,value in [('magic',0,0),('profile',8,2),('fd-low',16,2),
                                   ('deadline-zero',24,0),('private-pointer',32,8),
                                   ('length',40,len(last_core)+1),('reserved',48,1),
                                   ('reserved-last',120,1)]:
            changed=bytearray(base);struct.pack_into('<Q',changed,offset,value)
            rc,reply=invoke(image,bytes(changed))
            assert rc==BAD and reply==b'\xa5'*320,(label,rc,reply[:64].hex())
            controls.append(label)
        for label,changed in [('short',base[:127]),('truncated',base[:-1]),('trailing',base+b'x')]:
            rc,reply=invoke(image,changed)
            assert rc==BAD and reply==b'\xa5'*320,(label,rc,reply[:64].hex())
            controls.append(label)
        rejected=[]
        for label,core in [('bad-json',b'{'),('wrong-root',b'[]'),('not-canonical',b' '+last_core)]:
            rc,reply=invoke(image,wire(core,verifier.fd))
            assert reply[:8]==b'HIAMVNP1' and rc==q.get(reply,8) and rc!=0
            rejected.append(dict(case=label,status=rc,detail=q.get(reply,16)))
        assert set(os.listdir('/proc/self/fd'))==before
        return dict(cases=rows,controls=controls,actual_admission_rejections=rejected,
                    fd_set_unchanged=True,actual_native_vfy=True,
                    caller_owned_payload_retained_until_consumption=True,
                    vfy_value_pin='6aa48162de9636fd9a3a4552efce0cfa789e007db36aa261a1f3291134ea27b4',
                    client=pin(client.read_bytes()))
    finally:
        verifier.reset_values()
        verifier.finish()

def main():
    ap=argparse.ArgumentParser()
    for name in ('compiler','owner-build','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--verifier-client',type=Path,default=CLIENT)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    image,build=native_build(args.compiler,args.owner_build,args.output)
    (args.output/'build.json').write_text(json.dumps(build,indent=2)+'\n')
    behavior=actual_producer_cases(image,args.verifier_client)
    report=dict(schema='hepta.hia.generation-lease-captured-intake.qualification.v1',
                passed=True,build=build,behavior=behavior,
                fixed_enclosing_vfy_handoff_qualified=False,
                complete_generation_path_qualified=False,public_constructor_qualified=False,
                whole_public_runtime_qualified=False)
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('CAPTURED_INTAKE_ACTUAL_NATIVE_PASS',json.dumps(dict(groups=len(behavior['cases']),
          controls=len(behavior['controls']),admission_rejections=len(behavior['actual_admission_rejections']))),flush=True)
if __name__=='__main__':main()
