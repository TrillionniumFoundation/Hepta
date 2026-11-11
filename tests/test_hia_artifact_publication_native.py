"""Independent path/metadata/byte observations for the native publication policy."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
import json, os, struct, unittest
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import execute_program
from tools.generate_hia_artifact_publication import document
from tools.hia_selfhost_bulk import Body
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/hia_bootstrap/artifact_publication_policy.hepta'


def observe(wire, output_bytes, workspace, offsets=(), workspace_offsets=()):
    b=Body(0);owners=[];views=[]
    for data,size in ((wire,max(1,len(wire))),(output_bytes,1048576),(workspace,4096)):
        owner=b.value('buffer','buffer.new',[b.const('usize',size)]);owners.append(owner)
        view=b.value('mutbuf','borrow.mut',[owner])
        for at,value in enumerate(data):
            if value:b.effect('buffer.store',[view,b.const('usize',at),b.const('u8',value)])
        if not views:
            b.effect('loan.end',[view]);view=b.value('readbuf','borrow.read',[owner])
        views.append(view)
    result=b.value('u32','call',views,{'function':'f0'})
    values=[b.value('u8','buffer.load',[views[1],b.const('usize',at)]) for at in offsets]
    values += [b.value('u8','buffer.load',[views[2],b.const('usize',at)]) for at in workspace_offsets]
    for view in views:b.effect('loan.end',[view])
    for owner in owners:b.effect('owner.drop',[owner])
    source=('hia-asm.v1 hepta.hia.program.v8 artifact_reference\nfn observe() -> ('+
        ','.join(['u32']+['u8']*len(values))+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+
        b.text()+'  ret('+','.join([result,*values])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    observed=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert observed['status']=='returned',observed
    return observed['values'][0], bytes(observed['values'][1:])


def fields(**values):
    w=bytearray(4096)
    for offset,value in values.items():struct.pack_into('<Q',w,int(offset[1:]),value)
    return bytes(w)


class ArtifactPublicationPolicyTests(unittest.TestCase):
    def test_authoring_source_is_exact_and_resource_checked(self):
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))

    def test_native_packer_independent_VM_and_exact_generator(self):
        vm_pack(b"\xc3",b"\xc3")

    def test_paths_match_absolute_lexical_reference_without_resolving_dotdot(self):
        for stage,dest,cwd in [('a/./b','./out','/tmp'),('//a///b','/else','/'),('a/../b','d','/var/tmp')]:
            args=[b'publish',os.fsencode(stage),os.fsencode(dest),os.fsencode(cwd)]
            wire=struct.pack('<4Q',*[len(a) for a in args])+b''.join(args)
            expected=[]
            for raw in (stage,dest):
                expected.append(os.fsencode(str(PurePosixPath(raw) if raw.startswith('/') else PurePosixPath(cwd)/raw)))
            offsets=list(range(len(expected[0])+1))+list(range(262160,262160+len(expected[1])+1))
            code,actual=observe(wire,b'',fields(p0=0),offsets)
            self.assertEqual(code,1);self.assertEqual(actual,b'\0'.join(expected)+b'\0')
        args=[b'verify',b'/tmp/a',b'/tmp/./a/',b'/']
        wire=struct.pack('<4Q',*[len(a) for a in args])+b''.join(args)
        self.assertEqual(observe(wire,b'',fields(p0=0))[0],16)

    def test_bytes_are_authoritative_and_extra_or_missing_bytes_refused(self):
        for actual,total,offset,code in [(b'abc',3,0,0),(b'abd',3,0,11),(b'abcd',3,0,11),(b'a',3,4,11)]:
            self.assertEqual(observe(b'abc',actual,fields(p0=3,p16=total,p24=len(actual),p40=offset))[0],code)
        self.assertEqual(observe(b'',b'',fields(p0=4,p16=3,p40=2))[0],11)

    def test_identity_uses_inode_mode_size_mtime_ctime_not_uid_or_atime(self):
        def state(delta=None,post=False):
            w=bytearray(fields(p0=5 if post else 2,p32=1))
            st=bytearray(144)
            for at,v in [(0,7),(8,19),(24,0o100600),(48,3),(88,42),(96,9),(104,43),(112,10)]:
                struct.pack_into('<Q',st,at,v)
            w[272:416]=st;w[416:560]=st;w[704:848]=st;w[128:272]=st
            if delta is not None:
                at,v=delta;struct.pack_into('<Q',w,(128 if post else 416)+at,v)
            return bytes(w)
        self.assertEqual(observe(b'',b'',state())[0],0)
        for at in [0,8,24,48,88,96,104,112]:
            self.assertEqual(observe(b'',b'',state((at,99)))[0],12)
        for at in [16,72,80]:
            self.assertEqual(observe(b'',b'',state((at,99)))[0],0)
        self.assertEqual(observe(b'',b'',state((104,99),post=True))[0],0)
        self.assertEqual(observe(b'',b'',state((88,99),post=True))[0],12)

    def test_builder_rejects_old_source_cold_before_creating_output(self):
        import tempfile
        from tools.build_hia_artifact_publication import build,current_sources
        from tools.hia_selfhost_contract import PROFILE
        with tempfile.TemporaryDirectory(prefix='hia-publication-cold-refusal-') as folder:
            root=Path(folder);compiler=root/'compiler';compiler.write_bytes(b'not executed')
            cold=root/'cold.json';cold.write_text(json.dumps({'schema':'hepta.hia.selfhost-cold-replay.v1',
                'status':'COLD_SELFHOST_REPLAY_PASS','returncode':0,'profile':PROFILE,
                'source_manifest':dict(current_sources(),obsolete_source='00'*32),
                'checks':{},'generation_sha256':[]}))
            output=root/'must-not-exist'
            with self.assertRaisesRegex(ValueError,'matching-source'):
                build(output,compiler,cold)
            self.assertFalse(output.exists())

    def test_unknown_phase_and_unowned_withdrawal_refused(self):
        self.assertEqual(observe(b'',b'',fields(p0=99))[0],16)
        self.assertEqual(observe(b'',b'',fields(p0=6))[0],10)
        self.assertEqual(observe(b'',b'',fields(p0=1))[0],10)
        self.assertEqual(observe(b'',b'',fields(p0=3,p16=3,p24=3,p40=(1<<64)-1))[0],11)
        for success in (0,1):
            wanted=(json.dumps({'withdrawn':bool(success)},separators=(',',':'))+'\n').encode()
            n,raw=observe(b'',b'',fields(p0=8,p48=success),range(len(wanted)))
            self.assertEqual(n,len(wanted));self.assertEqual(raw,wanted)

    def test_receipt_formats_real_digest_and_full_u64_decimal(self):
        digest=bytes(range(32))
        for size in [0,1,4096,(1<<64)-1]:
            expected=(json.dumps({'sha256':digest.hex(),'bytes':size},separators=(',',':'))+'\n').encode()
            result,actual=observe(b'',digest,fields(p0=7,p16=size),range(len(expected)))
            self.assertEqual(result,len(expected));self.assertEqual(actual,expected)



class ArtifactPublicationKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        from tools.qualify_hia_selfhost import build_seed,compile_stage,invoke
        from tools.generate_hia_artifact_publication import MAGIC,template
        cls.temporary=tempfile.TemporaryDirectory(prefix='hia-publication-kernel-')
        cls.folder=Path(cls.temporary.name);cold_path=os.environ.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT')
        if cold_path:
            from tools.build_hia_artifact_publication import build
            outer=json.loads(Path(cold_path).read_bytes())
            inner=json.loads(Path(outer['nested_report']).read_bytes())
            cls.app=build(cls.folder/'build',Path(inner['generations'][-1]['produced_image']),Path(cold_path))
        else:
            # Independent policy and packer VM observations precede B0. The
            # development route is never called matching-source cold acceptance.
            observe(b'abc',b'abc',fields(p0=3,p16=3,p24=3))
            vm_pack(b'\xc3',b'\xc3')
            seed,_=build_seed(cls.folder)
            first,_=compile_stage(cls.folder,'B1',seed,(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes(),image_format='seed-shared')
            second,_=compile_stage(cls.folder,'B2',first,(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes())
            assert first.read_bytes()==second.read_bytes()
            images={}
            for name in ('artifact_publication_policy','artifact_publication_packer','sha256_stream'):
                images[name],_=compile_stage(cls.folder,name,second,(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes())
            policy=images['artifact_publication_policy'].read_bytes();sha=images['sha256_stream'].read_bytes()
            frame=struct.pack('<3Q',MAGIC,len(policy),len(sha))+policy+sha
            result,raw=invoke(cls.folder,'pack',images['artifact_publication_packer'],frame)
            size=result['core_u32'];assert 0<size<=len(raw)
            cls.app=cls.folder/'hia-artifact';cls.app.write_bytes(raw[:size]);cls.app.chmod(0o700)
        cls.serial=0

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        type(self).serial+=1
        self.case=self.folder/('case-'+str(self.serial));self.case.mkdir()
        self.stage=self.case/'stage';self.dest=self.case/'destination';self.payload=b'\0HIA\xffartifact\n'*327
        self.stage.write_bytes(self.payload)

    def run_app(self,op='publish',wire=None,code=0,stage=None,dest=None,prefix=()):
        import subprocess
        result=subprocess.run([*prefix,str(self.app),op,str(stage or self.stage),str(dest or self.dest)],
            input=self.payload if wire is None else wire,capture_output=True,env={'PATH':''},timeout=30)
        self.assertEqual(result.returncode,code,(result.stdout,result.stderr));return result

    def test_copied_empty_PATH_link_verify_withdraw_and_kernel_object(self):
        import shutil,subprocess
        from hashlib import sha256
        copied=self.case/'copied';shutil.copyfile(self.app,copied);copied.chmod(0o700)
        old=self.app;self.app=copied
        result=self.run_app();self.assertEqual(json.loads(result.stdout),{'sha256':sha256(self.payload).hexdigest(),'bytes':len(self.payload)})
        self.assertEqual(self.dest.stat().st_ino,self.stage.stat().st_ino)
        self.assertEqual(self.run_app('verify').stdout,result.stdout)
        self.assertEqual(json.loads(self.run_app('withdraw',wire=b'').stdout),{'withdrawn':True})
        self.assertEqual(json.loads(self.run_app('withdraw',wire=b'').stdout),{'withdrawn':False})
        self.app=old
        # A real machine-code object, produced and linked by external independent
        # compilers, witnesses bytes relevant to downstream native artifacts.
        compiler=shutil.which(os.environ.get('CLANG') or os.environ.get('HEPTA_CLANG') or 'clang-20')
        self.assertIsNotNone(compiler,'qualified Clang 20 is required')
        version=subprocess.run([compiler,'--version'],check=True,capture_output=True,text=True)
        self.assertRegex(version.stdout,r'\bclang version 20\.')
        source=self.case/'real.c';source.write_text('int answer(void){return 42;}\n')
        obj=self.case/'real.o';subprocess.run([compiler,'-c',str(source),'-o',str(obj)],check=True,capture_output=True)
        self.run_app(stage=obj,wire=obj.read_bytes());self.assertEqual(self.dest.read_bytes(),obj.read_bytes())
        main=self.case/'main.c';main.write_text('int answer(void);int main(void){return answer();}\n')
        exe=self.case/'real';subprocess.run([compiler,str(main),str(self.dest),'-o',str(exe)],check=True,capture_output=True)
        self.assertEqual(subprocess.run([str(exe)],env={'PATH':''},timeout=10).returncode,42)

    def test_refuses_missing_extra_changed_bytes_same_path_and_existing_entries(self):
        for bad in (b'',self.payload[:-1],self.payload+b'x',b'!'*len(self.payload)):
            self.run_app(wire=bad,code=16 if not bad else 11);self.assertFalse(self.dest.exists())
        self.run_app(dest=self.stage,code=16)
        self.dest.write_bytes(b'competitor');self.run_app(code=14);self.assertEqual(self.dest.read_bytes(),b'competitor')
        self.run_app('withdraw',wire=b'');self.assertEqual(self.dest.read_bytes(),b'competitor')
        alternate=self.case/'dangling';alternate.symlink_to(self.case/'absent');self.run_app(dest=alternate,code=14)
        self.assertTrue(alternate.is_symlink())

    def test_symlink_fifo_and_independent_equal_byte_inode_are_not_identity(self):
        linked=self.case/'sym';linked.symlink_to(self.stage)
        self.run_app(stage=linked,code=10)
        fifo=self.case/'fifo';os.mkfifo(fifo);self.run_app(stage=fifo,code=10)
        self.dest.write_bytes(self.payload);self.run_app('verify',code=10)
        self.assertEqual(json.loads(self.run_app('withdraw',wire=b'').stdout),{'withdrawn':False})
        self.assertEqual(self.dest.read_bytes(),self.payload)

    def test_streaming_exceeds_fixed_chunk_and_old_one_shot_limit(self):
        from hashlib import sha256
        payload=bytes(range(256))*((9<<20)//256+1)
        self.stage.write_bytes(payload)
        result=self.run_app(wire=payload)
        self.assertEqual(json.loads(result.stdout),{'sha256':sha256(payload).hexdigest(),'bytes':len(payload)})
        self.assertEqual(self.dest.stat().st_ino,self.stage.stat().st_ino)

    def test_real_syscall_EINTR_retry_and_no_child_or_dynamic_runtime(self):
        trace=self.case/'trace'
        result=self.run_app(prefix=('/usr/bin/strace','-f','-o',str(trace),'-e','trace=process,open,openat,read,write,link',
                    '-e','inject=read:error=EINTR:when=1','-e','inject=write:error=EINTR:when=1'))
        raw=trace.read_text();self.assertIn('EINTR',raw);self.assertEqual(raw.count('execve('),1)
        self.assertNotIn('openat(',raw);self.assertNotIn('clone(',raw);self.assertNotIn('vfork(',raw)
        self.assertNotIn('.so',raw);self.assertEqual(json.loads(result.stdout)['bytes'],len(self.payload))

    def test_post_link_actual_open_IO_failure_withdraws_own_link(self):
        trace=self.case/'io.trace'
        self.run_app(code=15,prefix=('/usr/bin/strace','-o',str(trace),'-e','trace=open,link,unlink',
                      '-e','inject=open:error=EIO:when=2'))
        self.assertIn('EIO',trace.read_text());self.assertFalse(self.dest.exists())
        self.assertEqual(self.stage.read_bytes(),self.payload)

    def test_receipt_write_failure_keeps_verified_link_without_success_claim(self):
        import subprocess
        process=subprocess.Popen([str(self.app),'publish',str(self.stage),str(self.dest)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''})
        process.stdout.close();process.stdout=None
        _,err=process.communicate(self.payload,timeout=10)
        self.assertEqual(process.returncode,15,err)
        self.assertEqual(self.dest.stat().st_ino,self.stage.stat().st_ino)
        self.assertEqual(self.dest.read_bytes(),self.payload)

    def race(self,injection,ready,mutation,code):
        import subprocess,time
        trace=self.case/'race.trace'
        process=subprocess.Popen(['/usr/bin/strace','-o',str(trace),'-e','trace=lstat,open,link,unlink',
            '-e',injection,str(self.app),'publish',str(self.stage),str(self.dest)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''})
        process.stdin.write(self.payload);process.stdin.close();process.stdin=None
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and process.poll() is None:
            if ready(trace.read_text() if trace.exists() else ''):
                mutation();break
            time.sleep(.001)
        else:
            process.kill();out,err=process.communicate();self.fail(('race not synchronized',out,err))
        out,err=process.communicate(timeout=10)
        self.assertEqual(process.returncode,code,(trace.read_text(),out,err));self.assertEqual(out,b'')

    def test_post_link_in_place_corruption_withdraws_only_own_link(self):
        self.race('inject=link:delay_exit=500ms',lambda trace:self.dest.exists(),
                  lambda:self.stage.write_bytes(b'X'*len(self.payload)),11)
        self.assertFalse(self.dest.exists());self.assertEqual(self.stage.read_bytes(),b'X'*len(self.payload))

    def test_post_link_competitor_replacement_is_never_withdrawn(self):
        replacement=self.case/'replacement';replacement.write_bytes(b'competitor')
        self.race('inject=link:delay_exit=500ms',lambda trace:self.dest.exists(),
                  lambda:os.replace(replacement,self.dest),10)
        self.assertEqual(self.dest.read_bytes(),b'competitor');self.assertEqual(self.stage.read_bytes(),self.payload)

    def test_regular_to_FIFO_race_is_nonblocking_and_refused(self):
        original=self.case/'original'
        def mutation():
            self.stage.rename(original);os.mkfifo(self.stage)
        self.race('inject=open:delay_enter=500ms',lambda trace:'lstat(' in trace and '= 0' in trace,mutation,12)
        self.assertFalse(self.dest.exists());self.assertEqual(original.read_bytes(),self.payload)


def vm_pack(policy,sha):
    from tools.generate_hia_artifact_publication import MAGIC,template,packer_source
    from hepta.hia_agent_assembly import render_assembly
    wire=struct.pack('<3Q',MAGIC,len(policy),len(sha))+policy+sha
    prefix,holes=template();wanted=bytearray(prefix+policy+sha)
    struct.pack_into('<Q',wanted,96,len(wanted));struct.pack_into('<Q',wanted,104,len(wanted))
    for key,at in holes.items():struct.pack_into('<I',wanted,at,len(prefix)+(len(policy) if key=='sha_hole' else 0)-at-4)
    b=Body(0);owners=[];views=[]
    # The reference expected bytes have a separate owner that the packer does
    # not receive. A compact VM loop compares EVERY output byte without
    # exceeding the unchanged human-assembly line/return-list budgets.
    for data,size in ((wire,len(wire)),(b'',len(wanted)),(b'',1),(wanted,len(wanted))):
        owner=b.value('buffer','buffer.new',[b.const('usize',size)]);owners.append(owner);view=b.value('mutbuf','borrow.mut',[owner])
        for at,value in enumerate(data):
            if value:b.effect('buffer.store',[view,b.const('usize',at),b.const('u8',value)])
        if len(views) in (0,3):
            b.effect('loan.end',[view]);view=b.value('readbuf','borrow.read',[owner])
        views.append(view)
    result=b.value('u32','call',views[:3],{'function':'f0'})
    mismatch=b.value('u8','call',[views[1],views[3]],{'function':'observe_bytes'})
    for view in views:b.effect('loan.end',[view])
    for owner in owners:b.effect('owner.drop',[owner])
    reference_body="""def compare(o:mutbuf, s:readbuf) -> u8:
    position = 0
    error = 0
    while position < length(s):
        error = error | (byte(o, position) ^ byte(s, position))
        position = position + 1
    return error
"""
    reference=render_assembly(document(reference_body,'independent_byte_comparison')).split('\n',1)[1]
    reference=reference.replace('fn f0(', 'fn observe_bytes(')
    source=('hia-asm.v1 hepta.hia.program.v8 packer_reference\n'
        'fn observe() -> (u32,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+
        '  ret('+result+','+mismatch+')\nend\n'+reference+
        (ROOT/'examples/hia_bootstrap/artifact_publication_packer.hepta').read_text().split('\n',1)[1])
    actual=execute_program(assemble_program(source),'observe',[],max_steps=2000000)
    assert actual['status']=='returned' and actual['values']==[len(wanted),0],actual
    assert (ROOT/'examples/hia_bootstrap/artifact_publication_packer.hepta').read_text()==render_assembly(document(packer_source(),'artifact_publication_packer'))


if __name__=='__main__':unittest.main()
