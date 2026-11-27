"""Independent VM and actual-kernel selected-release launch observations.

The target fixtures are explicitly authorized native bytes, not a claim that
arbitrary ELF bytes are HIA. Development compiler custody is separately named.
"""
from __future__ import annotations

from collections import Counter
import ctypes
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import execute_program
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_launch import (
    MAGIC, EXPECTED_ADAPTER_INPUTS, policy_source, packer_source, template, adapter_source,
)
from tools.build_hia_release_launch import build
from tools.hia_selfhost_bulk import Body
from tests.test_hia_release_install import bundle

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT/'examples/hia_bootstrap/release_launch_policy.hepta'
PACKER = ROOT/'examples/hia_bootstrap/release_launch_packer.hepta'


def arguments(root=b'/tmp', sequence=b'1', release=b'0'*64, name=b'app',
              digest=b'1'*64, argument=b'run'):
    parts = (root, sequence, release, name, digest, argument)
    return struct.pack('<6Q', *map(len, parts)) + b''.join(parts)


def fields(**kw):
    raw = bytearray(8192)
    for key, value in kw.items():
        struct.pack_into('<Q', raw, int(key[1:]), value)
    return raw


def executable(code):
    size = 176 + len(code)
    return (b'\x7fELF\x02\x01\x01' + bytes(9)
        + struct.pack('<HHIQQQIHHHHHH', 2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        + struct.pack('<IIQQQQQQ', 1,5,0,0x400000,0x400000,size,size,4096)
        + struct.pack('<IIQQQQQQ', 0x6474e551,6,0,0,0,0,0,16) + code)


def exit_image(code=37):
    return executable(b'\xbf'+struct.pack('<I',code)+b'\xb8\x3c\0\0\0\x0f\x05')


def package_table(wire):
    """Independent test-only decoder of the original installer's row ABI."""
    from tests.test_hia_release_install import reference_unpack
    reference_unpack(wire)
    table = bytearray(65536)
    count = struct.unpack_from('<Q',wire,8)[0]
    struct.pack_into('<2Q',table,16,len(wire),count)
    at=24
    for index in range(count):
        name,mode,size=struct.unpack_from('<3Q',wire,at);at+=24
        struct.pack_into('<5Q',table,4096+index*96,at,name,at+name,size,mode)
        at+=name+size
    return bytes(table)


def vm_equal(wire, output, workspace, expected_code, expected_output, expected_workspace):
    """Compare every output/workspace byte in the independent owned-buffer VM."""
    b=Body(0);owners=[];views=[]
    for index,data in enumerate((wire,output,workspace,expected_output,expected_workspace)):
        owner=b.value('buffer','buffer.new',[b.const('usize',len(data))]);owners.append(owner)
        view=b.value('mutbuf','borrow.mut',[owner])
        fill=Counter(data).most_common(1)[0][0] if data else 0
        if fill:b.effect('buffer.fill',[view,b.const('u8',fill)])
        for at,value in enumerate(data):
            if value!=fill:b.effect('buffer.store',[view,b.const('usize',at),b.const('u8',value)])
        if index in (0,3,4):
            b.effect('loan.end',[view]);view=b.value('readbuf','borrow.read',[owner])
        views.append(view)
    result=b.value('u32','call',views[:3],{'function':'f0'})
    out=b.value('u8','call',[views[1],views[3]],{'function':'compare_all'})
    work=b.value('u8','call',[views[2],views[4]],{'function':'compare_all'})
    for view in views:b.effect('loan.end',[view])
    for owner in owners:b.effect('owner.drop',[owner])
    compare='''def compare(o:mutbuf, s:readbuf) -> u8:
    i = 0
    different = 0
    while i < length(s):
        different = different | (byte(o, i) ^ byte(s, i))
        i = i + 1
    return different
'''
    compare=render_assembly(document(compare,'full_frame_compare')).split('\n',1)[1].replace('fn f0(', 'fn compare_all(')
    text=('hia-asm.v1 hepta.hia.program.v8 launch_frame_reference\n'
          'fn observe() -> (u32,u8,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
          +b.text()+f'  ret({result},{out},{work})\nend\n'+compare+POLICY.read_text().split('\n',1)[1])
    report=execute_program(assemble_program(text),'observe',[],max_steps=6000000)
    if (report['status']!='returned' or report['values']!=[expected_code,0,0]
            or report['resources']['live_owners'] or report['resources']['live_local_loans']):
        raise AssertionError(report)
    return report


def argument_expected(wire):
    lengths=struct.unpack_from('<6Q',wire);parts=[];at=48
    for size in lengths:parts.append(wire[at:at+size]);at+=size
    root,sequence,release,name,digest,argument=parts
    output=bytearray([165])*8192
    packet=struct.pack('<5Q',6,len(root),len(sequence),64,0)+b'verify'+root+sequence+release
    output[:len(packet)]=packet
    work=fields(p8=1,p16=len(name),p24=len(argument))
    work[128:192]=digest;work[256:256+len(name)]=name;work[512:512+len(argument)]=argument
    return len(packet),bytes(output),bytes(work)


class ReleaseLaunchFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_release_launch import selected_cold_fixture,admit_fixture
        cls.cold_fixture_path=selected_cold_fixture()
        if cls.cold_fixture_path is None:
            path=os.environ.get('HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_BUILD')
            if path is None:raise RuntimeError('explicit development BUILD.json required')
            data=json.loads(Path(path).read_bytes())
            if data['status']!='DEVELOPMENT_IMAGES_BUILT' or data['matching_cold'] is not False:
                raise ValueError('unknown development build record')
        else:
            data=admit_fixture(cls.cold_fixture_path)
        if sha256(POLICY.read_bytes()).hexdigest()!=data['source_sha256']['release_launch_policy']:
            raise ValueError('policy source changed')
        cls.raw=Path(data['policy_image']).read_bytes()
        cls.image=NativeHiaJsonImage(cls.raw,data['policy_sha256'])

    @classmethod
    def tearDownClass(cls):
        cls.image._mapping.close()
        if cls.cold_fixture_path is not None:
            from tools.qualify_hia_release_launch import admit_fixture
            admit_fixture(cls.cold_fixture_path)

    def compare(self,wire,out,work,code,expected_out,expected_work):
        vm_equal(wire,out,work,code,expected_out,expected_work)
        buffers=[]
        for data in (wire,out,work):
            raw=bytes([0x69])*32+bytes(data)+bytes([0x96])*32
            owner=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
            buffers.append((owner,raw,len(data)))
        args=[]
        for owner,_,size in buffers:args.extend((ctypes.addressof(owner)+32,size))
        result=int(self.image._entry(*args))
        self.assertEqual(result,code)
        for (owner,original,size),expected in zip(buffers,(wire,expected_out,expected_work)):
            actual=bytes(owner)
            self.assertEqual(actual[:32],original[:32])
            self.assertEqual(actual[32:32+size],bytes(expected))
            self.assertEqual(actual[32+size:],original[32+size:])

    def test_argument_result_and_refusals_match_complete_vm_and_native_frames(self):
        wire=arguments();code,out,work=argument_expected(wire)
        self.compare(wire,bytes([165])*8192,bytes(8192),code,out,work)
        self.compare(b'',bytes([165])*8192,bytes(8192),16,bytes([165])*8192,bytes(8192))

    def test_exact_entry_and_elf_refusal_match_complete_vm_and_native_frames(self):
        image=exit_image();wire=bundle([('app',0o500,image)])
        table=package_table(wire);work=fields(p0=1,p8=1,p16=3);work[256:259]=b'app'
        expected=bytearray(work);start,size=struct.unpack_from('<2Q',table,4096+16)
        struct.pack_into('<3Q',expected,32,start,size,0);struct.pack_into('<Q',expected,8,2)
        self.compare(wire,table,work,0,table,expected)
        changed=bytearray(image);changed[16]=3
        wire=bundle([('app',0o500,bytes(changed))]);table=package_table(wire)
        self.compare(wire,table,work,10,table,work)

    def test_seal_digest_terminal_and_replay_match_complete_vm_and_native_frames(self):
        image=exit_image();digest=sha256(image).digest()
        work=fields(p0=2,p8=2,p40=len(image),p64=63,p80=len(image),p88=1234,
                    p848=0,p856=33088|(1234<<32),p880=len(image))
        work[128:192]=sha256(image).hexdigest().encode()
        expected=bytearray(work);struct.pack_into('<Q',expected,8,3)
        self.compare(digest,b'canary',work,0,b'canary',expected)
        bad=bytearray(work);struct.pack_into('<Q',bad,64,15)
        self.compare(digest,b'canary',bad,11,b'canary',bad)
        terminal=fields(p0=3,p8=3);done=fields(p0=3,p8=4)
        self.compare(b'',b'',terminal,0,b'',done)
        self.compare(b'',b'',done,16,b'',done)


class ReleaseLaunchSourceTests(unittest.TestCase):
    def test_generated_hia_and_verifier_transport_preimages_are_exact(self):
        self.assertEqual(POLICY.read_text(),render_assembly(document(policy_source(),'release_launch_policy')))
        self.assertEqual(PACKER.read_text(),render_assembly(document(packer_source(),'release_launch_packer')))
        for name,digest in EXPECTED_ADAPTER_INPUTS.items():
            self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(),digest)
        from tools.generate_hia_release_selection import adapter_source as old_adapter
        old=old_adapter();new=adapter_source()
        original_verify=old[old.index('verify_tree:\n'):old.index('strlen_bounded:\n')]
        self.assertEqual(new.count(original_verify),1)
        self.assertIn('stdin_next:\n mov edi,3\n',new)
        self.assertNotIn('mov edi,13\n',new)
        self.assertIn('sgate 20\n sgate 18\n call selection_check_lock_name\n stat_current r14d\n gate 5\n jmp launch_enter',new)
        self.assertLess(new.index('call launch_prepare_image'),new.index('sgate 20\n'))

    def test_independent_vm_arguments_complete_buffers_and_bounds(self):
        wire=arguments();code,out,work=argument_expected(wire)
        vm_equal(wire,bytes([165])*8192,bytes(8192),code,out,work)
        for wire in (b'',arguments(name=b'../escape'),arguments(argument=b'x'*32)):
            with self.subTest(input_bytes=len(wire)):
                # All three fail before the first workspace/output write.
                vm_equal(wire,bytes([165])*8192,bytes(8192),16,bytes([165])*8192,bytes(8192))

    def test_independent_vm_entry_and_exact_canonical_elf(self):
        image=exit_image();wire=bundle([('readme',0o400,b'x'),('app',0o500,image)])
        table=package_table(wire);work=fields(p0=1,p8=1,p16=3);work[256:259]=b'app'
        expected=bytearray(work);start,size=struct.unpack_from('<2Q',table,4096+96+16)
        struct.pack_into('<3Q',expected,32,start,size,1);struct.pack_into('<Q',expected,8,2)
        vm_equal(wire,table,work,0,table,expected)
        refused=bundle([('app',0o400,image)]);rt=package_table(refused)
        vm_equal(refused,rt,work,10,rt,work)

    def test_independent_vm_actual_seal_metadata_digest_and_one_terminal(self):
        image=exit_image();digest=sha256(image).digest()
        work=fields(p0=2,p8=2,p40=len(image),p64=63,p80=len(image),p88=1234,
                    p848=0,p856=33088|(1234<<32),p880=len(image))
        work[128:192]=sha256(image).hexdigest().encode()
        expected=bytearray(work);struct.pack_into('<Q',expected,8,3)
        vm_equal(digest,bytes([165])*16,work,0,bytes([165])*16,expected)
        bad=bytearray(work);struct.pack_into('<Q',bad,64,15)
        vm_equal(digest,bytes([165])*16,bad,11,bytes([165])*16,bad)
        terminal=fields(p0=3,p8=3);done=fields(p0=3,p8=4)
        vm_equal(b'',b'',terminal,0,b'',done)
        vm_equal(b'',b'',done,16,b'',done)

    def test_builder_rejects_unqualified_cold_before_output(self):
        with tempfile.TemporaryDirectory(prefix='hia-launch-refusal-') as folder:
            root=Path(folder);compiler=root/'compiler';cold=root/'cold.json'
            compiler.write_bytes(b'unqualified');cold.write_text('{}')
            with self.assertRaises(ValueError):build(root/'output',compiler,cold)
            self.assertFalse((root/'output').exists())


def prepare_development(folder):
    """Fresh B0/B1/B2/B3; explicitly development, never a production build bypass."""
    from tools.qualify_hia_selfhost import build_seed,compile_stage,invoke
    folder=Path(folder);folder.mkdir(mode=0o700)
    seed,seed_receipt=build_seed(folder)
    compiler_source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
    first,r1=compile_stage(folder,'B1',seed,compiler_source,image_format='seed-shared')
    second,r2=compile_stage(folder,'B2',first,compiler_source)
    third,r3=compile_stage(folder,'B3',second,compiler_source)
    if not first.read_bytes()==second.read_bytes()==third.read_bytes():
        raise AssertionError('fresh development compiler fixed point differs')
    names=('release_install_policy','release_install_packer','sha256_stream',
           'release_selection_policy','release_selection_packer',
           'release_launch_policy','release_launch_packer')
    images={};receipts={};sources={}
    for name in names:
        raw=(ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes();sources[name]=sha256(raw).hexdigest()
        images[name],receipts[name]=compile_stage(folder,name,third,raw)
    from tools.generate_hia_release_install import MAGIC as INSTALL
    from tools.generate_hia_release_selection import MAGIC as SELECTION
    executables={};packs={}
    for label,roles,packer,magic in (
        ('hia-release',('release_install_policy','sha256_stream'),'release_install_packer',INSTALL),
        ('hia-select',('release_install_policy','sha256_stream','release_selection_policy'),'release_selection_packer',SELECTION),
        ('hia-run-selected',('release_install_policy','sha256_stream','release_selection_policy','release_launch_policy'),'release_launch_packer',MAGIC)):
        payloads=[images[name].read_bytes() for name in roles]
        frame=struct.pack('<'+'Q'*(len(payloads)+1),magic,*map(len,payloads))+b''.join(payloads)
        report,raw=invoke(folder,'pack-'+label,images[packer],frame)
        if report['status']!='returned' or not 0<report['core_u32']<=len(raw):raise AssertionError(report)
        path=folder/label;path.write_bytes(raw[:report['core_u32']]);path.chmod(0o700)
        from tools.qualify_hia_selfhost_cli import inspect_executable
        inspection=inspect_executable(path.read_bytes())
        executables[label]={'path':str(path.resolve()),'sha256':sha256(path.read_bytes()).hexdigest(),'inspection':inspection}
        packs[label]=report
    result={'schema':'hia.release-launch.development-build.v1','status':'DEVELOPMENT_IMAGES_BUILT',
            'compiler_receipts':[seed_receipt,r1,r2,r3],'source_sha256':sources,
            'compile_receipts':receipts,'pack_receipts':packs,'executables':executables,
            'policy_image':str(images['release_launch_policy'].resolve()),
            'policy_sha256':sha256(images['release_launch_policy'].read_bytes()).hexdigest(),
            'matching_cold':False,'whole_native':False}
    (folder/'BUILD.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result


class ReleaseLaunchKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_release_launch import selected_cold_fixture,admit_fixture,COLD_EVIDENCE_ENV
        cls.cold_fixture_path=selected_cold_fixture()
        if cls.cold_fixture_path is None:
            selected=os.environ.get('HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_BUILD')
            if not selected:raise RuntimeError('explicit development BUILD.json required; no cold authority inferred')
            cls.build_path=Path(selected);cls.build_raw=cls.build_path.read_bytes();data=json.loads(cls.build_raw)
            if data.get('status')!='DEVELOPMENT_IMAGES_BUILT' or data.get('matching_cold') is not False:
                raise ValueError('unknown development build record')
        else:
            cls.build_path=cls.cold_fixture_path;cls.build_raw=cls.build_path.read_bytes()
            data=admit_fixture(cls.build_path)
        cls.applications={}
        for name,row in data['executables'].items():
            p=Path(row['path']);raw=p.read_bytes()
            if sha256(raw).hexdigest()!=row['sha256']:raise ValueError('changed development executable')
            cls.applications[name]=p
        for name,digest in data['source_sha256'].items():
            if sha256((ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes()).hexdigest()!=digest:
                raise ValueError('changed actual HIA source')
        evidence_name=(COLD_EVIDENCE_ENV if cls.cold_fixture_path is not None
                       else 'HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_EVIDENCE')
        base=Path(os.environ.get(evidence_name,
                                cls.build_path.parent/'kernel-controls'))
        base.mkdir(mode=0o700,parents=True,exist_ok=True)
        cls.root=base/cls.__name__;cls.root.mkdir(mode=0o700)
        cls.observations=[];cls.serial=0

    @classmethod
    def tearDownClass(cls):
        if cls.build_path.read_bytes()!=cls.build_raw:raise AssertionError('build record changed')
        scope='DEVELOPMENT_KERNEL_NOT_COLD'
        if cls.cold_fixture_path is not None:
            from tools.qualify_hia_release_launch import admit_fixture
            admit_fixture(cls.cold_fixture_path)
            scope='MATCHING_SOURCE_COLD_KERNEL_OBSERVATIONS'
        (cls.root/'OBSERVATIONS.json').write_text(json.dumps({'scope':scope,
            'observations':cls.observations,'whole_native':False},indent=2,sort_keys=True)+'\n')

    def setUp(self):
        type(self).serial+=1
        self.case=self.root/f'{self.serial:03d}-{self._testMethodName}';self.case.mkdir(mode=0o700)
        self.releases=self.case/'releases';self.releases.mkdir(mode=0o700)

    def tool(self,name,args,payload=b''):
        p=subprocess.run([str(self.applications[name]),*map(str,args)],input=payload,
                         capture_output=True,env={'PATH':''},timeout=30)
        self.record(name,p)
        return p

    def record(self,label,p):
        at=len(self.observations);prefix=self.case/f'{at:04d}-{label}'
        prefix.with_suffix('.stdout').write_bytes(p.stdout or b'')
        prefix.with_suffix('.stderr').write_bytes(p.stderr or b'')
        self.observations.append({'test':self.id(),'label':label,'returncode':p.returncode,
            'pid':getattr(p,'observed_pid',None),
            'stdout_hex':(p.stdout or b'').hex(),'stderr_hex':(p.stderr or b'').hex()})

    def install(self,image=None,mode=0o500,entry='app',extras=()):
        image=exit_image() if image is None else image
        self.image=image;self.entry=entry
        self.package=bundle([(entry,mode,image),*extras]);self.digest=sha256(self.package).hexdigest()
        self.package_path=self.case/'package';self.package_path.write_bytes(self.package)
        p=self.tool('hia-release',['install',self.releases,self.digest],self.package)
        self.assertEqual(p.returncode,0,(p.stdout,p.stderr))
        p=self.tool('hia-select',['activate',self.releases,'0','-',self.digest],self.package)
        self.assertEqual(p.returncode,0,(p.stdout,p.stderr))

    def launch(self,*,payload=b'',sequence='1',release=None,entry=None,digest=None,argument='run',
               package=None,prefix=(),restore_signals=True,preexec=None,stdout=subprocess.PIPE,
               after_start=None):
        package_path=self.package_path
        if package is not None:
            package_path=self.case/f'package-variant-{len(self.observations)}';package_path.write_bytes(package)
        args=[str(self.applications['hia-run-selected']),str(self.releases),sequence,
              self.digest if release is None else release,self.entry if entry is None else entry,
              sha256(self.image).hexdigest() if digest is None else digest,argument]
        fd=os.open(package_path,os.O_RDONLY)
        try:
            # keep fd3 through Popen's close-fd phase, even if setup duplicates.
            saved=None
            if fd!=3:
                try:saved=os.dup(3)
                except OSError:pass
                os.dup2(fd,3)
            try:
                child=subprocess.Popen([*prefix,*args],stdin=subprocess.PIPE,
                    stdout=stdout,stderr=subprocess.PIPE,pass_fds=(3,),preexec_fn=preexec,
                    env={'PATH':''},restore_signals=restore_signals,start_new_session=True)
                try:
                    observed=b'' if after_start is None else after_start(child)
                    out,err=child.communicate(payload,timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid,signal.SIGKILL)
                    out,err=child.communicate(timeout=5)
                    self.record('timeout-launch',subprocess.CompletedProcess(args,child.returncode,out,err))
                    raise
                except BaseException:
                    if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
                    child.communicate(timeout=5)
                    raise
                out=(observed or b'')+(out or b'')
                p=subprocess.CompletedProcess(args,child.returncode,out,err)
                p.observed_pid=child.pid
            finally:
                if fd!=3:
                    if saved is not None:os.dup2(saved,3);os.close(saved)
                    else:os.close(3)
        finally:os.close(fd)
        self.record('launch',p)
        return p

    def assemble_fixture(self,name,body):
        src=self.case/(name+'.S');obj=self.case/(name+'.o');raw=self.case/(name+'.bin')
        src.write_text('.intel_syntax noprefix\n.text\n.global _start\n_start:\n'+body+'\n')
        subprocess.run(['as','--64',str(src),'-o',str(obj)],check=True,capture_output=True,timeout=10)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True,timeout=10)
        return executable(raw.read_bytes())

    def test_exact_native_exit_and_original_verify_remains_nonexecuting(self):
        self.install()
        p=self.tool('hia-select',['verify',self.releases,'1',self.digest],self.package)
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout)['operation'],'verify')
        p=self.launch();self.assertEqual((p.returncode,p.stdout,p.stderr),(37,b'',b''))

    def test_business_stdin_stdout_and_same_process_native_pid(self):
        image=self.assemble_fixture('echo', '''sub rsp,32
mov eax,39
syscall
mov [rsp],rax
mov eax,1
mov edi,1
mov rsi,rsp
mov edx,8
syscall
xor eax,eax
xor edi,edi
lea rsi,[rsp+8]
mov edx,1
syscall
cmp rax,1
jne bad
mov eax,1
mov edi,1
lea rsi,[rsp+8]
mov edx,1
syscall
mov edi,42
jmp done
bad: mov edi,99
done: mov eax,60
syscall''')
        self.install(image)
        p=self.launch(payload=b'Q');self.assertEqual(p.returncode,42);self.assertEqual(p.stdout[8:],b'Q')
        self.assertEqual(len(p.stdout),9)
        self.assertEqual(struct.unpack('<Q',p.stdout[:8])[0],p.observed_pid)

    def test_stale_sequence_release_and_separate_execution_digest_refuse(self):
        self.install()
        for options,code in (({'sequence':'2'},19),({'release':'0'*64},11),
                             ({'digest':'0'*64},11),({'entry':'missing'},10)):
            with self.subTest(options=options):
                p=self.launch(**options);self.assertEqual((p.returncode,p.stdout),(code,b''))

    def test_nonexecuting_mode_and_noncanonical_elf_are_not_old_verify_refusals(self):
        self.install(mode=0o400)
        p=self.tool('hia-select',['verify',self.releases,'1',self.digest],self.package)
        self.assertEqual(p.returncode,0)
        p=self.launch();self.assertEqual((p.returncode,p.stdout),(10,b''))

    def test_explicit_native_text_and_dynamic_elf_profile_refuse_only_execution(self):
        for image in (b'authorized non-ELF text',exit_image()[:16]+b'\x03\x00'+exit_image()[18:]):
            with self.subTest(image_sha256=sha256(image).hexdigest()):
                self.releases=self.case/('root-'+sha256(image).hexdigest());self.releases.mkdir(mode=0o700)
                self.install(image)
                self.assertEqual(self.tool('hia-select',['verify',self.releases,'1',self.digest],self.package).returncode,0)
                self.assertEqual((self.launch().returncode),10)

    def test_target_observes_all_seals_no_private_descriptors_and_empty_environment(self):
        image=self.assemble_fixture('self-seals','''cmp QWORD PTR [rsp],2
jne bad
cmp QWORD PTR [rsp+32],0
jne bad
mov ebx,3
fds:
mov edi,ebx
mov esi,1
mov eax,72
syscall
cmp rax,-9
jne bad
inc ebx
cmp ebx,256
jne fds
lea rdi,[rip+exe]
xor esi,esi
xor edx,edx
mov eax,2
syscall
test rax,rax
js bad
mov r12,rax
mov rdi,rax
mov esi,1034
mov eax,72
syscall
cmp rax,63
jne bad
mov rdi,r12
/* Removing the executable bit must be refused by F_SEAL_EXEC.
 * Merely adding the owner-write mode bit (0500 -> 0700) is permitted;
 * F_SEAL_WRITE independently prevents changing the actual contents. */
mov esi,384
mov eax,91
syscall
cmp rax,-1
jne bad
mov edi,43
jmp done
bad: mov edi,99
done: mov eax,60
syscall
exe: .asciz "/proc/self/exe"''')
        self.install(image)
        self.assertEqual((self.launch().returncode),43)

    def test_inherited_sigpipe_is_preserved_across_in_place_exec(self):
        image=self.assemble_fixture('sigpipe','''sub rsp,32
mov edi,13
xor esi,esi
mov rdx,rsp
mov r10d,8
mov eax,13
syscall
test rax,rax
jnz bad
mov rdi,[rsp]
cmp rdi,1
ja bad
add edi,40
jmp done
bad: mov edi,99
done: mov eax,60
syscall''')
        self.install(image)
        self.assertEqual(self.launch(restore_signals=True).returncode,40)
        self.assertEqual(self.launch(restore_signals=False).returncode,41)

    def test_signal_cancellation_keeps_process_group_and_releases_selection_lock(self):
        import select
        image=self.assemble_fixture('pause','''push 82
mov edi,1
mov rsi,rsp
mov edx,1
mov eax,1
syscall
mov eax,34
syscall
ud2''')
        self.install(image)
        def cancel(child):
            self.assertTrue(select.select([child.stdout],[],[],5)[0],'target did not start')
            observed=child.stdout.read(1);self.assertEqual(observed,b'R')
            self.assertEqual(os.getpgid(child.pid),child.pid)
            with (self.releases/'.hia-selection.lock').open('rb') as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            os.killpg(child.pid,signal.SIGTERM)
            return observed
        p=self.launch(after_start=cancel)
        self.assertEqual((p.returncode,p.stdout),(-15,b'R'))
        self.assertFalse(Path(f'/proc/{p.observed_pid}').exists())

    def test_hardlinked_entry_and_replaced_selection_during_actual_read_refuse(self):
        from tests.test_hia_release_selection import state
        self.install(extras=(('slow',0o400,b'read-boundary\0'*(600000)),))
        entry=self.releases/self.digest/self.entry
        peer=self.case/'hardlinked';os.link(entry,peer)
        self.assertEqual(self.launch().returncode,10);peer.unlink()
        path=self.releases/'.hia-selection.current';original=path.read_bytes()
        expected=str(self.releases/self.digest/'slow')
        for replacement in (False,True):
            with self.subTest(replacement=replacement):
                def replace(child):
                    end=time.monotonic()+15;observed=False
                    while time.monotonic()<end:
                        self.assertIsNone(child.poll(),'execution passed the requested observation boundary')
                        try:
                            names=[os.readlink(p) for p in Path(f'/proc/{child.pid}/fd').iterdir()]
                        except FileNotFoundError:continue
                        if expected in names:observed=True;break
                        time.sleep(.001)
                    self.assertTrue(observed,'actual payload descriptor was not observed')
                    child.send_signal(signal.SIGSTOP)
                    _,status=os.waitpid(child.pid,os.WUNTRACED)
                    self.assertTrue(os.WIFSTOPPED(status))
                    self.assertIn(expected,[os.readlink(p) for p in Path(f'/proc/{child.pid}/fd').iterdir()])
                    if replacement:
                        new=self.releases/'replacement';new.write_bytes(original);new.chmod(0o400);new.replace(path)
                    else:
                        path.chmod(0o600);path.write_bytes(state(2,self.digest,'1'*64));path.chmod(0o400)
                    child.send_signal(signal.SIGCONT)
                try:
                    p=self.launch(after_start=replace)
                    self.assertEqual((p.returncode,p.stdout),(12,b''))
                finally:
                    path.chmod(0o600);path.write_bytes(original);path.chmod(0o400)

    def test_changed_installed_permissions_bytes_and_symlink_refuse(self):
        self.install();target=self.releases/self.digest/self.entry
        target.chmod(0o700)
        self.assertEqual(self.launch().returncode,10)
        target.write_bytes(b'x'*len(self.image));target.chmod(0o500)
        self.assertEqual(self.launch().returncode,11)
        directory=target.parent;directory.chmod(0o700);target.unlink();target.symlink_to(self.package_path)
        self.assertEqual(self.launch().returncode,10)

    def test_native_signal_termination_is_not_relabelled_a_launcher_success(self):
        image=self.assemble_fixture('signal', '''mov eax,39
syscall
mov rdi,rax
mov esi,15
mov eax,62
syscall
ud2''')
        self.install(image)
        p=self.launch();self.assertEqual((p.returncode,p.stdout),(-signal.SIGTERM,b''))

    def test_actual_trace_seals_readback_single_exec_and_descriptor_cleanup(self):
        self.assertIsNotNone(shutil.which('strace'),'strace is required, not skipped')
        self.install();trace=self.case/'trace'
        p=self.launch(prefix=[shutil.which('strace'),'-qq','-f','-o',str(trace),'-e','trace=process,desc,memory,signal,close_range'])
        self.assertEqual(p.returncode,37)
        text=trace.read_text()
        self.assertIn('execveat(',text);self.assertIn('AT_EMPTY_PATH',text)
        self.assertIn('F_ADD_SEALS',text);self.assertIn('F_GET_SEALS',text)
        self.assertIn('CLOSE_RANGE_CLOEXEC',text)
        self.assertNotIn('clone(',text);self.assertNotIn('clone3(',text);self.assertNotIn('fork(',text)
        self.assertNotIn('rt_sigaction(SIGPIPE',text)
        self.assertEqual(text.count('execveat('),1)

    def test_missing_package_descriptor_and_wrong_arity_never_execute(self):
        self.install()
        args=[str(self.applications['hia-run-selected']),str(self.releases),'1',self.digest,
              self.entry,sha256(self.image).hexdigest(),'run']
        p=subprocess.run(args,capture_output=True,timeout=30,close_fds=True,env={'PATH':''})
        self.record('missing-fd3',p);self.assertEqual((p.returncode,p.stdout),(15,b''))
        p=self.tool('hia-run-selected',[]);self.assertEqual((p.returncode,p.stdout),(64,b''))


class ReleaseLaunchSyscallFaultTests(unittest.TestCase):
    # These controls require an actual ptrace-capable environment. They remain
    # required, not skipped or replaced by an expected-error assertion.
    setUpClass=classmethod(ReleaseLaunchKernelTests.setUpClass.__func__)
    tearDownClass=classmethod(ReleaseLaunchKernelTests.tearDownClass.__func__)
    setUp=ReleaseLaunchKernelTests.setUp
    tool=ReleaseLaunchKernelTests.tool
    record=ReleaseLaunchKernelTests.record
    install=ReleaseLaunchKernelTests.install
    launch=ReleaseLaunchKernelTests.launch

    def trace(self,injection):
        exe=shutil.which('strace');self.assertIsNotNone(exe)
        path=self.case/f'trace-{len(self.observations)}'
        return [exe,'-qq','-o',str(path),'-e','trace=all','-e','inject='+injection],path

    def test_actual_eintr_preserves_capture_memfd_write_and_seal_operations(self):
        self.install()
        for syscall in ('read','memfd_create','write','fcntl','flock'):
            with self.subTest(syscall=syscall):
                prefix,trace=self.trace(syscall+':error=EINTR:when=1')
                p=self.launch(prefix=prefix)
                self.assertEqual((p.returncode,p.stdout),(37,b''))
                self.assertIn('INJECTED',trace.read_text())

    def test_false_short_write_and_incomplete_seal_readback_cannot_execute(self):
        self.install()
        for injection,expected in (('write:retval=1:when=1',11),('fcntl:retval=15:when=2',11)):
            with self.subTest(injection=injection):
                prefix,trace=self.trace(injection);p=self.launch(prefix=prefix)
                self.assertEqual((p.returncode,p.stdout),(expected,b''))
                text=trace.read_text();self.assertIn('INJECTED',text);self.assertNotIn('execveat(',text)

    def test_memfd_seal_and_descriptor_cleanup_feature_refusals_have_no_fallback(self):
        self.install()
        for injection in ('memfd_create:error=EINVAL:when=1','fcntl:error=EIO:when=1',
                          'close_range:error=ENOSYS:when=1'):
            with self.subTest(injection=injection):
                prefix,trace=self.trace(injection);p=self.launch(prefix=prefix)
                self.assertEqual((p.returncode,p.stdout),(15,b''))
                text=trace.read_text();self.assertIn('INJECTED',text);self.assertNotIn('execveat(',text)

    def test_exec_refusal_returns_once_without_retry_or_path_execution(self):
        self.install()
        prefix,trace=self.trace('execveat:error=EACCES:when=1');p=self.launch(prefix=prefix)
        self.assertEqual((p.returncode,p.stdout),(22,b''))
        text=trace.read_text();self.assertIn('INJECTED',text);self.assertEqual(text.count('execveat('),1)
        self.assertEqual(text.count('execve('),1)
        self.assertNotIn('clone(',text);self.assertNotIn('fork(',text)


class ReleaseLaunchInstalledAgentTests(unittest.TestCase):
    setUpClass=classmethod(ReleaseLaunchKernelTests.setUpClass.__func__)
    tearDownClass=classmethod(ReleaseLaunchKernelTests.tearDownClass.__func__)
    setUp=ReleaseLaunchKernelTests.setUp
    tool=ReleaseLaunchKernelTests.tool
    record=ReleaseLaunchKernelTests.record
    install=ReleaseLaunchKernelTests.install
    launch=ReleaseLaunchKernelTests.launch

    def test_actual_hia_stdio_capabilities_verify_compile_and_assembly_through_selected_release(self):
        from tests.test_hia_agent_stdio import EXPECTED_VERIFIED,cap_bytes
        from tools.qualify_hia_release_launch import selected_cold_fixture,load_cold_agent,AGENT_STATUS
        if selected_cold_fixture() is None:
            selected=os.environ.get('HEPTA_HIA_RELEASE_LAUNCH_DEVELOPMENT_AGENT')
            self.assertIsNotNone(selected,'explicit actual HIA development payload required')
            path=Path(selected);record_raw=path.read_bytes();data=json.loads(record_raw)
            self.assertEqual(data['status'],'DEVELOPMENT_HIA_AGENT_PAYLOAD')
            self.assertIs(data['matching_cold'],False)
        else:
            path,record_raw,data=load_cold_agent()
            self.assertEqual(data['status'],AGENT_STATUS)
            self.assertIs(data['matching_cold'],True)
        image=Path(data['path']).read_bytes();self.assertEqual(sha256(image).hexdigest(),data['sha256'])
        sample=Path(data['sample_image']).read_bytes()
        self.assertEqual(sha256(sample).hexdigest(),data['sample_image_sha256'])
        for name,digest in data['source_sha256'].items():
            self.assertEqual(sha256((ROOT/'examples/hia_bootstrap'/f'{name}.hepta').read_bytes()).hexdigest(),digest)
        assembly=(ROOT/'examples/hia_bootstrap/bytesum.hepta').read_bytes()
        program=assemble_program(assembly).as_dict()
        wire=json.dumps(program,separators=(',',':')).encode()
        self.install(image,entry='hia-native')
        for argument,payload,expected in (
            ('capabilities',b'not JSON',cap_bytes()),('verify',wire,EXPECTED_VERIFIED),
            ('compile',wire,sample),('render-assembly',wire,render_assembly(program).encode()),
            ('assemble',assembly,sample),('check-assembly',assembly,EXPECTED_VERIFIED)):
            with self.subTest(argument=argument):
                p=self.launch(argument=argument,payload=payload)
                self.assertEqual((p.returncode,p.stdout,p.stderr),(0,expected,b''))
        self.assertEqual(path.read_bytes(),record_raw)


if __name__=='__main__':
    unittest.main()
