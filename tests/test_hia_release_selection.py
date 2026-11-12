"""Independent HIA VM, native CAS/rollback and actual crash/durability controls."""
from __future__ import annotations
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import execute_program, verify_core
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_selection import (MAGIC, STATE_MAGIC, policy_source,
    packer_source, template, adapter_source)
from tools.hia_selfhost_bulk import Body
from tests import test_hia_release_install as install_controls

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT/'examples/hia_bootstrap/release_selection_policy.hiaasm'
PACKER = ROOT/'examples/hia_bootstrap/release_selection_packer.hiaasm'
CURRENT = '.hia-selection.current'
LOCK = '.hia-selection.lock'


def state(sequence, current, previous=None, action=1):
    raw = struct.pack('<4Q', STATE_MAGIC, sequence, action, 0)
    raw += current.encode('ascii') + (previous.encode('ascii') if previous else bytes(64))
    assert len(raw) == 160
    return raw + sha256(raw).digest()


def unpack_state(raw):
    if len(raw) != 192 or sha256(raw[:160]).digest() != raw[160:]:
        raise ValueError('extent or checksum')
    magic, sequence, action, reserved = struct.unpack('<4Q', raw[:32])
    if magic != STATE_MAGIC or reserved or not 1 <= sequence <= (1 << 64) - 1:
        raise ValueError('header')
    current = raw[32:96].decode('ascii')
    previous = None if raw[96:160] == bytes(64) else raw[96:160].decode('ascii')
    if not re.fullmatch('[0-9a-f]{64}', current):
        raise ValueError('current')
    if sequence == 1:
        if action != 1 or previous is not None:
            raise ValueError('initial state')
    elif action not in (1, 2) or previous is None or not re.fullmatch('[0-9a-f]{64}', previous):
        raise ValueError('successor state')
    if previous == current:
        raise ValueError('no-op')
    return sequence, current, previous, action


def packet(*args):
    values = [a.encode() if isinstance(a, str) else a for a in args]
    values += [b''] * (5 - len(values))
    assert len(values) == 5
    return struct.pack('<5Q', *map(len, values)) + b''.join(values)


def fields(**values):
    return install_controls.fields(**values)


def observe(wire, workspace, **kwargs):
    # This reuses only the independent VM's byte-buffer plumbing. The program
    # executed is the new checked-in HIA policy, never a Python state algorithm.
    with patch.object(install_controls, 'POLICY', POLICY):
        return install_controls.observe(wire, workspace, **kwargs)


def vm_pack():
    images = (b'\xc3', b'\x90\xc3', b'\x90\x90\xc3')
    frame = struct.pack('<4Q', MAGIC, *map(len, images)) + b''.join(images)
    prefix, holes = template()
    expected = bytearray(prefix + b''.join(images))
    struct.pack_into('<Q', expected, 96, len(expected))
    struct.pack_into('<Q', expected, 104, len(expected))
    for name, offset in holes.items():
        addition = len(images[0]) if name in ('sha_hole', 'selection_hole') else 0
        addition += len(images[1]) if name == 'selection_hole' else 0
        struct.pack_into('<I', expected, offset, len(prefix) + addition - offset - 4)
    b = Body(0)
    owners, views = [], []
    for data, size in ((frame,len(frame)),(b'',len(expected)),(b'',1),(expected,len(expected))):
        owner = b.value('buffer','buffer.new',[b.const('usize',size)])
        owners.append(owner)
        view = b.value('mutbuf','borrow.mut',[owner])
        for at, value in enumerate(data):
            if value:
                b.effect('buffer.store',[view,b.const('usize',at),b.const('u8',value)])
        if len(views) in (0,3):
            b.effect('loan.end',[view])
            view = b.value('readbuf','borrow.read',[owner])
        views.append(view)
    size = b.value('u32','call',views[:3],{'function':'f0'})
    mismatch = b.value('u8','call',[views[1],views[3]],{'function':'compare_all'})
    for view in views:
        b.effect('loan.end',[view])
    for owner in owners:
        b.effect('owner.drop',[owner])
    reference = '''def compare(o:mutbuf, s:readbuf) -> u8:
    i = 0
    difference = 0
    while i < length(s):
        difference = difference | (byte(o, i) ^ byte(s, i))
        i = i + 1
    return difference
'''
    reference = render_assembly(document(reference,'comparison')).split('\n',1)[1].replace('fn f0(','fn compare_all(')
    source = ('hia-asm.v1 hepta.hia.program.v8 selection_packer_reference\n'
        'fn observe() -> (u32,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        + b.text() + '  ret(' + size + ',' + mismatch + ')\nend\n'
        + reference + PACKER.read_text().split('\n',1)[1])
    actual = execute_program(assemble_program(source),'observe',[],max_steps=6000000)
    assert actual['status'] == 'returned' and actual['values'] == [len(expected),0], actual


class ReleaseSelectionSourceTests(unittest.TestCase):
    def test_sources_and_real_verifier_reuse(self):
        for path, source, name in [(POLICY,policy_source(),'release_selection_policy'),
                                  (PACKER,packer_source(),'release_selection_packer')]:
            doc = document(source,name)
            verify_core(doc)
            self.assertEqual(path.read_text(),render_assembly(doc))
        installer = (ROOT/'tools/hia_release_install_syscalls.S').read_text()
        actual = adapter_source()
        exact = installer[installer.index('/* Capture every named file'):installer.index('success:\n')]
        self.assertIn(exact,actual)
        self.assertNotIn('materialize_next:',actual)
        self.assertNotIn('mkdir_retry:',actual)
        self.assertIn('mov eax,73',actual)

    def test_vm_arguments_canonical_sequence_and_native_verify_packet(self):
        root, target = b'/private/releases', b'a1'*32
        wire = packet('activate',root,'0','-',target)
        expected = struct.pack('<3Q',6,len(root),64) + b'verify' + root + target
        code, actual = observe(wire,fields(p0=0),offsets=range(len(expected)))
        self.assertEqual((code,actual),(len(expected),expected))
        code, actual = observe(packet('status',root),fields(p0=0),offsets=range(len(expected)))
        self.assertEqual((code,actual),(len(expected),expected[:-64]+b'0'*64))
        for sequence in ('00','01','-1','+1','1x','18446744073709551616'):
            self.assertEqual(observe(packet('activate',root,sequence,'a'*64,target),fields(p0=0))[0],16)
        for changed in (packet('activate',root,'0','a'*64,target),
                        packet('activate',root,'1','-',target),
                        packet('status',root,'0','-',target),
                        packet('activate',root,'0','-',b'A'*64)):
            self.assertEqual(observe(changed,fields(p0=0))[0],16)
        self.assertGreater(observe(packet('activate',root,str((1<<64)-1),'b'*64,target),fields(p0=0))[0],64)

    def test_vm_exact_state_cas_rollback_checksum_and_exhaustion(self):
        a,b,c = 'a'*64,'b'*64,'c'*64
        w=fields(p0=4,p8=1,p16=0,p24=0)
        w[192:256]=a.encode()
        code,raw=observe(b'x',w,workspace_offsets=range(448,608))
        self.assertEqual((code,raw),(0,state(1,a)[:160]))
        old=state(2,b,a)
        for op,target,expected in ((1,c,0),(2,a,0),(2,c,20),(1,b,19)):
            w=fields(p0=4,p8=op,p16=2,p24=2)
            w[128:192]=b.encode(); w[192:256]=target.encode(); w[256:448]=old
            self.assertEqual(observe(b'x',w)[0],expected)
        w=fields(p0=4,p8=1,p16=1,p24=2)
        w[128:192]=b.encode();w[192:256]=c.encode();w[256:448]=old
        self.assertEqual(observe(b'x',w)[0],19)
        w=fields(p0=4,p8=1,p16=(1<<64)-1,p24=(1<<64)-1)
        w[128:192]=b.encode();w[192:256]=c.encode();w[256:448]=state((1<<64)-1,b,a)
        self.assertEqual(observe(b'x',w)[0],21)
        w=fields(p0=2,p32=1,p72=192);w[256:448]=old
        self.assertEqual(observe(b'x',w)[0],0)
        for at in (256,280,288,352):
            changed=bytearray(w);changed[at]=255
            self.assertEqual(observe(b'x',changed)[0],11)
        for size in (0,191,193):
            changed=bytearray(w);struct.pack_into('<Q',changed,72,size)
            self.assertEqual(observe(b'x',changed)[0],11)
        struct.pack_into('<Q',w,0,3)
        self.assertEqual(observe(sha256(old[:160]).digest(),w)[0],0)
        self.assertEqual(observe(bytes(32),w)[0],11)

    def test_vm_receipt_and_staged_name(self):
        for op,operation,sequence,current,previous in [(3,'status',0,None,None),
                (1,'activate',1,'a'*64,None),(2,'rollback',(1<<64)-1,'b'*64,'a'*64),
                (4,'verify',2,'b'*64,'a'*64)]:
            w=fields(p0=14,p8=op,p24=sequence)
            if current:w[288:352]=current.encode()
            if previous:w[352:416]=previous.encode()
            expected=(json.dumps({'schema':'hepta.hia.release-selection.v1','operation':operation,
                'sequence':sequence,'current':current,'previous':previous,'release_verified':op!=3},separators=(',',':'))+'\n').encode()
            pieces=[]
            for start in range(0,len(expected),128):
                code,raw=observe(b'x',w,offsets=range(start,min(start+128,len(expected))))
                self.assertEqual(code,len(expected))
                pieces.append(raw)
            self.assertEqual(b''.join(pieces),expected)
        w=fields(p0=10);w[704:720]=bytes(range(16))
        expected=b'.hia-selection-stage-'+bytes(range(16)).hex().encode()+b'\0'
        self.assertEqual(observe(b'x',w,workspace_offsets=range(640,640+len(expected)))[1],expected)

    def test_vm_selected_release_verify_identity_and_full_snapshot(self):
        root,digest='/private/releases','a'*64
        expected=struct.pack('<3Q',6,len(root),64)+b'verify'+root.encode()+digest.encode()
        self.assertEqual(observe(packet('verify',root,'1',digest),fields(p0=0),
            offsets=range(len(expected))),(len(expected),expected))
        for args in [('verify',root,'0',digest),('verify',root,'01',digest),
                     ('verify',root,'1','A'*64),('verify',root,'1',digest,digest)]:
            self.assertEqual(observe(packet(*args),fields(p0=0))[0],16)
        w=fields(p0=18,p8=4,p16=2,p24=2,p32=1)
        w[128:192]=digest.encode();w[256:448]=state(2,digest,'b'*64)
        self.assertEqual(observe(b'',w)[0],0)
        for at,value in ((8,1),(16,1),(32,0)):
            changed=bytearray(w);struct.pack_into('<Q',changed,at,value)
            self.assertEqual(observe(b'',changed)[0],16 if at==8 else 19)
        changed=bytearray(w);changed[128]=ord('b')
        self.assertEqual(observe(b'',changed)[0],19)
        w=fields(p0=20)
        raw=state(2,digest,'b'*64)
        w[256:448]=raw;w[1408:1600]=raw
        self.assertEqual(observe(b'',w)[0],0)
        for at in (256,352,416,768,776,784,792,816,856,864,872,880):
            changed=bytearray(w);changed[at]^=1
            self.assertEqual(observe(b'',changed)[0],12,at)

    def test_independent_vm_packer_all_bytes(self):
        vm_pack()

    def test_builder_refuses_unqualified_source_before_output(self):
        from tools.build_hia_release_selection import build
        with tempfile.TemporaryDirectory(prefix='hia-selection-refusal-') as folder:
            base=Path(folder)
            (base/'compiler').write_bytes(b'not executed');(base/'cold').write_text('{}')
            with self.assertRaisesRegex(ValueError,'cold qualification'):
                build(base/'absent',base/'compiler',base/'cold')
            self.assertFalse((base/'absent').exists())


class ReleaseSelectionKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed,compile_stage,invoke
        cls.temporary=None
        observations=os.environ.get('HEPTA_HIA_RELEASE_SELECTION_OBSERVATIONS')
        if observations:
            observation_root=Path(observations)
            observation_root.mkdir(mode=0o700,exist_ok=True)
            # Preserve independent class receipts in a shared CI artifact root.
            # An existing class directory still refuses reuse or overwriting.
            cls.folder=observation_root/cls.__name__
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary=tempfile.TemporaryDirectory(prefix='hia-selection-kernel-')
            cls.folder=Path(cls.temporary.name)
        cold_path=os.environ.get('HEPTA_HIA_RELEASE_SELECTION_COLD_REPORT')
        if cold_path:
            from tools.build_hia_release_selection import build
            from tools.build_hia_release_install import build as build_install
            outer=json.loads(Path(cold_path).read_bytes())
            inner=json.loads(Path(outer['nested_report']).read_bytes())
            compiler=Path(inner['generations'][-1]['produced_image'])
            cls.app=build(cls.folder/'selection',compiler,Path(cold_path))
            cls.installer=build_install(cls.folder/'installer',compiler,Path(cold_path))
        else:
            assert observe(packet('status','/tmp'),fields(p0=0))[0] == 98
            vm_pack()
            seed,_=build_seed(cls.folder)
            first,_=compile_stage(cls.folder,'B1',seed,(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes(),image_format='seed-shared')
            second,_=compile_stage(cls.folder,'B2',first,(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes())
            assert first.read_bytes()==second.read_bytes()
            images={}
            for name in ('release_install_policy','release_install_packer','sha256_stream',
                         'release_selection_policy','release_selection_packer'):
                images[name],_=compile_stage(cls.folder,name,second,(ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm').read_bytes())
            from tools.generate_hia_release_install import MAGIC as INSTALL_MAGIC
            for label,names,packer,magic in [
                    ('hia-release',('release_install_policy','sha256_stream'),'release_install_packer',INSTALL_MAGIC),
                    ('hia-select',('release_install_policy','sha256_stream','release_selection_policy'),'release_selection_packer',MAGIC)]:
                payloads=[images[name].read_bytes() for name in names]
                frame=struct.pack('<'+'Q'*(1+len(payloads)),magic,*map(len,payloads))+b''.join(payloads)
                result,raw=invoke(cls.folder,'pack-'+label,images[packer],frame)
                assert result['status']=='returned' and 0<result['core_u32']<=len(raw),result
                path=cls.folder/label;path.write_bytes(raw[:result['core_u32']]);path.chmod(0o700)
            cls.app,cls.installer=cls.folder/'hia-select',cls.folder/'hia-release'
        cls.observations=[];cls.serial=0

    @classmethod
    def tearDownClass(cls):
        (cls.folder/'observations.json').write_text(json.dumps({
            'schema':'hepta.hia.release-selection-observations.v1',
            'executable_sha256':sha256(cls.app.read_bytes()).hexdigest(),
            'installer_sha256':sha256(cls.installer.read_bytes()).hexdigest(),
            'matching_cold_report':os.environ.get('HEPTA_HIA_RELEASE_SELECTION_COLD_REPORT'),
            'observations':cls.observations,'whole_native_delivery_qualified':False},indent=2,sort_keys=True)+'\n')
        if cls.temporary:
            for path,dirs,_ in os.walk(cls.folder,topdown=True,followlinks=False):
                os.chmod(path,os.stat(path).st_mode|0o700)
                for name in dirs:
                    child=Path(path)/name
                    if not child.is_symlink():child.chmod(child.stat().st_mode|0o700)
            cls.temporary.cleanup()

    def setUp(self):
        type(self).serial+=1
        self.case=self.folder/f'case-{self.serial}';self.case.mkdir(mode=0o700)
        self.root=self.case/'releases';self.root.mkdir(mode=0o700)
        self.wires=[install_controls.bundle([('app',0o500,b'actual release '+bytes([i]))]) for i in range(3)]
        self.ids=[sha256(raw).hexdigest() for raw in self.wires]
        for wire,digest in zip(self.wires,self.ids):
            p=subprocess.run([str(self.installer),'install',str(self.root),digest],input=wire,capture_output=True,env={'PATH':''},timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)

    def run_app(self,operation='status',sequence=None,current=None,target=0,*,code=0,prefix=(),root=None,wire=None):
        args=[str(self.app),operation,str(root or self.root)]
        data=b''
        if sequence is not None:
            args += [str(sequence),current or '-']
            if operation != 'verify':
                args.append(self.ids[target])
            data=self.wires[target] if wire is None else wire
        p=subprocess.run([*prefix,*args],input=data,capture_output=True,env={'PATH':''},timeout=30)
        self.observations.append({'case':self.id(),'operation':operation,'returncode':p.returncode,
            'stdout':p.stdout.decode('ascii',errors='backslashreplace'),'stderr_sha256':sha256(p.stderr).hexdigest()})
        self.assertEqual(p.returncode,code,(p.stdout,p.stderr))
        if code:self.assertEqual(p.stdout,b'')
        return p

    def selected(self):
        return json.loads(self.run_app().stdout)

    def test_real_activation_status_rollback_and_immutable_releases(self):
        before={p.name:(p.stat().st_ino,(p/'app').read_bytes()) for p in self.root.iterdir()}
        empty=self.selected()
        self.assertEqual((empty['sequence'],empty['current'],empty['previous']),(0,None,None))
        self.assertFalse((self.root/LOCK).exists())
        first=json.loads(self.run_app('activate',0,None,0).stdout)
        self.assertEqual((first['sequence'],first['current'],first['previous'],first['release_verified']),(1,self.ids[0],None,True))
        self.run_app('activate',1,self.ids[0],1)
        self.assertEqual(unpack_state((self.root/CURRENT).read_bytes()),(2,self.ids[1],self.ids[0],1))
        self.run_app('rollback',2,self.ids[1],2,code=20)
        self.run_app('rollback',2,self.ids[1],0)
        self.assertEqual(unpack_state((self.root/CURRENT).read_bytes()),(3,self.ids[0],self.ids[1],2))
        status=self.selected()
        self.assertEqual((status['sequence'],status['current'],status['release_verified']),(3,self.ids[0],False))
        self.assertEqual((self.root/CURRENT).stat().st_mode&0o7777,0o400)
        self.assertEqual((self.root/LOCK).stat().st_mode&0o7777,0o600)
        after={name:((self.root/name).stat().st_ino,(self.root/name/'app').read_bytes()) for name in before}
        self.assertEqual(after,before)

    def test_real_cas_replay_conflicts_and_rollbacks_require_previous(self):
        self.run_app('rollback',0,None,0,code=20)
        self.run_app('activate',0,None,0)
        original=(self.root/CURRENT).read_bytes()
        for args in [('activate',0,None,1),('activate',1,self.ids[1],1),('activate',1,self.ids[0],0)]:
            self.run_app(*args,code=19)
            self.assertEqual((self.root/CURRENT).read_bytes(),original)
        self.run_app('rollback',1,self.ids[0],1,code=20)

    def test_selected_release_verify_is_coherent_readonly_and_requires_exact_identity(self):
        self.run_app('verify',1,self.ids[0],code=19)
        self.assertFalse((self.root/LOCK).exists())
        self.run_app('activate',0,None,0)
        before={str(p.relative_to(self.root)):(p.stat().st_ino,p.stat().st_mode,p.stat().st_size,
            p.stat().st_mtime_ns,p.read_bytes() if p.is_file() else None)
            for p in self.root.rglob('*')}
        verified=json.loads(self.run_app('verify',1,self.ids[0]).stdout)
        self.assertEqual(verified,{'schema':'hepta.hia.release-selection.v1','operation':'verify',
            'sequence':1,'current':self.ids[0],'previous':None,'release_verified':True})
        with (self.root/LOCK).open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_SH|fcntl.LOCK_NB)
            self.run_app('verify',1,self.ids[0])
            self.run_app('activate',1,self.ids[0],1,code=18)
        self.run_app('verify',2,self.ids[0],code=19)
        self.run_app('verify',1,self.ids[1],1,code=19)
        self.run_app('verify',1,self.ids[0],wire=self.wires[1],code=11)
        after={str(p.relative_to(self.root)):(p.stat().st_ino,p.stat().st_mode,p.stat().st_size,
            p.stat().st_mtime_ns,p.read_bytes() if p.is_file() else None)
            for p in self.root.rglob('*')}
        self.assertEqual(after,before)
        self.assertFalse(any(p.name.startswith('.hia-selection-stage-') for p in self.root.iterdir()))
        app=self.root/self.ids[0]/'app'
        app.chmod(0o700);app.write_bytes(b'changed installed executable');app.chmod(0o500)
        self.run_app('verify',1,self.ids[0],code=11)
        self.assertEqual((self.root/CURRENT).read_bytes(),before[CURRENT][-1])

    def test_selected_verify_rechecks_actual_state_after_mid_read_replacement(self):
        # The advisory lock cannot stop a noncooperating same-UID writer. This
        # control changes an actual state after the original read and requires
        # readback refusal; it grants no protection after the observation ends.
        wire=install_controls.bundle([('app',0o500,b'bounded-readback-control\0'*(400000))])
        digest=sha256(wire).hexdigest()
        installed=subprocess.run([str(self.installer),'install',str(self.root),digest],
            input=wire,capture_output=True,env={'PATH':''},timeout=30)
        self.assertEqual(installed.returncode,0,installed.stderr)
        self.run_app('activate',0,None,0)
        activated=subprocess.run([str(self.app),'activate',str(self.root),'1',self.ids[0],digest],
            input=wire,capture_output=True,env={'PATH':''},timeout=30)
        self.assertEqual(activated.returncode,0,activated.stderr)
        selected_path=self.root/CURRENT
        original=selected_path.read_bytes()
        for replace_inode in (False,True):
            child=subprocess.Popen([str(self.app),'verify',str(self.root),'2',digest],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''})
            try:
                child.stdin.write(wire);child.stdin.close();child.stdin=None
                expected=str(self.root/digest/'app')
                deadline=time.monotonic()+15
                observed=False
                while time.monotonic()<deadline:
                    self.assertIsNone(child.poll(),'verifier ended before actual file-read boundary')
                    for descriptor in Path(f'/proc/{child.pid}/fd').iterdir():
                        try:
                            if os.readlink(descriptor)==expected:
                                observed=True
                                break
                        except FileNotFoundError:
                            pass
                    if observed:
                        break
                    time.sleep(0.001)
                self.assertTrue(observed,'actual installed payload descriptor was not observed')
                child.send_signal(signal.SIGSTOP)
                _,stopped=os.waitpid(child.pid,os.WUNTRACED)
                self.assertTrue(os.WIFSTOPPED(stopped),'verifier must be alive at the actual read boundary')
                if replace_inode:
                    replacement=self.root/'independent-replacement'
                    replacement.write_bytes(original);replacement.chmod(0o400)
                    replacement.replace(selected_path)
                else:
                    # A valid same-sequence/current record with a different
                    # previous release must also fail the complete snapshot.
                    selected_path.chmod(0o600)
                    selected_path.write_bytes(state(2,digest,self.ids[1]))
                    selected_path.chmod(0o400)
                child.send_signal(signal.SIGCONT)
                output,error=child.communicate(timeout=30)
                self.assertEqual((child.returncode,output),(12,b''),error)
                self.observations.append({'case':self.id(),'selection_inode_replaced':replace_inode,
                    'actual_installed_payload_descriptor_observed':True,'returncode':child.returncode})
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)
                selected_path.chmod(0o600);selected_path.write_bytes(original);selected_path.chmod(0o400)

    def test_actual_lock_contention_and_two_process_compare_and_swap(self):
        self.run_app('activate',0,None,0)
        with (self.root/LOCK).open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.run_app(code=18)
            self.run_app('activate',1,self.ids[0],1,code=18)
        commands=[[str(self.app),'activate',str(self.root),'1',self.ids[0],self.ids[i]] for i in (1,2)]
        children=[subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''}) for args in commands]
        outcomes=[child.communicate(self.wires[i],timeout=30) for child,i in zip(children,(1,2))]
        codes=[child.returncode for child in children]
        self.assertEqual(codes.count(0),1,(codes,outcomes))
        self.assertTrue(all(code in (0,18,19) for code in codes),codes)
        self.assertEqual(self.selected()['sequence'],2)
        self.observations.append({'case':self.id(),'concurrent_returncodes':codes})

    def test_corrupt_truncated_extra_state_and_exhaustion_refuse(self):
        self.run_app('activate',0,None,0)
        path=self.root/CURRENT;good=path.read_bytes()
        for raw in (good[:-1],good+b'x',bytes(192),good[:160]+bytes(32)):
            path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400)
            self.run_app(code=10 if len(raw)!=192 else 11)
            self.run_app('activate',1,self.ids[0],1,code=10 if len(raw)!=192 else 11)
            self.assertEqual(path.read_bytes(),raw)
        exhausted=state((1<<64)-1,self.ids[0],self.ids[1])
        path.chmod(0o600);path.write_bytes(exhausted);path.chmod(0o400)
        self.run_app('activate',(1<<64)-1,self.ids[0],2,code=21)
        self.assertEqual(path.read_bytes(),exhausted)

    def test_symlink_hardlink_mode_and_real_installed_corruption_refuse(self):
        self.run_app('activate',0,None,0)
        path=self.root/CURRENT
        path.chmod(0o600);self.run_app(code=10);path.chmod(0o400)
        peer=self.case/'state-link';os.link(path,peer);self.run_app(code=10);peer.unlink()
        saved=path.read_bytes();path.unlink();path.symlink_to(self.case/'missing')
        self.run_app(code=10);path.unlink();path.write_bytes(saved);path.chmod(0o400)
        app=self.root/self.ids[1]/'app';app.chmod(0o700);app.write_bytes(b'wrong bytes');app.chmod(0o500)
        self.run_app('activate',1,self.ids[0],1,code=11)
        self.assertEqual(path.read_bytes(),saved)
        alias=self.case/'alias';alias.symlink_to(self.root,target_is_directory=True)
        self.run_app(root=alias,code=10)
        self.root.chmod(0o777);self.run_app(code=10);self.root.chmod(0o700)

    def test_invalid_request_and_digest_never_change_selection(self):
        before=sorted(p.name for p in self.root.iterdir())
        self.run_app('activate',0,None,0,wire=self.wires[1],code=11)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),before)
        p=subprocess.run([str(self.app),'activate',str(self.root),'00','-',self.ids[0]],input=self.wires[0],capture_output=True,env={'PATH':''})
        self.assertEqual((p.returncode,p.stdout),(16,b''))
        self.assertFalse((self.root/CURRENT).exists())
        p=subprocess.run([str(self.app),'status',str(self.root),'','',''],capture_output=True,env={'PATH':''})
        self.assertEqual((p.returncode,p.stdout),(64,b''))


class ReleaseSelectionFaultTests(unittest.TestCase):
    setUpClass = classmethod(ReleaseSelectionKernelTests.setUpClass.__func__)
    tearDownClass = classmethod(ReleaseSelectionKernelTests.tearDownClass.__func__)
    setUp = ReleaseSelectionKernelTests.setUp
    run_app = ReleaseSelectionKernelTests.run_app
    selected = ReleaseSelectionKernelTests.selected

    def trace(self,injection):
        executable=shutil.which('strace')
        self.assertIsNotNone(executable,'actual syscall fault controls require strace')
        trace=self.case/f'trace-{len(self.observations)}.log'
        return [executable,'-qq','-o',str(trace),'-e','trace=all','-e','inject='+injection],trace

    def test_real_fsync_failures_and_status_recovery(self):
        for when in (1,2):
            root=self.case/f'fsync-{when}';root.mkdir(mode=0o700)
            p=subprocess.run([str(self.installer),'install',str(root),self.ids[0]],input=self.wires[0],capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)
            prefix,trace=self.trace(f'fsync:error=EIO:when={when}')
            self.run_app('activate',0,None,0,root=root,prefix=prefix,code=15)
            self.assertIn('INJECTED',trace.read_text())
            status=json.loads(self.run_app(root=root).stdout)
            self.assertEqual(status['sequence'],1 if when==2 else 0)
            self.assertEqual((root/CURRENT).exists(),when==2)

    def test_actual_lost_ack_and_same_expected_retry(self):
        prefix,trace=self.trace('write:error=EIO:when=2')
        self.run_app('activate',0,None,0,prefix=prefix,code=15)
        self.assertIn('INJECTED',trace.read_text())
        self.assertEqual(self.selected()['sequence'],1)
        before=(self.root/CURRENT).stat().st_ino
        self.run_app('activate',0,None,0,code=19)
        self.assertEqual((self.root/CURRENT).stat().st_ino,before)

    def test_actual_sigkill_before_and_after_commit_is_resolved(self):
        for syscall,when,selected in [('renameat2',1,False),('write',2,True)]:
            root=self.case/f'kill-{syscall}';root.mkdir(mode=0o700)
            p=subprocess.run([str(self.installer),'install',str(root),self.ids[0]],input=self.wires[0],capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)
            prefix,trace=self.trace(f'{syscall}:signal=SIGKILL:when={when}')
            p=subprocess.run([*prefix,str(self.app),'activate',str(root),'0','-',self.ids[0]],input=self.wires[0],capture_output=True,env={'PATH':''},timeout=30)
            self.assertIn(p.returncode,(-9,137),p.stderr)
            self.assertEqual(p.stdout,b'');self.assertIn('SIGKILL',trace.read_text())
            status=json.loads(self.run_app(root=root).stdout)
            self.assertEqual(status['sequence'],1 if selected else 0)
            self.observations.append({'case':self.id(),'cut':f'{syscall}:{when}',
                'returncode':p.returncode,'observed_sequence':status['sequence'],'trace_sha256':sha256(trace.read_bytes()).hexdigest()})

    def test_eintr_retry_and_no_child_or_runtime_interpreter(self):
        prefix,trace=self.trace('flock:error=EINTR:when=1')
        self.run_app('activate',0,None,0,prefix=prefix)
        raw=trace.read_text()
        self.assertIn('INJECTED',raw)
        self.assertEqual(len(re.findall(r'^execve\(',raw,re.M)),1)
        self.assertNotRegex(raw,r'\b(?:fork|vfork|clone|clone3)\(')
        self.assertNotIn('ld.so',raw)
        self.assertLess(raw.index('flock('),raw.index('renameat2('))
        self.assertLess(raw.index('fsync('),raw.index('renameat2('))

    def test_selected_verify_has_no_mutation_syscalls_or_child_and_retries_eintr(self):
        self.run_app('activate',0,None,0)
        prefix,trace=self.trace('flock:error=EINTR:when=1')
        self.run_app('verify',1,self.ids[0],prefix=prefix)
        raw=trace.read_text()
        self.assertIn('INJECTED',raw)
        self.assertEqual(len(re.findall(r'^execve\(',raw,re.M)),1)
        self.assertNotRegex(raw,r'\b(?:fork|vfork|clone|clone3|fsync|fchmod|renameat2|unlinkat|mkdirat)\(')
        self.assertNotIn('O_CREAT',raw)
        self.assertNotIn('ld.so',raw)
        self.assertRegex(raw,r'flock\(\d+, LOCK_SH\|LOCK_NB\)')



if __name__=='__main__':
    unittest.main()
