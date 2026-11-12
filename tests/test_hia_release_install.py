"""Independent package/VM controls and real native installation/recovery effects."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import execute_program
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import BUNDLE_MAGIC, MAGIC, policy_source, packer_source, template
from tools.hia_selfhost_bulk import Body

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT/'examples/hia_bootstrap/release_install_policy.hiaasm'
PACKER = ROOT/'examples/hia_bootstrap/release_install_packer.hiaasm'


def bundle(files):
    raw = bytearray(struct.pack('<3Q', BUNDLE_MAGIC, len(files), 0))
    for name, mode, content in files:
        name = name.encode('ascii') if isinstance(name, str) else name
        raw += struct.pack('<3Q', len(name), mode, len(content)) + name + content
    return bytes(raw)


def reference_unpack(raw):
    """Independent bounded reader: ordinary strings and exact stream exhaustion."""
    import io
    stream = io.BytesIO(raw)
    header = stream.read(24)
    if len(raw) > 64 << 20 or len(header) != 24:
        raise ValueError('size')
    magic, count, reserved = struct.unpack('<3Q', header)
    if magic != BUNDLE_MAGIC or reserved or not 1 <= count <= 256:
        raise ValueError('header')
    files = {}
    for _ in range(count):
        fields = stream.read(24)
        if len(fields) != 24:
            raise ValueError('entry header')
        size, mode, extent = struct.unpack('<3Q', fields)
        if not 1 <= size <= 127 or mode not in (0o400, 0o500) or extent > len(raw):
            raise ValueError('entry limits')
        name = stream.read(size)
        if len(name) != size or re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9._-]*', name) is None or name in files:
            raise ValueError('entry name')
        payload = stream.read(extent)
        if len(payload) != extent:
            raise ValueError('entry bytes')
        files[name] = (mode, payload)
    if stream.read():
        raise ValueError('trailing')
    return files


def fields(**values):
    raw = bytearray(65536)
    for key, value in values.items():
        struct.pack_into('<Q', raw, int(key[1:]), value)
    return raw


def observe(wire, workspace, *, output_bytes=b'', output_size=8192, offsets=(), workspace_offsets=()):
    b = Body(0)
    owners, views = [], []
    for data, size in ((wire, max(1, len(wire))), (output_bytes, output_size), (workspace, 65536)):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        owners.append(owner)
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for at, value in enumerate(data):
            if value:
                b.effect('buffer.store', [view, b.const('usize', at), b.const('u8', value)])
        if not views:
            b.effect('loan.end', [view])
            view = b.value('readbuf', 'borrow.read', [owner])
        views.append(view)
    result = b.value('u32', 'call', views, {'function': 'f0'})
    values = [b.value('u8', 'buffer.load', [views[1], b.const('usize', at)]) for at in offsets]
    values += [b.value('u8', 'buffer.load', [views[2], b.const('usize', at)]) for at in workspace_offsets]
    for view in views:
        b.effect('loan.end', [view])
    for owner in owners:
        b.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 release_reference\nfn observe() -> ('+
              ','.join(['u32']+['u8']*len(values))+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+
              b.text()+'  ret('+','.join([result, *values])+')\nend\n'+POLICY.read_text().split('\n', 1)[1])
    result = execute_program(assemble_program(source), 'observe', [], max_steps=4000000)
    assert result['status'] == 'returned', result
    return result['values'][0], bytes(result['values'][1:])


def vm_pack():
    policy, sha = b'\xc3', b'\x90\xc3'
    frame = struct.pack('<3Q', MAGIC, len(policy), len(sha))+policy+sha
    prefix, holes = template()
    expected = bytearray(prefix+policy+sha)
    struct.pack_into('<Q', expected, 96, len(expected))
    struct.pack_into('<Q', expected, 104, len(expected))
    for name, at in holes.items():
        struct.pack_into('<I', expected, at, len(prefix)+(len(policy) if name == 'sha_hole' else 0)-at-4)
    b = Body(0)
    owners, views = [], []
    for data, size in ((frame, len(frame)), (b'', len(expected)), (b'', 1), (expected, len(expected))):
        owner = b.value('buffer', 'buffer.new', [b.const('usize', size)])
        owners.append(owner)
        view = b.value('mutbuf', 'borrow.mut', [owner])
        for at, value in enumerate(data):
            if value:
                b.effect('buffer.store', [view, b.const('usize', at), b.const('u8', value)])
        if len(views) in (0, 3):
            b.effect('loan.end', [view])
            view = b.value('readbuf', 'borrow.read', [owner])
        views.append(view)
    size = b.value('u32', 'call', views[:3], {'function': 'f0'})
    mismatch = b.value('u8', 'call', [views[1], views[3]], {'function': 'compare_all'})
    for view in views:
        b.effect('loan.end', [view])
    for owner in owners:
        b.effect('owner.drop', [owner])
    reference = '''def compare(o:mutbuf, s:readbuf) -> u8:
    i = 0
    difference = 0
    while i < length(s):
        difference = difference | (byte(o, i) ^ byte(s, i))
        i = i + 1
    return difference
'''
    reference = render_assembly(document(reference, 'comparison')).split('\n', 1)[1].replace('fn f0(', 'fn compare_all(')
    source = ('hia-asm.v1 hepta.hia.program.v8 packer_reference\n'
              'fn observe() -> (u32,u8) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+
              b.text()+'  ret('+size+','+mismatch+')\nend\n'+reference+PACKER.read_text().split('\n', 1)[1])
    actual = execute_program(assemble_program(source), 'observe', [], max_steps=4000000)
    assert actual['status'] == 'returned' and actual['values'] == [len(expected), 0], actual


class ReleaseInstallerSourceTests(unittest.TestCase):
    def test_policy_and_packer_sources_are_exact(self):
        self.assertEqual(POLICY.read_text(), render_assembly(document(policy_source(), 'release_install_policy')))
        self.assertEqual(PACKER.read_text(), render_assembly(document(packer_source(), 'release_install_packer')))

    def test_independent_vm_package_and_rejection(self):
        raw = bundle([('hia-native', 0o500, b'\x7fELF\x00'), ('source.hiaasm', 0o400, b'' )])
        self.assertEqual(len(reference_unpack(raw)), 2)
        result, observed = observe(raw, fields(p0=2), workspace_offsets=range(24, 32))
        self.assertEqual((result, struct.unpack('<Q', observed)[0]), (0, 2))
        for changed in (raw+b'x', raw[:-1], bundle([('../escape', 0o400, b'x')]),
                        bundle([('a', 0o400, b''), ('a', 0o500, b'x')])):
            with self.assertRaises(ValueError):
                reference_unpack(changed)
            self.assertEqual(observe(changed, fields(p0=2))[0], 16)

    def test_independent_vm_arguments_hash_stage_and_receipt(self):
        args = [b'install', b'/var/tmp/releases', b'01'*32]
        wire = struct.pack('<3Q', *map(len, args))+b''.join(args)
        expected = b'\0var\0tmp\0releases\0'
        code, raw = observe(wire, fields(p0=0), offsets=range(len(expected)))
        self.assertEqual((code, raw), (1, expected))
        w = fields(p0=1)
        w[768:832] = b'01'*32
        self.assertEqual(observe(b'\x01'*32, w)[0], 0)
        self.assertEqual(observe(b'\x02'*32, w)[0], 11)
        w = fields(p0=13)
        w[912:928] = bytes(range(16))
        expected = b'.hia-stage-'+bytes(range(16)).hex().encode()+b'\0'
        self.assertEqual(observe(b'x', w, workspace_offsets=range(848, 848+len(expected)))[1], expected)
        for op in (1, 2):
            w = fields(p0=14, p8=op, p16=(1<<64)-1, p24=256)
            w[768:832] = b'01'*32
            expected = (json.dumps({'schema':'hepta.hia.release-install.v1', 'sha256':'01'*32,
                                   'files':256, 'bytes':(1<<64)-1, 'published':op == 1}, separators=(',', ':'))+'\n').encode()
            count, actual = observe(b'x', w, offsets=range(len(expected)))
            self.assertEqual((count, actual), (len(expected), expected))

    def test_independent_vm_packer_bytes_and_elf_shape(self):
        vm_pack()

    def test_independent_vm_only_private_owned_stage_accepts_inherited_sgid(self):
        for mode, uid, expected in [(0o40700,1000,0),(0o42700,1000,0),
                                    (0o40755,1000,10),(0o40700,1001,10),(0o47700,1000,10)]:
            w = fields(p0=6,p8=1,p64=1000,p416=7,p424=9,p440=mode,p444=uid)
            self.assertEqual(observe(b'x',w)[0],expected)

    def test_builder_refuses_incomplete_cold_before_output(self):
        from tools.build_hia_release_install import build
        with tempfile.TemporaryDirectory(prefix='hia-release-refusal-') as folder:
            base = Path(folder)
            compiler, cold = base/'compiler', base/'cold'
            compiler.write_bytes(b'not executed')
            cold.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'cold qualification'):
                build(base/'must-stay-absent', compiler, cold)
            self.assertFalse((base/'must-stay-absent').exists())


class ReleaseInstallerKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke
        cls.temporary = None
        observations = os.environ.get('HEPTA_HIA_RELEASE_INSTALL_OBSERVATIONS')
        if observations:
            cls.folder = Path(observations)
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-release-kernel-')
            cls.folder = Path(cls.temporary.name)
        cold_path = os.environ.get('HEPTA_HIA_RELEASE_INSTALL_COLD_REPORT')
        if cold_path:
            from tools.build_hia_release_install import build
            outer = json.loads(Path(cold_path).read_bytes())
            inner = json.loads(Path(outer['nested_report']).read_bytes())
            cls.app = build(cls.folder/'build', Path(inner['generations'][-1]['produced_image']), Path(cold_path))
        else:
            # Real independent VM execution precedes B0. This is development
            # evidence, never a replacement for a completed matching cold run.
            assert observe(bundle([('x', 0o400, b'a')]), fields(p0=2))[0] == 0
            vm_pack()
            development_sources = {
                name: (ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm').read_bytes()
                for name in ('selfhost', 'release_install_policy', 'release_install_packer', 'sha256_stream')
            }
            seed, _ = build_seed(cls.folder)
            first, _ = compile_stage(cls.folder, 'B1', seed,
                                     development_sources['selfhost'], image_format='seed-shared')
            second, _ = compile_stage(cls.folder, 'B2', first,
                                      development_sources['selfhost'])
            assert first.read_bytes() == second.read_bytes()
            images = {}
            for name in ('release_install_policy', 'release_install_packer', 'sha256_stream'):
                images[name], _ = compile_stage(cls.folder, name, second,
                                                development_sources[name])
                if (cls.folder/(name+'.input.bin')).read_bytes() != development_sources[name]:
                    raise AssertionError('development release compiler input differs from frozen source')
            if (any((ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm').read_bytes() != raw
                    for name, raw in development_sources.items())
                    or any((cls.folder/(name+'.input.bin')).read_bytes() != development_sources['selfhost']
                           for name in ('B1', 'B2'))):
                raise AssertionError('development release source changed during compilation')
            policy, sha = images['release_install_policy'].read_bytes(), images['sha256_stream'].read_bytes()
            result, raw = invoke(cls.folder, 'pack', images['release_install_packer'],
                                 struct.pack('<3Q', MAGIC, len(policy), len(sha))+policy+sha)
            assert result['status'] == 'returned' and 0 < result['core_u32'] <= len(raw), result
            cls.app = cls.folder/'hia-release'
            cls.app.write_bytes(raw[:result['core_u32']])
            cls.app.chmod(0o700)
        cls.serial = 0
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        (cls.folder/'observations.json').write_text(json.dumps({
            'schema':'hepta.hia.release-install-observations.v1',
            'executable_sha256':sha256(cls.app.read_bytes()).hexdigest(),
            'matching_cold_report':os.environ.get('HEPTA_HIA_RELEASE_INSTALL_COLD_REPORT'),
            'observations':cls.observations, 'whole_native_delivery_qualified':False,
        }, indent=2, sort_keys=True)+'\n')
        if cls.temporary is not None:
            # Test-owned sealed directories need search/write restored for the
            # harness teardown. The product never performs this recursive edit.
            for path, directories, _ in os.walk(cls.folder, topdown=True, followlinks=False):
                os.chmod(path, os.stat(path).st_mode | 0o700)
                for name in directories:
                    child = Path(path)/name
                    if not child.is_symlink():
                        child.chmod(child.stat().st_mode | 0o700)
            cls.temporary.cleanup()

    def setUp(self):
        type(self).serial += 1
        self.case = self.folder/f'case-{self.serial}'
        self.case.mkdir(mode=0o700)
        self.root = self.case/'releases'
        self.root.mkdir(mode=0o700)
        self.wire = bundle([('app', 0o500, b'\x00native\xff\n'*211), ('source.hiaasm', 0o400, b'')])

    def run_app(self, operation='install', *, wire=None, code=0, root=None, digest=None, prefix=(), executable=None, umask=-1):
        wire = self.wire if wire is None else wire
        digest = sha256(wire).hexdigest() if digest is None else digest
        result = subprocess.run([*prefix, str(executable or self.app), operation, str(root or self.root), digest],
                                input=wire, capture_output=True, env={'PATH':''}, timeout=120, umask=umask)
        self.observations.append({'case':self.id(), 'operation':operation, 'bundle_sha256':sha256(wire).hexdigest(),
                                  'expected_sha256':digest, 'returncode':result.returncode,
                                  'stdout':result.stdout.decode('ascii', errors='backslashreplace'),
                                  'stderr_sha256':sha256(result.stderr).hexdigest()})
        self.assertEqual(result.returncode, code, (result.stdout, result.stderr))
        if code:
            self.assertEqual(result.stdout, b'')
        return result

    def test_real_install_readback_no_replace_and_independent_new_version(self):
        result = self.run_app()
        receipt = json.loads(result.stdout)
        digest = sha256(self.wire).hexdigest()
        self.assertEqual(receipt, {'schema':'hepta.hia.release-install.v1', 'sha256':digest,
                                  'files':2, 'bytes':len(self.wire), 'published':True})
        release = self.root/digest
        before = release.stat()
        self.assertEqual(before.st_mode & 0o7777, 0o500)
        for name, (mode, payload) in reference_unpack(self.wire).items():
            path = release/os.fsdecode(name)
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(path.stat().st_mode & 0o7777, mode)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [digest])
        self.run_app(code=14)
        self.assertEqual(release.stat().st_ino, before.st_ino)
        self.assertFalse(json.loads(self.run_app('verify').stdout)['published'])
        other = bundle([('app', 0o500, b'next'), ('source.hiaasm', 0o400, b'new')])
        self.run_app(wire=other)
        self.assertEqual((release/'app').read_bytes(), reference_unpack(self.wire)[b'app'][1])

    def test_installed_copy_operates_under_empty_path_with_no_host_stack(self):
        wire = bundle([('hia-release', 0o500, self.app.read_bytes()),
                       ('release-policy.hiaasm', 0o400, POLICY.read_bytes())])
        self.run_app(wire=wire)
        installed = self.root/sha256(wire).hexdigest()/'hia-release'
        self.run_app('verify', wire=wire, executable=installed)
        target = self.case/'another-root'
        target.mkdir(mode=0o700)
        self.run_app(root=target, executable=installed)
        self.assertTrue((target/sha256(self.wire).hexdigest()/'app').exists())

    def test_package_and_argument_refusals_have_zero_filesystem_effects(self):
        invalid = [b'', self.wire[:-1], self.wire+b'x', bundle([]),
                   bundle([('x',0o777,b'x')]), bundle([('x',0o644,b'x')]),
                   bundle([('x',0o400,b'a'),('x',0o400,b'b')])]
        for name in (b'../escape',b'a/b',b'.',b'..',b'.hidden',b'a\x00b',b'\xff',b'x'*128):
            invalid.append(bundle([(name,0o400,b'x')]))
        for raw in invalid:
            self.run_app(wire=raw,code=16)
            self.assertEqual(list(self.root.iterdir()), [])
        self.run_app(digest='0'*64,code=11)
        self.run_app(digest='AB'*32,code=16)
        self.run_app('unknown',code=16)
        self.run_app(root=str(self.root)+'/../releases',code=16)
        self.run_app(root=str(self.root)+'/',code=16)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_all_symlink_components_and_unsafe_root_are_refused(self):
        leaf = self.case/'alias'
        leaf.symlink_to(self.root, target_is_directory=True)
        self.run_app(root=leaf,code=10)
        parent = self.case/'parent-alias'
        parent.symlink_to(self.case, target_is_directory=True)
        self.run_app(root=parent/'releases',code=10)
        self.root.chmod(0o777)
        self.run_app(code=10)
        self.root.chmod(0o700)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_ancestor_traversal_needs_search_not_directory_read_authority(self):
        parent = self.case/'search-only-parent'
        parent.mkdir(mode=0o700)
        root = parent/'private-release-root'
        root.mkdir(mode=0o700)
        parent.chmod(0o111)
        try:
            self.run_app(root=root)
            self.run_app('verify',root=root)
        finally:
            parent.chmod(0o700)

    def test_sgid_root_and_restrictive_caller_umask_preserve_exact_release_modes(self):
        self.root.chmod(0o2700)
        root_before = self.root.stat()
        self.run_app(umask=0o777)
        self.run_app('verify',umask=0o777)
        root_after = self.root.stat()
        self.assertEqual((root_after.st_ino,root_after.st_mode,root_after.st_uid,root_after.st_gid),
                         (root_before.st_ino,root_before.st_mode,root_before.st_uid,root_before.st_gid))
        release = self.root/sha256(self.wire).hexdigest()
        self.assertEqual(release.stat().st_mode & 0o7777,0o500)
        self.assertEqual((release/'app').stat().st_mode & 0o7777,0o500)
        self.assertEqual((release/'source.hiaasm').stat().st_mode & 0o7777,0o400)

    def test_inventory_modes_symlinks_hardlinks_and_content_corruption(self):
        self.run_app()
        release = self.root/sha256(self.wire).hexdigest()
        release.chmod(0o700)
        extra = release/'extra'
        extra.write_bytes(b'not authorized')
        release.chmod(0o500)
        self.run_app('verify',code=11)
        release.chmod(0o700)
        extra.unlink()
        app = release/'app'
        app.chmod(0o700)
        release.chmod(0o500)
        self.run_app('verify',code=10)
        app.chmod(0o500)
        peer = self.case/'hardlink'
        os.link(app,peer)
        self.run_app('verify',code=10)
        peer.unlink()
        app.chmod(0o700)
        raw = app.read_bytes()
        app.write_bytes(b'x'+raw[1:])
        app.chmod(0o500)
        self.run_app('verify',code=11)
        release.chmod(0o700)
        app.unlink()
        app.symlink_to(self.app)
        release.chmod(0o500)
        self.run_app('verify',code=10)

    def test_count_name_and_transport_limits(self):
        self.run_app(wire=bundle([(f'file-{i}',0o400,b'') for i in range(256)]))
        self.run_app(wire=bundle([(f'file-{i}',0o400,b'') for i in range(257)]),code=16)
        self.run_app(wire=bundle([('x'*127,0o400,b'')]))
        self.run_app(wire=b'\x00'*((64<<20)+1),code=17)

    def test_existing_destination_and_dangling_symlink_remain_unchanged(self):
        digest = sha256(self.wire).hexdigest()
        dest = self.root/digest
        dest.mkdir()
        marker = dest/'owner'
        marker.write_bytes(b'previous release')
        inode = dest.stat().st_ino
        self.run_app(code=14)
        self.assertEqual((dest.stat().st_ino, marker.read_bytes()), (inode,b'previous release'))
        marker.unlink()
        dest.rmdir()
        dest.symlink_to(self.case/'absent',target_is_directory=True)
        self.run_app(code=14)
        self.assertTrue(dest.is_symlink())

    def trace(self, injection=None):
        executable = shutil.which('strace')
        self.assertIsNotNone(executable, 'real syscall fault controls require strace')
        trace = self.case/f'trace-{len(self.observations)}.log'
        prefix = [executable,'-qq','-o',str(trace),'-e','trace=all']
        if injection:
            prefix += ['-e','inject='+injection]
        return prefix, trace

    def test_real_fsync_failures_and_read_only_recovery_after_publication(self):
        wire = bundle([('app',0o500,b'actual file')])
        for when in (1,2,3):
            root = self.case/f'fsync-{when}'
            root.mkdir(mode=0o700)
            prefix, trace = self.trace(f'fsync:error=EIO:when={when}')
            self.run_app(wire=wire,root=root,prefix=prefix,code=15)
            self.assertIn('INJECTED',trace.read_text())
            release = root/sha256(wire).hexdigest()
            self.assertEqual(release.exists(),when == 3)
            if when == 3:
                self.run_app('verify',wire=wire,root=root)
            else:
                stages = list(root.glob('.hia-stage-*'))
                self.assertEqual(len(stages),1)

    def test_actual_receipt_loss_retains_verified_release_without_replay(self):
        wire = bundle([('app',0o500,b'actual file')])
        prefix, trace = self.trace('write:error=EIO:when=2')
        self.run_app(wire=wire,prefix=prefix,code=15)
        self.assertIn('INJECTED',trace.read_text())
        release = self.root/sha256(wire).hexdigest()
        before = release.stat().st_ino
        self.run_app('verify',wire=wire)
        self.assertEqual(release.stat().st_ino,before)

    def test_real_interrupted_syscalls_and_no_foreign_child(self):
        prefix, trace = self.trace('read:error=EINTR:when=1')
        self.run_app(prefix=prefix)
        raw = trace.read_text()
        self.assertIn('INJECTED',raw)
        self.assertEqual(len(re.findall(r'^execve\(',raw,re.M)),1)
        self.assertNotRegex(raw,r'\b(?:fork|vfork|clone|clone3)\(')
        self.assertNotIn('ld.so',raw)
        self.assertLess(raw.index('fsync('),raw.index('renameat2('))
        self.assertIn('RENAME_NOREPLACE',raw)

    def test_actual_sigkill_before_and_after_publication_has_read_only_resolution(self):
        wire = bundle([('app',0o500,b'actual file')])
        for syscall, when, published in [('renameat2',1,False),('write',2,True)]:
            root = self.case/f'kill-{syscall}'
            root.mkdir(mode=0o700)
            prefix, trace = self.trace(f'{syscall}:signal=SIGKILL:when={when}')
            result = subprocess.run([*prefix,str(self.app),'install',str(root),sha256(wire).hexdigest()],
                                    input=wire,capture_output=True,env={'PATH':''},timeout=30)
            self.observations.append({'case':self.id(),'cut':f'{syscall}:{when}',
                                      'returncode':result.returncode,'stdout_hex':result.stdout.hex(),
                                      'trace_sha256':sha256(trace.read_bytes()).hexdigest()})
            self.assertIn(result.returncode,(-9,137),result.stderr)
            self.assertEqual(result.stdout,b'')
            self.assertIn('SIGKILL',trace.read_text())
            release = root/sha256(wire).hexdigest()
            self.assertEqual(release.exists(),published)
            if published:
                self.run_app('verify',wire=wire,root=root)
            else:
                self.assertEqual(len(list(root.glob('.hia-stage-*'))),1)
                self.run_app('verify',wire=wire,root=root,code=10)


if __name__ == '__main__':
    unittest.main()
