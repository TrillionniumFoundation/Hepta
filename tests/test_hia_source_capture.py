"""Exercise the real descriptor-bound HIA source capture and its refusal surface."""
from __future__ import annotations

import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from tools.build_hia_source_capture import build

ROOT = Path(__file__).resolve().parents[1]
SMALL = b'''hia-asm.v1 hepta.hia.program.v8 captured_source
fn value(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)
  v3:u32 = const() {"value":7}
  ret(v3)
end
'''


def request(root_fd, rows, tag=b'HIANAM01'):
    wire = bytearray(struct.pack('<8sQ8sQ', b'HIACAP01', root_fd, tag, len(rows)))
    for path, alias, data in rows:
        path = path.encode('ascii') if isinstance(path, str) else path
        alias = alias.encode('ascii') if isinstance(alias, str) else alias
        wire += struct.pack('<3Q', len(path), len(alias), len(data))
        wire += sha256(data).digest() + path + alias
    return bytes(wire)


def packet(rows, tag=b'HIANAM01'):
    if tag == b'HIARAW01':
        return rows[0][2]
    wire = bytearray(struct.pack('<8sQ', tag, len(rows)))
    for _, alias, data in rows:
        alias = alias.encode('ascii') if isinstance(alias, str) else alias
        wire += struct.pack('<2Q', len(alias), len(data)) + alias + data
    return bytes(wire)


def seal(name, raw):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        at = 0
        while at < len(raw):
            written = os.write(fd, raw[at:])
            if written <= 0:
                raise OSError('short executable capture')
            at += written
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
        return fd
    except BaseException:
        os.close(fd)
        raise


class SourceCaptureSourceTests(unittest.TestCase):
    def test_generated_source_and_packer_are_exact(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_artifact_publication import document
        from tools.generate_hia_source_capture import policy_source, packer_source

        for name, source in (('source_capture', policy_source()), ('source_capture_packer', packer_source())):
            self.assertEqual((ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_text(),
                             render_assembly(document(source, name)))


@unittest.skipUnless(os.environ.get('HEPTA_HIA_SOURCE_CAPTURE_COLD_REPORT'), 'matching source cold report required')
class SourceCaptureNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix='hia-source-capture-tests-')
        cls.work = Path(cls.workspace.name)
        report = Path(os.environ['HEPTA_HIA_SOURCE_CAPTURE_COLD_REPORT']).resolve()
        compiler = report.with_suffix('.cold') / 'qualification.evidence/B3.image.bin'
        cls.compiler, cls.report = compiler, report
        cls.executable = build(cls.work / 'build', compiler, report)
        cls.code = cls.executable.read_bytes()
        cls.executable_fd = seal('hia-source-capture-test', cls.code)
        cls.root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)

    @classmethod
    def tearDownClass(cls):
        os.close(cls.root_fd)
        os.close(cls.executable_fd)
        cls.workspace.cleanup()

    def run_capture(self, wire, *, root_fd=None, arguments=(), timeout=3, output=None):
        return subprocess.run([f'/proc/self/fd/{self.executable_fd}', *arguments], input=wire,
                              stdout=subprocess.PIPE if output is None else output, stderr=subprocess.PIPE,
                              pass_fds=(self.executable_fd, self.root_fd if root_fd is None else root_fd),
                              cwd=self.work, env={'PATH': ''}, timeout=timeout)

    def assert_refused(self, wire, code, *, root_fd=None, arguments=()):
        result = self.run_capture(wire, root_fd=root_fd, arguments=arguments)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (code, b'', b''))

    def test_all_declared_recipe_sources_and_packer_kits_match(self):
        table = (ROOT / 'examples/hia_bootstrap/release_member_sources.tsv').read_text().splitlines()
        declared = int(table[0].split('\t')[1])
        recipes = [line.split('\t') for line in table[1:] if line]
        self.assertEqual(len(recipes), declared)
        used = set()
        for fields in recipes:
            name, packer_name, *mappings = fields
            sources = [item.split('=', 1) for item in mappings]
            rows = [('examples/hia_bootstrap/' + source, alias,
                     (ROOT / 'examples/hia_bootstrap' / source).read_bytes()) for alias, source in sources]
            if rows:
                tag = b'HIASRC01' if len(rows) == 1 else b'HIAMUL01'
                with self.subTest(member=name):
                    result = self.run_capture(request(self.root_fd, rows, tag))
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, packet(rows, tag), b''))
            if packer_name not in used:
                used.add(packer_name)
                aliases = (('source_build_policy.hepta', 'source_filter_member.hepta'),
                           ('selfhost.hepta', 'selfhost.hepta'), ('source_build_packer.hepta', packer_name))
                rows = [('examples/hia_bootstrap/' + source, alias,
                         (ROOT / 'examples/hia_bootstrap' / source).read_bytes()) for alias, source in aliases]
                for tag in (b'HIAKIT01', b'HIAKOBJ1'):
                    with self.subTest(packer=packer_name, tag=tag):
                        result = self.run_capture(request(self.root_fd, rows, tag))
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                                         (0, packet(rows, tag), b''))
        self.assertGreaterEqual(len(used), 61)

    def test_all_group_forms_and_raw_resource_are_exact(self):
        rows = [('examples/hia_bootstrap/sha256_stream.hepta', 'hash.hepta',
                 (ROOT / 'examples/hia_bootstrap/sha256_stream.hepta').read_bytes())]
        for tag in (b'HIANAM01', b'HIASRC01', b'HIAIMG01'):
            result = self.run_capture(request(self.root_fd, rows, tag))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, packet(rows, tag), b''))
        rows = [('examples/hia_bootstrap/release_member_sources.tsv', 'recipes',
                 (ROOT / 'examples/hia_bootstrap/release_member_sources.tsv').read_bytes())]
        result = self.run_capture(request(self.root_fd, rows, b'HIARAW01'))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, rows[0][2], b''))

    def test_release_transport_does_not_read_or_hash_sources_in_python(self):
        from unittest.mock import patch
        from tools.build_hia_source_capture import capture_named_sources

        relative = 'examples/hia_bootstrap/sha256_stream.hepta'
        source = (ROOT / relative).read_bytes()
        admitted = {relative: sha256(source).hexdigest()}
        with (patch.object(Path, 'read_bytes', side_effect=AssertionError('host source capture entered')),
              patch.object(os, 'stat', side_effect=AssertionError('host source stat entered'))):
            captured = capture_named_sources(self.code, ROOT, {'hash.hepta': 'sha256_stream.hepta'},
                                             admitted, self.work)
        self.assertEqual(captured, {'hash.hepta': source})
        changed = dict(admitted, **{relative: '0' * 64})
        with self.assertRaisesRegex(ValueError, 'native source capture refused'):
            capture_named_sources(self.code, ROOT, {'hash.hepta': 'sha256_stream.hepta'}, changed, self.work)

    def test_v2_native_metadata_lengths_and_v1_zero_length_refusal(self):
        rows = [('examples/hia_bootstrap/sha256_stream.hepta', 'hash.hepta',
                 (ROOT / 'examples/hia_bootstrap/sha256_stream.hepta').read_bytes())]
        for tag in (b'HIANAM01', b'HIARAW01'):
            wire = bytearray(request(self.root_fd, rows, tag))
            struct.pack_into('<Q', wire, 48, 0)
            self.assert_refused(wire, 16)
            wire[:8] = b'HIACAP02'
            result = self.run_capture(wire)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, packet(rows, tag), b''))
            wire[56] ^= 1
            self.assert_refused(wire, 19)

    def test_request_extent_aliases_and_parent_paths_are_rejected_before_output(self):
        rows = [('examples/hia_bootstrap/sha256_stream.hepta', 'hash.hepta',
                 (ROOT / 'examples/hia_bootstrap/sha256_stream.hepta').read_bytes())]
        valid = request(self.root_fd, rows)
        for wire in (b'', valid[:31], b'X' + valid[1:], valid + b'X', valid[:-1],
                     valid[:24] + struct.pack('<Q', 129) + valid[32:],
                     request(self.root_fd, rows * 2), request(self.root_fd, rows, b'HIAMUL01'),
                     request(self.root_fd, rows, b'HIAKIT01'), request(self.root_fd, rows, b'INVALID1')):
            with self.subTest(size=len(wire), prefix=wire[:32]):
                self.assert_refused(wire, 16)
        for path in ('/etc/passwd', '../sha256_stream.hepta', 'examples//x.hepta',
                     './examples/hia_bootstrap/sha256_stream.hepta', 'examples/../sha256_stream.hepta',
                     'examples/x\x00.hepta', 'examples/'):
            self.assert_refused(request(self.root_fd, [(path, 'hash.hepta', rows[0][2])]), 16)
        for alias in ('x', '../x.hepta', '.hidden.hepta', '-x.hepta', 'x/hepta', 'x\x00.hepta'):
            self.assert_refused(request(self.root_fd, [(rows[0][0], alias, rows[0][2])]), 16)
        self.assert_refused(valid, 16, arguments=('ignored',))

    def test_bad_pin_size_missing_root_and_late_source_failure_publish_nothing(self):
        source = (ROOT / 'examples/hia_bootstrap/sha256_stream.hepta').read_bytes()
        row = ('examples/hia_bootstrap/sha256_stream.hepta', 'hash.hepta', source)
        wire = bytearray(request(self.root_fd, [row]))
        wire[56] ^= 1
        self.assert_refused(wire, 19)
        wire = bytearray(request(self.root_fd, [row]))
        struct.pack_into('<Q', wire, 48, len(source) - 1)
        self.assert_refused(wire, 19)
        missing = ('examples/hia_bootstrap/does-not-exist.hepta', 'missing.hepta', SMALL)
        self.assert_refused(request(self.root_fd, [row, missing]), 15)
        with tempfile.TemporaryFile() as regular:
            self.assert_refused(request(regular.fileno(), [row]), 16, root_fd=regular.fileno())

    def test_symlinks_hardlinks_fifo_and_directories_are_refused(self):
        with tempfile.TemporaryDirectory(dir=self.work) as tmp:
            root = Path(tmp)
            (root / 'file.hepta').write_bytes(SMALL)
            (root / 'link.hepta').symlink_to('file.hepta')
            (root / 'escape').symlink_to(ROOT, target_is_directory=True)
            (root / 'directory').mkdir()
            os.mkfifo(root / 'fifo.hepta')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for name, code in (('link.hepta', 15), ('escape/examples/hia_bootstrap/selfhost.hepta', 15),
                                   ('directory', 16), ('fifo.hepta', 16)):
                    with self.subTest(name=name):
                        self.assert_refused(request(fd, [(name, 'source.hepta', SMALL)]), code, root_fd=fd)
                os.link(root / 'file.hepta', root / 'alias.hepta')
                self.assert_refused(request(fd, [('file.hepta', 'source.hepta', SMALL)]), 16, root_fd=fd)
            finally:
                os.close(fd)

    def test_binary_resource_and_maximum_source_extent_are_captured(self):
        with tempfile.TemporaryDirectory(dir=self.work) as tmp:
            root = Path(tmp)
            raw = bytes(range(256)) * 4096
            (root / 'binary').write_bytes(raw)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                wire = request(fd, [('binary', 'binary', raw)], b'HIARAW01')
                result = self.run_capture(wire, root_fd=fd, timeout=10)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, raw, b''))
                with open('/dev/full', 'wb', buffering=0) as full:
                    result = self.run_capture(wire, root_fd=fd, output=full, timeout=10)
                    self.assertEqual((result.returncode, result.stderr), (15, b''))
                (root / 'binary').write_bytes(raw + b'x')
                self.assert_refused(request(fd, [('binary', 'source.hepta', raw + b'x')]), 16, root_fd=fd)
            finally:
                os.close(fd)

    def test_capture_feeds_the_sealed_native_source_compiler(self):
        from tools.build_hia_source_build import _compiled_sources, _check_pack_output
        from tools.generate_hia_source_build import PACK_MAGIC
        from tools.qualify_hia_selfhost import compile_stage, invoke

        observer = bytes.fromhex(json.loads(self.report.read_bytes())['native_flat_observer_hex'])
        work = self.work / 'source-build'
        work.mkdir()
        images = []
        for name in ('source_build_policy', 'selfhost', 'source_build_packer'):
            path, _ = compile_stage(work, name, self.compiler,
                                    (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes(),
                                    flat_observer=observer)
            images.append(path.read_bytes())
        frame = struct.pack('<4Q', PACK_MAGIC, *map(len, images)) + b''.join(images)
        result, output = invoke(work, 'pack', work / 'source_build_packer.image.bin', frame, flat_observer=observer)
        code = _check_pack_output(result, output, artifact=images[-1], source=frame)
        program_fd = seal('hia-source-build-test', code)
        fixture = self.work / 'fixture'
        fixture.mkdir()
        (fixture / 'value.hepta').write_bytes(SMALL)
        source_fd = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY)
        try:
            captured = self.run_capture(request(source_fd, [('value.hepta', 'value.hepta', SMALL)]), root_fd=source_fd)
            self.assertEqual((captured.returncode, captured.stderr), (0, b''))
            compiled = subprocess.run([f'/proc/self/fd/{program_fd}', 'sources'], input=captured.stdout,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(program_fd,),
                                      env={'PATH': ''}, cwd=fixture, timeout=10)
            self.assertEqual((compiled.returncode, compiled.stderr), (0, b''))
            artifacts = _compiled_sources(compiled.stdout, {'value.hepta': SMALL})
            self.assertGreater(len(artifacts['value.hepta']), 0)
        finally:
            os.close(source_fd)
            os.close(program_fd)


if __name__ == '__main__':
    unittest.main()
