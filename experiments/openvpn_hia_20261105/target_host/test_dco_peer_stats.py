#!/usr/bin/env python3
"""Pinned ovpn peer dump protocol regressions; offline, not kernel acceptance."""
import importlib.util
from pathlib import Path
import struct
import unittest
import tempfile
import sys
import io
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('dco_peer_stats',HERE/'dco_peer_stats.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class NetlinkPeerDumpTests(unittest.TestCase):
    def sample_peer(self):
        return module.attr(1,struct.pack('=I',17))+b''.join(module.attr(i,struct.pack('=Q',1000+i)) for i in module.COUNTERS)

    def simulate(self, reply):
        sock=mock.MagicMock()
        sock.__enter__.return_value=sock
        with mock.patch.object(module.socket,'if_nametoindex',return_value=3),mock.patch.object(module.socket,'socket',return_value=sock),mock.patch.object(module,'request',side_effect=[[{1:struct.pack('=H',44)}],reply]) as req:
            result=module.query('tunbench-s');return result,req

    def test_dump_request_has_ifindex_and_no_empty_peer_nest(self):
        result,req=self.simulate([{2:self.sample_peer()}])
        self.assertEqual(req.call_args_list[1].args[3],module.attr(1,struct.pack('=I',3)))
        self.assertTrue(req.call_args_list[1].kwargs['dump'])
        self.assertEqual(result['peers'][0]['peer_id'],17)
        self.assertEqual(result['peers'][0]['vpn_rx_bytes'],1016)

    def test_optional_ifindex_echo_must_match(self):
        with self.assertRaisesRegex(ValueError,'another interface'):
            self.simulate([{1:struct.pack('=I',999),2:self.sample_peer()}])

    def test_missing_peer_counter_rejected(self):
        missing=module.attr(1,struct.pack('=I',17))
        with self.assertRaisesRegex(ValueError,'missing peer ID or counters'):
            self.simulate([{2:missing}])

    def test_duplicate_id_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate peer'):
            self.simulate([{2:self.sample_peer()},{2:self.sample_peer()}])

    def test_archived_kernel_einval_is_never_treated_as_counter_evidence(self):
        # 2026-11-05 original target run 41998233420 returned -EINVAL for
        # PEER_GET with the extra empty nested OVPN_A_PEER request attribute.
        archived_request = bytes.fromhex(
            '200000002c000103020000005627000003010000080001000300000004000280')
        self.assertEqual(archived_request[20:],
                         module.attr(1,struct.pack('=I',3)) + module.attr(2 | 0x8000,b''))
        sock = mock.MagicMock()
        sock.getsockname.return_value = (0x2756, 0)
        error = module.NLHDR.pack(20, module.NLMSG_ERROR, 0, 2, 0) + struct.pack('=i', -22)
        sock.recvmsg.return_value = (error, [], 0, (0, 0))
        with self.assertRaises(OSError) as ctx:
            module.request(sock,44,3,module.attr(1,struct.pack('=I',3)),2,dump=True)
        self.assertEqual(ctx.exception.errno, 22)

    def test_cli_rejects_dangling_output_symlink_without_touching_target(self):
        # The older Path.exists() + write_text() silently followed this
        # dangling leaf symlink and created a file outside the evidence path.
        with tempfile.TemporaryDirectory() as tmp:
            outside=Path(tmp)/'unrelated.json'
            output=Path(tmp)/'peer.json'
            output.symlink_to(outside)
            with mock.patch.object(module,'query',return_value={'schema':'mock-peer'}), \
                 mock.patch.object(sys,'argv',['dco_peer_stats.py','--interface','tunbench-s','--out',str(output)]), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_result:
                    module.main()
            self.assertEqual(exit_result.exception.code,2)
            self.assertTrue(output.is_symlink())
            self.assertFalse(outside.exists())

    def test_cli_writes_fresh_output_and_never_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'peer.json'
            with mock.patch.object(module,'query',return_value={'schema':'mock-peer'}), \
                 mock.patch.object(sys,'argv',['dco_peer_stats.py','--interface','tunbench-s','--out',str(output)]), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(),0)
                original=output.read_bytes()
                with self.assertRaises(SystemExit) as exit_result:
                    module.main()
            self.assertEqual(exit_result.exception.code,2)
            self.assertEqual(output.read_bytes(),original)


    def test_cli_rejects_symlink_parent_without_creating_external_evidence(self):
        # The original exclusive-create leaf guard is not enough: mkdir
        # accepts an existing directory symlink, and open('x') follows it.
        # This is a location-integrity negative test, not a TUN/DCO claim.
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            external=base/'unrelated-directory'
            external.mkdir()
            symlink=base/'public-evidence'
            symlink.symlink_to(external,target_is_directory=True)
            output=symlink/'peer.json'
            with mock.patch.object(module,'query',return_value={'schema':'mock-peer'}), \
                 mock.patch.object(sys,'argv',['dco_peer_stats.py','--interface','tunbench-s','--out',str(output)]), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_result:
                    module.main()
            self.assertEqual(exit_result.exception.code,2)
            self.assertTrue(symlink.is_symlink())
            self.assertFalse((external/'peer.json').exists())

    def test_cli_creates_fresh_nested_directories_without_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'new'/'nested'/'peer.json'
            with mock.patch.object(module,'query',return_value={'schema':'mock-peer'}), \
                 mock.patch.object(sys,'argv',['dco_peer_stats.py','--interface','tunbench-s','--out',str(output)]), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(module.main(),0)
            self.assertEqual(__import__('json').loads(output.read_text())['schema'],'mock-peer')
            self.assertTrue(output.parent.is_dir())


    def test_evidence_creation_respects_maximum_permissions_even_with_zero_umask(self):
        # Root-invoked helpers must not create writable-by-others receipts or
        # newly created parents when their inherited umask is permissive.
        # This is an offline filesystem permission test, not a TUN/DCO pass.
        import os
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'new' / 'nested' / 'peer.json'
            previous = os.umask(0)
            try:
                module.write_evidence_no_follow(output, '{"schema":"umask"}\n')
            finally:
                os.umask(previous)
            for path in (output.parent, output.parent.parent, output):
                mode = stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode & 0o022, 0, (str(path), oct(mode)))
            self.assertEqual(output.read_text(), '{"schema":"umask"}\n')

if __name__=='__main__':unittest.main(verbosity=2)
