"""Isolated local checks; never contacts or mutates the Mac controller."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HELPER=Path('/workspace/scratch/372e7da9bde9/mac-controller-deployment.py')
spec=importlib.util.spec_from_file_location('reviewed_deployment',HELPER)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def linux_exchange(left,right,published):
    """Exercise the same exchange semantics in a Linux-only temporary directory."""
    assert sys.platform=='linux'
    function=ctypes.CDLL(None,use_errno=True).renameat2
    function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    function.restype=ctypes.c_int
    fd=os.open(Path(left).parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        if function(fd,os.fsencode(Path(left).name),fd,os.fsencode(Path(right).name),2):
            raise OSError(ctypes.get_errno(),'isolated RENAME_EXCHANGE failed')
        published()
    finally: os.close(fd)


class DeploymentLogicTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='hia-cutover-review-')
        self.root=Path(self.directory.name)
        self.atomic=patch.object(module,'atomic_exchange',linux_exchange)
        self.atomic.start()

    def tearDown(self):
        self.atomic.stop()
        self.directory.cleanup()

    def file(self,name='runtime.json',raw=b'old'):
        path=self.root/name
        module.write_new(path,raw)
        return path

    def test_post_exchange_io_failure_keeps_mutation_flag_and_rolls_back(self):
        live=self.file(); changes=[]
        def fail_after_exchange(left,right,published):
            linux_exchange(left,right,published)
            raise OSError('injected post-exchange close/read failure')
        with patch.object(module,'atomic_exchange',fail_after_exchange):
            with self.assertRaises(OSError):
                module.publish_swap(changes,live,b'new',module.sha(b'old'),private=True)
        self.assertEqual(len(changes),1)
        self.assertTrue(changes[0].ever_applied and changes[0].active)
        self.assertEqual(live.read_bytes(),b'new')
        changes[0].rollback()
        self.assertTrue(changes[0].rollback_verified)
        self.assertEqual(live.read_bytes(),b'old')
        self.assertEqual(changes[0].temp.read_bytes(),b'new')

    def test_concurrent_displaced_content_is_retained_and_restored(self):
        live=self.file(); change=module.OwnedSwap(live,b'new',module.sha(b'old'),private=True)
        def race(left,right,published):
            live.write_bytes(b'concurrent-owner-edit')
            linux_exchange(left,right,published)
        with patch.object(module,'atomic_exchange',race):
            with self.assertRaises(module.PublicationConflict): change.publish()
        self.assertTrue(change.active)
        self.assertEqual(change.temp.read_bytes(),b'concurrent-owner-edit')
        change.rollback()
        self.assertEqual(live.read_bytes(),b'concurrent-owner-edit')
        self.assertEqual(change.temp.read_bytes(),b'new')

    def test_rollback_refuses_another_live_inode_even_with_equal_new_bytes(self):
        live=self.file(); change=module.OwnedSwap(live,b'new',module.sha(b'old'),private=True)
        change.publish()
        other=self.file('other',b'new')
        os.replace(other,live)
        with self.assertRaises(module.PublicationConflict): change.rollback()
        self.assertEqual(live.read_bytes(),b'new')
        self.assertEqual(change.temp.read_bytes(),b'old')

    def test_symlink_exchange_preserves_original_inode_and_rolls_back(self):
        live=self.root/'current';live.symlink_to('/review/old')
        old_inode=live.lstat().st_ino
        change=module.OwnedSwap(live,'/review/new','/review/old',kind='symlink')
        change.publish()
        self.assertEqual(os.readlink(live),'/review/new')
        self.assertEqual(change.temp.lstat().st_ino,old_inode)
        change.rollback()
        self.assertEqual(live.lstat().st_ino,old_inode)
        self.assertEqual(os.readlink(live),'/review/old')

    def test_only_hia_worker_and_explicit_plist_resource_fields_may_change(self):
        before={'unknown_future_field':{'keep':[1,2]},'host':'main'}
        after={**before,'hia_worker':{'backend':'reviewed'}}
        module.check_config_addition(json.dumps(before),json.dumps(after))
        with self.assertRaises(module.PublicationConflict):
            module.check_config_addition(json.dumps(before),json.dumps({**after,'host':'changed'}))
        original={'Label':'retained','EnvironmentVariables':{'KEEP':'yes'},'Unknown':[1,2]}
        expected={'Label':'retained','EnvironmentVariables':{'KEEP':'yes','TMPDIR':module.TRUSTED_TMPDIR},
                  'Unknown':[1,2],'SoftResourceLimits':{'NumberOfFiles':8192},'HardResourceLimits':{'NumberOfFiles':8192}}
        module.check_plist_change(plistlib.dumps(original),plistlib.dumps(expected))
        expected['Unknown']=[1]
        with self.assertRaises(module.PublicationConflict):
            module.check_plist_change(plistlib.dumps(original),plistlib.dumps(expected))

    def test_actual_launchctl_resource_format_requires_both_limits(self):
        text='resource limits = {\n maxfiles (soft) => 8192\n maxfiles (hard) => 8192\n}\nenvironment = {\n TMPDIR => '+module.TRUSTED_TMPDIR+'\n}\n'
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=text,stderr='')):
            self.assertEqual(module.controller_resources()['number_of_files'],{'soft':8192,'hard':8192})
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=text.replace('(soft) => 8192','(soft) => 256'),stderr='')):
            with self.assertRaises(module.PublicationConflict): module.controller_resources()

    def test_sentinel_waits_for_explicit_release_then_exits_once(self):
        marker,ready,release=[self.root/name for name in ('once','ready','release')]
        child=subprocess.Popen([sys.executable,'-c',module.sentinel_source(marker,ready,release)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            deadline=time.monotonic()+5
            while not ready.exists() and time.monotonic()<deadline: time.sleep(.01)
            self.assertTrue(ready.exists())
            self.assertIsNone(child.poll())
            self.assertEqual(marker.read_text(),'1')
            module.write_new(release,b'verified')
            out,err=child.communicate(timeout=5)
            self.assertEqual(child.returncode,0,err)
            self.assertEqual(out.splitlines(),['RESTART_BEGIN','ONCE_CONTENT=1','RESTART_END'])
        finally:
            if child.poll() is None: child.kill();child.communicate(timeout=5)


if __name__=='__main__': unittest.main(verbosity=2)
