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


class SentinelCompletionTests(unittest.TestCase):
    @staticmethod
    def receipts(stdout=b'RESTART_BEGIN\nONCE_CONTENT=1\nRESTART_END\n', stderr=b'diagnostic\n'):
        def stream(raw):
            return {'bytes_hex':raw.hex(), 'text':raw.decode('utf-8',errors='replace'),
                    'eof':True, 'offset':0, 'next_offset':len(raw), 'size':len(raw)}
        terminal={'job_id':'original-sentinel', 'state':'succeeded', 'exit_code':0,
                  'output_complete':True, 'output_durable':True,
                  'terminal_publication_confirmed':True}
        logs={'job_id':'original-sentinel', 'stdout':stream(stdout), 'stderr':stream(stderr)}
        return terminal,logs

    def test_rejects_missing_false_or_nonboolean_durability_fields(self):
        for field in ('output_complete','output_durable','terminal_publication_confirmed'):
            for value in ('missing',False,None,1,'true'):
                with self.subTest(field=field,value=value):
                    terminal,logs=self.receipts()
                    if value=='missing': terminal.pop(field)
                    else: terminal[field]=value
                    with self.assertRaises(module.PublicationConflict):
                        module.verify_sentinel_completion(terminal,logs,'original-sentinel')

    def test_requires_original_terminal_and_read_job_identity_and_success(self):
        for owner in ('terminal','read'):
            for value in ('missing','another-job',None):
                with self.subTest(owner=owner,value=value):
                    terminal,logs=self.receipts();target=terminal if owner=='terminal' else logs
                    if value=='missing': target.pop('job_id')
                    else: target['job_id']=value
                    with self.assertRaises(module.PublicationConflict):
                        module.verify_sentinel_completion(terminal,logs,'original-sentinel')
        terminal,logs=self.receipts();terminal['state']='failed'
        with self.assertRaises(module.PublicationConflict):
            module.verify_sentinel_completion(terminal,logs,'original-sentinel')

    def test_rejects_incomplete_or_inconsistent_stream_receipts(self):
        for name in ('stdout','stderr'):
            for field,value in [('eof',False),('offset',1),('next_offset',0),('size',999),
                                ('size',True),('size',-1),('bytes_hex','0'),('bytes_hex','gg'),
                                ('bytes_hex',''),('text','unrelated text')]:
                with self.subTest(stream=name,field=field,value=value):
                    terminal,logs=self.receipts();logs[name][field]=value
                    with self.assertRaises(module.PublicationConflict):
                        module.verify_sentinel_completion(terminal,logs,'original-sentinel')
            for field in ('bytes_hex','text','eof','offset','next_offset','size'):
                with self.subTest(stream=name,missing=field):
                    terminal,logs=self.receipts();logs[name].pop(field)
                    with self.assertRaises(module.PublicationConflict):
                        module.verify_sentinel_completion(terminal,logs,'original-sentinel')

    def test_rejects_additional_missing_or_reordered_sentinel_lines(self):
        for raw in (b'RESTART_BEGIN\nONCE_CONTENT=1\n',
                    b'RESTART_BEGIN\nONCE_CONTENT=1\nRESTART_END',
                    b'RESTART_BEGIN\nONCE_CONTENT=1\nRESTART_END\nEXTRA\n',
                    b'RESTART_BEGIN\nONCE_CONTENT=1\nONCE_CONTENT=1\nRESTART_END\n',
                    b'RESTART_END\nONCE_CONTENT=1\nRESTART_BEGIN\n'):
            with self.subTest(stdout=raw):
                terminal,logs=self.receipts(stdout=raw)
                with self.assertRaises(module.PublicationConflict):
                    module.verify_sentinel_completion(terminal,logs,'original-sentinel')

    def test_accepts_complete_receipts_and_preserves_nonempty_stderr(self):
        for stderr in (b'',b'complete diagnostic\n',b'non-UTF8 diagnostic: \xff\n'):
            with self.subTest(stderr=stderr):
                terminal,logs=self.receipts(stderr=stderr)
                before=json.dumps([terminal,logs],sort_keys=True)
                proof=module.verify_sentinel_completion(terminal,logs,'original-sentinel')
                self.assertEqual(proof['job_id'],'original-sentinel')
                self.assertTrue(proof['output_durable'] and proof['terminal_publication_confirmed'])
                self.assertTrue(proof['stdout_exact_once_transcript'])
                self.assertEqual(proof['streams']['stderr']['sha256'],module.sha(stderr))
                self.assertEqual(proof['streams']['stderr']['bytes'],len(stderr))
                self.assertEqual(json.dumps([terminal,logs],sort_keys=True),before)


if __name__=='__main__': unittest.main(verbosity=2)
