"""Real unprivileged EACCES fixtures plus full typed archive and partial refusal.

These are custody-control fixtures, never original HIA qualification evidence.
The test owner supplies an independent new 180/3 envelope; production budgets
and the 32 original qualification groups are not modified or exercised.
"""
import argparse, contextlib, errno, hashlib, importlib.util, io, json, os
from pathlib import Path
import stat, subprocess, sys, tarfile, time, traceback, unittest
from unittest import mock

BASE=Path(__file__).resolve().parent
SOURCE=BASE/'candidate'
sys.path.insert(0,str(SOURCE))
import full_common, retain, controller

PINS={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.iterdir() if p.is_file()}
PYTHON=Path('/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12')
EXPECTED=[
 'CustodyPermissionTests.test_complete_typed_readable_failed_original',
 'CustodyPermissionTests.test_directory_permission_is_explicit_partial',
 'CustodyPermissionTests.test_file_permission_preserves_other_originals',
 'CustodyPermissionTests.test_nonpermission_io_and_race_errors_are_not_hidden',
 'CustodyPermissionTests.test_partial_finalizer_preserves_failure_and_cannot_qualify',
]
ACTUAL=BASE/'controls-actual-r1'

def write(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    raw=value if isinstance(value,bytes) else full_common.wire(value)
    with path.open('xb') as f:f.write(raw)
    return path

def guardian(root, public, *, capture=False):
    directory=public/'custody-guard' if capture else root/'guard'
    directory.mkdir(mode=0o700,exist_ok=False)
    command=([str(PYTHON),'-I','-B',str(SOURCE/'retain.py'),'--root',str(root),'--public',str(public)]
             if capture else [str(PYTHON),'-I','-S','-B','-c','raise SystemExit(1)'])
    # -I does not import the adjacent module. Production invokes retain.py
    # with -B; this fixture uses that same invocation for its real archive.
    if capture:command=[str(PYTHON),'-B',str(SOURCE/'retain.py'),'--root',str(root),'--public',str(public)]
    request={'schema':'hia-external-guardian-request.v1','command':command,'cwd':str(root),
        'controller_seconds':30,'expected_qualification':None,
        'source_identities':{str(SOURCE/name):pin for name,pin in PINS.items()}}
    request_path=write(directory/'request.json',request)
    if not capture:write(public/'GUARDIAN-REQUEST.json',request)
    argv=[str(PYTHON),'-I','-S','-B',str(SOURCE/'guardian.py'),'--config',str(request_path),
          '--config-sha256',hashlib.sha256(request_path.read_bytes()).hexdigest(),
          '--implementation',str(SOURCE/'process_owner_impl.py')]
    with (directory/'launcher.stdout.log').open('xb') as out,(directory/'launcher.stderr.log').open('xb') as err:
        result=subprocess.run(argv,cwd=root,env={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'/usr/bin:/bin'},stdout=out,stderr=err,timeout=40,check=False)
    receipt=json.loads((directory/'guardian.json').read_bytes())
    full_common.closed_guardian(receipt,request)
    if capture:
        assert result.returncode==0
        full_common.natural_guardian(receipt,request)
    else:assert result.returncode==1 and receipt['lifecycle']['returncode']==1
    return request,receipt

def fixture(label, *, locked_file=False, locked_directory=False):
    container=ACTUAL/label;container.mkdir(mode=0o700,exist_ok=False)
    root=container/'root';root.mkdir(mode=0o700)
    public=container/'public';public.mkdir(mode=0o700)
    write(root/'preparation-logs/fresh-prerequisite-supply.stderr.log',b'EXACT SYNTHETIC SUPPLIER ERROR\n')
    write(root/'supply/reports/SUPPLY.json',{'status':'SYNTHETIC_FAILED_SUPPLY_FIXTURE','is_real_product_result':False})
    outside=write(container/'outside-original',b'NEVER FOLLOW THIS SYMBOLIC LINK\n')
    (root/'outside-link').symlink_to(outside)
    os.mkfifo(root/'metadata-fifo',0o600)
    if locked_file:
        write(root/'supply/apt-cache/lock',b'UNREADABLE ORIGINAL LOCK FIXTURE\n').chmod(0)
    if locked_directory:
        write(root/'unlisted/hidden-original',b'UNLISTED ORIGINAL FIXTURE\n')
        (root/'unlisted').chmod(0)
    write(public/'SETUP.json',{'root':str(root),'public':str(public),'is_real_product_result':False})
    guardian(root,public)
    guardian(root,public,capture=True)
    custody=json.loads((public/'CUSTODY.json').read_bytes())
    catalog=json.loads((public/'ORIGINAL-CATALOG.json').read_bytes())
    with tarfile.open(public/'full-retained-originals.tar.gz','r:gz') as archive:
        items=archive.getmembers();names=[x.name for x in items]
        assert len(set(names))==len(names)
        assert archive.extractfile('preparation-logs/fresh-prerequisite-supply.stderr.log').read()==b'EXACT SYNTHETIC SUPPLIER ERROR\n'
        assert archive.getmember('metadata-fifo').isfifo()
        assert archive.getmember('outside-link').issym()
        assert archive.extractfile(retain.MANIFEST).read()==(public/'ORIGINAL-CATALOG.json').read_bytes()
    assert outside.read_bytes()==b'NEVER FOLLOW THIS SYMBOLIC LINK\n'
    return root,public,custody,catalog,names

class CustodyPermissionTests(unittest.TestCase):
    def test_complete_typed_readable_failed_original(self):
        root,public,custody,catalog,names=fixture('readable')
        self.assertEqual(custody['status'],'COMPLETE_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN')
        self.assertTrue(custody['all_regular_bytes_read_back'])
        self.assertEqual(custody['unreadable_regular_paths'],[])
        self.assertEqual(custody['unlisted_directory_paths'],[])
        self.assertFalse(custody['permissions_or_ownership_changed'])
        self.assertEqual(json.loads((public/'qualification-guardian-originals/guardian.json').read_bytes())['lifecycle']['returncode'],1)

    def test_directory_permission_is_explicit_partial(self):
        self.assertNotEqual(os.getuid(),0,'real EACCES test must run unprivileged')
        root,public,custody,catalog,names=fixture('directory-refusal',locked_directory=True)
        self.assertEqual(custody['status'],'PARTIAL_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN')
        self.assertEqual(custody['unlisted_directory_paths'],['unlisted'])
        self.assertFalse(custody['all_regular_bytes_read_back'])
        self.assertFalse(catalog['full_namespace_observed'])
        row=next(x for x in catalog['originals'] if x['path']=='unlisted')
        self.assertEqual(row['kind'],'directory');self.assertEqual(row['traversal_error']['errno'],errno.EACCES)
        self.assertNotIn('unlisted/hidden-original',names)
        self.assertEqual(stat.S_IMODE((root/'unlisted').stat().st_mode),0)

    def test_file_permission_preserves_other_originals(self):
        self.assertNotEqual(os.getuid(),0)
        root,public,custody,catalog,names=fixture('file-refusal',locked_file=True)
        self.assertEqual(custody['status'],'PARTIAL_TYPED_ORIGINALS_PENDING_CUSTODY_GUARDIAN')
        self.assertEqual(custody['unreadable_regular_paths'],['supply/apt-cache/lock'])
        row=next(x for x in catalog['originals'] if x['path']=='supply/apt-cache/lock')
        self.assertEqual(row['kind'],'regular');self.assertEqual(row['read_error']['errno'],errno.EACCES)
        self.assertNotIn('sha256',row);self.assertNotIn(row['path'],names)
        self.assertEqual(row['bytes'],len(b'UNREADABLE ORIGINAL LOCK FIXTURE\n'))
        self.assertEqual(stat.S_IMODE((root/row['path']).stat().st_mode),0)
        self.assertTrue(custody['all_selected_regular_bytes_read_back'])
        self.assertFalse(custody['all_regular_bytes_read_back'])

    def test_nonpermission_io_and_race_errors_are_not_hidden(self):
        root=ACTUAL/'refuse-other-error';root.mkdir(mode=0o700)
        write(root/'original',b'fixed\n')
        for error in [OSError(errno.EIO,'synthetic device error'),ValueError('synthetic identity changed')]:
            with self.subTest(error=type(error).__name__),mock.patch.object(retain,'file_record',side_effect=error):
                with self.assertRaises(type(error)):retain.inventory(root)

    def test_partial_finalizer_preserves_failure_and_cannot_qualify(self):
        root,public,custody,catalog,names=fixture('partial-finalizer',locked_file=True,locked_directory=True)
        request=json.loads((public/'custody-guard/request.json').read_bytes())
        with mock.patch.object(controller,'load_setup',return_value=(root,public,{'context':{'fixture':True}},{'source':{'fixture':True}})), \
             mock.patch.object(controller,'custody_request',return_value=request), \
             mock.patch.object(controller,'qualification',side_effect=AssertionError('partial must never reach original qualification')) as qualification:
            code=controller.finish(object())
        final=json.loads((public/'FINAL.json').read_bytes())
        self.assertEqual(code,1);self.assertEqual(final['status'],'HOLD')
        self.assertFalse(final['complete_custody']);self.assertTrue(final['custody_archive_verified'])
        self.assertEqual(final['original_qualification_status'],'MISSING_ORIGINAL_REPORT')
        self.assertIn('partial original custody cannot qualify',final['errors'][0])
        qualification.assert_not_called()

if __name__=='__main__':
    ACTUAL.mkdir(mode=0o700,exist_ok=False)
    before={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in PINS}
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(CustodyPermissionTests)
    observed=[x.id().split('.',1)[1] for x in suite]
    assert observed==EXPECTED
    started=time.monotonic_ns()
    with (ACTUAL/'unittest.log').open('x') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    after={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in PINS}
    anomalies={k:len(getattr(result,k)) for k in ('failures','errors','skipped','expectedFailures','unexpectedSuccesses')}
    report={'schema':'hia.full32.custody-permission-controls.v1','status':'PASS' if result.wasSuccessful() and not any(anomalies.values()) and before==after else 'FAIL',
        'expected_ids':EXPECTED,'loaded_ids':observed,'tests_run':result.testsRun,'anomalies':anomalies,
        'source_before':before,'source_after':after,'elapsed_ns':time.monotonic_ns()-started,
        'real_unprivileged_permission_refusals':True,'uid':os.getuid(),'original_full32_executed':False,'original_supply_executed':False,
        'permissions_or_ownership_changed_by_retainer':False,'synthetic_guardian_fixtures_are_product_qualification':False}
    write(ACTUAL/'REPORT.json',report)
    print(json.dumps(report,sort_keys=True))
    raise SystemExit(0 if report['status']=='PASS' else 1)
