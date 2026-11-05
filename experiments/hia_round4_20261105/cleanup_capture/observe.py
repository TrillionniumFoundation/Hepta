import hashlib,json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/data/hepta-hia-round4-9925-20261105/work-integration')
out=pathlib.Path('/data/hepta-hia-round4-9925-20261105/evidence/cleanup-deadline')
label=sys.argv[1]
dest=out/label
dest.mkdir()
if label=='original-r1':
 names=['tests.test_core_capture_terminal_deadline.CaptureTerminalDeadlineTests.'+n for n in ('test_cleanup_eof_after_deadline_is_rejected_without_renewal','test_cleanup_late_data_consumes_quota_without_persistence_or_renewal','test_cleanup_wait_returning_after_deadline_never_succeeds')]
 count=3
else:
 names=['tests.test_core_capture_terminal_deadline','tests.test_core_syntax_diagnostic_capture','tests.test_core_seven_certificate_pending_eio']
 count=45
runner="""import json,sys,unittest
loader=unittest.TestLoader()
suite=loader.loadTestsFromNames(NAME_LITERAL)
result=unittest.TextTestRunner(verbosity=2).run(suite)
receipt={'testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),'loader_errors':loader.errors,'expected_count':COUNT_LITERAL}
print(json.dumps(receipt,sort_keys=True))
sys.exit(0 if result.wasSuccessful() and result.testsRun==COUNT_LITERAL and not loader.errors and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses else 1)
""".replace('NAME_LITERAL',repr(names)).replace('COUNT_LITERAL',str(count))
(dest/'runner.py').write_text(runner)
before=hashlib.sha256((root/'tools/core_syntax_diagnostic_capture.py').read_bytes()).hexdigest()
start=time.monotonic_ns()
c=subprocess.run(['taskset','-c','8',sys.executable,'-B','-c',runner],cwd=root,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0'),capture_output=True,timeout=45)
elapsed=time.monotonic_ns()-start
(dest/'stdout').write_bytes(c.stdout);(dest/'stderr').write_bytes(c.stderr)
after=hashlib.sha256((root/'tools/core_syntax_diagnostic_capture.py').read_bytes()).hexdigest()
record={'label':label,'returncode':c.returncode,'elapsed_ns':elapsed,'source_before':before,'source_after':after,'same_source':before==after,'tests':json.loads(c.stdout.splitlines()[-1]),'stdout_sha256':hashlib.sha256(c.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(c.stderr).hexdigest(),'observer_cpu':[8],'exclusive_host':False}
(dest/'RESULT.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps(record,sort_keys=True),flush=True)
sys.exit(0 if (label=='original-r1' and c.returncode==1) or (label!='original-r1' and c.returncode==0) else 1)
