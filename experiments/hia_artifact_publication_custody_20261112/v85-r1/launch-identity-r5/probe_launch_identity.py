"""Real short subprocess fault probe, no HIA/app/39-test execution."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
import types
import unittest
from unittest.mock import patch


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def main():
    p=argparse.ArgumentParser();p.add_argument('--module-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--mode',choices=('raise','none','normal','constructor-error'),required=True)
    args=p.parse_args();root=args.output;root.mkdir(mode=0o700)
    tools=types.ModuleType('tools');tools.__path__=[str(args.module_root/'tools')];sys.modules['tools']=tools
    custody=load('tools.hia_artifact_publication_custody',args.module_root/'tools/hia_artifact_publication_custody.py')
    runner=load('tools.qualify_hia_artifact_publication_tests',args.module_root/'tools/qualify_hia_artifact_publication_tests.py')
    program=root/'synthetic-publication-shaped-child';release=root/'release'
    if args.mode=='constructor-error':
        program.write_text('#!/nonexistent-interpreter-for-exact-control\n')
    elif args.mode=='raise':
        program.write_text('#!'+sys.executable+'\nimport pathlib,sys,time\np=pathlib.Path(sys.argv[2])\ndeadline=time.monotonic()+3\nwhile not p.exists() and time.monotonic()<deadline:time.sleep(.005)\nsys.stdout.buffer.write(b"synthetic child exited")\n')
    else:
        program.write_text('#!'+sys.executable+'\nimport sys,time\ntime.sleep(.02)\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n')
    program.chmod(0o700);session=custody.Session(root/'records');session.test_id='real-launch-identity-'+args.mode
    original_identity=custody.process_identity;error=None;result=unittest.TestResult();result.testsRun=1
    observed={'mode':args.mode,'real_child_executed':args.mode!='constructor-error','HIA_or_product_executed':False}
    session.install()
    try:
        def fault(pid):
            if args.mode=='raise':raise OSError('controlled /proc identity failure after real Popen')
            if args.mode=='none':return None
            return original_identity(pid)
        with patch.object(custody,'process_identity',side_effect=fault):
            completed=subprocess.run([str(program),'store-put',str(release),'-'],input=b'complete offered input',
                                     capture_output=True,env={'PATH':''},timeout=2)
        observed['result']={'returncode':completed.returncode,'stdout':completed.stdout.hex(),'stderr':completed.stderr.hex()}
    except BaseException:
        error=sys.exc_info();observed['exception']=traceback.format_exc()
        result.addError(unittest.FunctionTestCase(lambda:None,description='real child identity fault'),error)
    finally:
        session.restore()
    call=session.calls[0];child=call.process
    observed['actual_child_pid']=None if child is None else child.pid
    observed['control_observed_os_identity']=None if child is None else original_identity(child.pid)
    observed['actual_child_returncode_before_finish']=None if child is None else child.returncode
    body=session.finish(result);observed['producer_RUN']=body
    # Explicit test-harness cleanup AFTER the original RUN receipt is frozen.
    # Do not rewrite its missing identity/reap observations with this later fact.
    if child is not None:
        release.write_bytes(b'release synthetic child')
        observed['control_cleanup_returncode']=child.wait(timeout=3)
        for pipe in (getattr(child,'stdin',None),getattr(child,'stdout',None),getattr(child,'stderr',None)):
            if pipe is not None:pipe.close()
        observed['control_cleanup_identity_absent']=original_identity(child.pid) is None
    session.flush_calls()
    custody.write_json(root/'PROBE.json',observed)
    print(json.dumps({'mode':args.mode,'known_direct_children_reaped':body['known_direct_children_reaped'],
                      'status':body['status'],'actual_child_pid':observed['actual_child_pid']}))
    return 0


if __name__=='__main__':raise SystemExit(main())
