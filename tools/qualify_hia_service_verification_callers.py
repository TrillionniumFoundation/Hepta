"""Complete original caller modules under explicit verification selection.

Existing inputs, clear-environment scopes, subprocess bundles and method
budgets are unchanged. A selected route cannot invoke a retained original.
An explicitly unselected scope remains observable and is reported separately;
this command does not enlarge an old administrator bundle.
"""
from __future__ import annotations
import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
FIXTURE='tests/fixtures/hia_service_verification_original_r12/caller-scopes.json'
FIXTURE_SHA256='a1759844fa0ef1959d9de7a76efbcac25f3c8155bc37beca94a85b5769e70e08'

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope',choices=('ordinary','journal'),required=True)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--cold-report',type=Path)
    choice.add_argument('--development-manifest',type=Path)
    parser.add_argument('--development-compiler',type=Path)
    parser.add_argument('--journal-development-manifest',type=Path)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    if (args.cold_report is not None and args.development_compiler is not None
            or args.development_manifest is not None and args.development_compiler is None):
        raise ValueError('DEV caller scope requires its declared same-compiler image; cold is exclusive')
    raw=(ROOT/FIXTURE).read_bytes()
    if sha256(raw).hexdigest()!=FIXTURE_SHA256:raise ValueError('caller scope bytes differ')
    fixture=json.loads(raw);scope=fixture['scopes'][args.scope]
    for name,pin in scope['files'].items():
        if sha256((ROOT/name).read_bytes()).hexdigest()!=pin['sha256']:
            raise ValueError('an original complete caller module changed: '+name)
    from tools.hia_selfhost_contract import file_digests
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.build_hia_service_verification import build
    from hepta import hia_agent_service as api,hia_service_verification_native as native
    # The explicit import below is kept separate from corpus verification.
    before=file_digests()
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    if args.cold_report is not None:
        outer=json.loads(args.cold_report.read_bytes());nested=json.loads(Path(outer['nested_report']).read_bytes())
        compiler=Path(nested['generations'][-1]['produced_image'])
        manifest=build(args.evidence/'verification',compiler,args.cold_report)
        mode='MATCHING_SOURCE_COLD_COMPLETE_CALLERS'
    else:
        compiler=args.development_compiler.resolve(strict=True)
        manifest=args.development_manifest.resolve(strict=True)
        mode='DEVELOPMENT_COMPLETE_CALLERS'
    compiler_raw=compiler.read_bytes();manifest_raw=manifest.read_bytes();manifest_value=json.loads(manifest_raw)
    if sha256(compiler_raw).hexdigest()!=manifest_value['compiler_sha256']:
        raise ValueError('caller image was not produced by its declared compiler')
    image=native.installed_service_verification(str(manifest))
    runtime_environment={native.SELECTOR:str(manifest)}
    if args.scope=='journal':
        prefix='HEPTA_HIA_AGENT_JOURNAL'
    else:prefix=None
    if prefix is not None:
        runtime_environment[prefix+'_EVIDENCE']=str(args.evidence/'original-component')
        if args.cold_report is not None:
            runtime_environment[prefix+'_COLD_REPORT']=str(args.cold_report)
        else:
            if args.scope=='journal':
                if args.journal_development_manifest is None:
                    raise ValueError('the original journal DEV gate requires its actual development manifest')
                journal_raw=args.journal_development_manifest.read_bytes()
                journal_value=json.loads(journal_raw)
                if journal_value['compiler_sha256']!=sha256(compiler_raw).hexdigest():
                    raise ValueError('journal and verification were built by different compilers')
                runtime_environment[prefix+'_DEVELOPMENT_MANIFEST']=str(args.journal_development_manifest.resolve(strict=True))
            else:
                runtime_environment[prefix+'_DEVELOPMENT_COMPILER']=str(compiler)
    planned=scope['ordered_ids'];started=[];stopped=[];selected_originals=[];unselected_originals=[]
    frames=Counter();entries=Counter();active=['outside-test']
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            active[0]=test.id();started.append(test.id());super().startTest(test)
        def stopTest(self,test):
            stopped.append(test.id());super().stopTest(test);active[0]='outside-test'
    initializer=native.ServiceVerificationFrame.__init__;entry=image._entry
    originals={number:getattr(api,'_SERVICE_VERIFICATION_REFERENCE_'+str(number)) for number in range(1,10)}
    def counted_frame(frame,selected,*values,**kw):
        if selected is not image:raise AssertionError('caller selected an undeclared verification image')
        initializer(frame,selected,*values,**kw);frames[str(frame.mode)]+=1
    def counted_entry(source,size,output,capacity,state,extent):
        request=struct.unpack('<16Q',ctypes.string_at(source,size))
        code=entry(source,size,output,capacity,state,extent)
        if code!=native.OUTPUT_BYTES or request[0]!=native.REQUEST_MAGIC:
            raise AssertionError('caller returned a different actual ABI')
        entries[str(request[1])]+=1;return code
    def retained(number):
        original=originals[number]
        def invoke(*values,**named):
            if os.environ.get(native.SELECTOR) is not None:
                selected_originals.append({'test':active[0],'mode':number})
                raise AssertionError('selected verification used a retained original')
            unselected_originals.append({'test':active[0],'mode':number})
            call={'callee':original,'values':values,'named':named}
            del values,named
            return call.pop('callee')(*call.pop('values'),**call.pop('named'))
        return invoke
    began=time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ,runtime_environment))
        stack.enter_context(patch.object(native.ServiceVerificationFrame,'__init__',counted_frame))
        stack.enter_context(patch.object(image,'_entry',counted_entry))
        for number in range(1,10):
            stack.enter_context(patch.object(api,'_SERVICE_VERIFICATION_REFERENCE_'+str(number),retained(number)))
        suite,actual=load_declared_suite(scope['modules'])
        if list(actual)!=planned:raise ValueError('runtime TestLoader differs from the complete pinned caller inventory')
        result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after=file_digests();stable=before==after
    stable=stable and compiler.read_bytes()==compiler_raw and manifest.read_bytes()==manifest_raw and (ROOT/FIXTURE).read_bytes()==raw
    success=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
             and started==planned and stopped==planned and stable and not selected_originals
             and sum(frames.values())>0 and sum(entries.values())>0)
    report={'schema':'hepta.hia.service-verification-complete-callers.v1','status':'PASS' if success else 'HOLD',
        'qualification_mode':mode,'scope':args.scope,'modules':scope['modules'],'planned':planned,
        'started':started,'stopped':stopped,'tests_run':result.testsRun,
        'failures':[x.id() for x,_ in result.failures],'errors':[x.id() for x,_ in result.errors],
        'skipped':[(x.id(),reason) for x,reason in result.skipped],
        'selected_retained_calls':selected_originals,'explicitly_unselected_retained_calls':unselected_originals,
        'frames_by_mode':dict(frames),'actual_entries_by_event':dict(entries),
        'source_before':before,'source_after':after,'source_unchanged':stable,
        'manifest_path':str(manifest),'manifest_sha256':sha256(manifest_raw).hexdigest(),
        'actual_image_sha256':image.image_sha256,'compiler_sha256':sha256(compiler_raw).hexdigest(),
        'elapsed_seconds':time.monotonic()-began,'outer_budget_seconds':scope['outer_seconds'],
        'old_admin_bundles_or_clear_environment_scopes_modified':False,'whole_native':False}
    (args.evidence/'report.json').write_bytes(canonical(report)+b'\n')
    raise SystemExit(0 if success else 1)
if __name__=='__main__':
    main()
