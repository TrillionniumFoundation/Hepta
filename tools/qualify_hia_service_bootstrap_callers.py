"""Complete original caller modules under explicit bootstrap selection.

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
FIXTURE='tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json'
FIXTURE_SHA256='b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4'
CLOSED_ADMINISTRATOR_IDS={
    'context':('tests.test_hia_service_context_native.ServiceContextNativeTests.test_all_four_actual_public_routes_use_native_with_references_poisoned',),
}

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()

_DIAGNOSTICS_SOURCE = 'tests/hia_caller_diagnostics_admission.py'
_DIAGNOSTICS_SOURCE_PIN = {
    'bytes': 5185,
    'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578',
}
_DIAGNOSTICS_FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTICS_FIXTURE_PIN = {
    'bytes': 3545,
    'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c',
}
_DIAGNOSTICS_CALLER = 'tests/test_hia_agent_native_tools.py'
_JOURNAL_CALLER = 'tests/test_hia_agent_journal_native.py'
_JOURNAL_HELPER = 'tests/hia_journal_installed_preparation.py'
_JOURNAL_HELPER_PIN = {
    'bytes': 15935,
    'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797',
}
_JOURNAL_FIXTURE = 'tests/fixtures/journal_installed_preparation_v2.json'
_JOURNAL_FIXTURE_PIN = {
    'bytes': 14729,
    'sha256': '81914ecb2bef21e9c641282dc8530158146ecadd4b86e8e4e6b3f83e71b73e7b',
}
_JOURNAL_ARCHIVE = 'tests/fixtures/journal_installed_preparation_v1.py.txt'
_JOURNAL_ORIGINAL = {
    'bytes': 48482,
    'sha256': 'a0a6e63291eb76ee84787b432c56eaa32bd1181b762f9593532c059d4a665077',
}
_JOURNAL_CURRENT = {
    'bytes': 48798,
    'sha256': '7d5cebde72523ade809346a30916a48611e18a157230b4f2f6129c0d16b8715c',
}


def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


_SCOPED_HISTORY = 'tools/hia_scoped_caller_source_history.py'
_SCOPED_HISTORY_PIN = {"bytes":7154,"sha256":"608b2a291cfe41d5314d15da320d835c03ee5453b9987e76d383a80ce94fe773"}
_SCOPED_SOURCE_DIGESTS = {
    'tests/test_hia_agent_native_tools.py': {
        '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70',
        '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'},
    'tests/test_hia_agent_native_machine_validation.py': {
        '0c03b958462d2d2b8f7304b52bf419a9832037c3db4e51fa940053176fad0cbb'},
    'tests/test_hia_agent_native_proof_contract.py': {
        'cb958dfdac9ae83b421a55c34109247dbda64af85171525969da55ad3a6d1f03'},
    'tests/test_hia_agent_journal_native.py': {
        '97dec702780d755cc5c2ffa59e5a798c98dc48a17735f9b8983bfdb610d2f263'},
    'tests/test_hia_service_context_native.py': {
        '94bba1ba99cfeb29baa9eb34072514803af288a11d964f950c46bea431e92c1b'},
}


def _review_scoped_caller(root, capture, name, raw, expected):
    if sha256(raw).hexdigest() not in _SCOPED_SOURCE_DIGESTS.get(name, set()):
        return raw, None
    helper = capture(_SCOPED_HISTORY)
    if {'bytes': len(helper), 'sha256': sha256(helper).hexdigest()} != _SCOPED_HISTORY_PIN:
        raise ValueError('scoped caller complete source-history helper changed')
    from tools import hia_scoped_caller_source_history as history
    if Path(history.__file__).read_bytes() != helper:
        raise ValueError('scoped caller imported another source-history helper')
    saved = {name: raw, _SCOPED_HISTORY: helper}
    def take(path):
        relative = Path(path).relative_to(root).as_posix()
        if relative not in saved:
            saved[relative] = capture(relative)
        elif (root / relative).read_bytes() != saved[relative]:
            raise ValueError('scoped caller physical source changed between layers')
        return saved[relative]
    return history.predecessor(root, name, raw, expected, take=take)


def admit_original_scope(root, scope_name):
    """Read one complete fixed scope and its exact reviewed source successors.

    The reconstructed historical test is data only. The caller still loads the
    complete current modules, and the original ordered IDs and budgets remain
    authoritative. Every consumed input is reread before admission returns.
    """
    if type(scope_name) is not str or scope_name not in ('ordinary', 'journal', 'context'):
        raise ValueError('unknown original bootstrap caller scope')
    root = Path(root)
    captured = {}

    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('bootstrap caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    def capture_path(path):
        name = Path(path).relative_to(root).as_posix()
        if name not in captured:
            return capture(name)
        observed = (root / name).read_bytes()
        if observed != captured[name]:
            raise ValueError('bootstrap physical history input changed between layers')
        return observed

    frozen = capture(FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('caller scope bytes differ')
    scope = json.loads(frozen)['scopes'][scope_name]
    from tests.hia_bootstrap_caller_predecessors import bootstrap_caller_predecessor

    adjustments = {}
    journal_adjustments = {}
    predecessors = {}
    for name, expected in scope['files'].items():
        physical = capture(name)
        raw, predecessor_review = _review_scoped_caller(root, capture, name, physical, expected)
        if predecessor_review is not None:
            predecessors[name] = predecessor_review
        else:
            raw = bootstrap_caller_predecessor(root, name, physical, expected, capture)
            if raw != physical:
                predecessors[name] = {'physical': _source_pin(physical), 'predecessor': _source_pin(raw)}
        if _source_pin(raw) == expected:
            continue
        if name == _JOURNAL_CALLER:
            if (scope_name != 'journal' or expected != _JOURNAL_ORIGINAL
                    or _source_pin(raw) != _JOURNAL_CURRENT):
                raise ValueError('bootstrap Journal original scope differs')
            helper = capture(_JOURNAL_HELPER)
            provenance = capture(_JOURNAL_FIXTURE)
            archive = capture(_JOURNAL_ARCHIVE)
            if (_source_pin(helper) != _JOURNAL_HELPER_PIN
                    or _source_pin(provenance) != _JOURNAL_FIXTURE_PIN
                    or _source_pin(archive) != _JOURNAL_ORIGINAL):
                raise ValueError('bootstrap Journal preparation authority changed')
            from tests import hia_journal_installed_preparation as preparation
            if Path(preparation.__file__).read_bytes() != helper:
                raise ValueError('bootstrap imported a different Journal preparation')
            if raw == physical:
                detail = preparation.admit_source(root, name, raw, expected)
            else:
                from tests.hia_installed_distribution_history import journal_preparation_source
                detail = journal_preparation_source(root, physical, expected, take=capture_path)

            actual = {item: _source_pin(captured[item]) for item in
                      (_JOURNAL_CALLER, _JOURNAL_HELPER, _JOURNAL_FIXTURE, _JOURNAL_ARCHIVE)}
            actual[name] = _source_pin(raw)
            if (canonical(detail['captured_files']) != canonical(actual)
                    or detail['original_method_ids'] != scope['ordered_ids']):
                raise ValueError('bootstrap Journal source admission differs from captured scope')
            journal_adjustments[name] = detail
            continue
        if name != _DIAGNOSTICS_CALLER:
            raise ValueError('an original complete caller module changed: ' + name)
        helper = capture(_DIAGNOSTICS_SOURCE)
        provenance = capture(_DIAGNOSTICS_FIXTURE)
        if (_source_pin(helper) != _DIAGNOSTICS_SOURCE_PIN
                or _source_pin(provenance) != _DIAGNOSTICS_FIXTURE_PIN):
            raise ValueError('bootstrap caller diagnostic authority changed')
        from tests import hia_caller_diagnostics_admission as diagnostics
        if Path(diagnostics.__file__).read_bytes() != helper:
            raise ValueError('bootstrap caller imported a different diagnostic admission')
        if expected != diagnostics.ORIGINAL:
            raise ValueError('bootstrap caller diagnostic original identity differs')
        adjustments[name] = diagnostics.admit(
            name, raw, expected['sha256'], provenance)
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('bootstrap caller captured bytes changed: ' + name)
    proof = {
        'schema': 'hepta.hia.service-bootstrap-caller-source-admission.v1',
        'scope': scope_name,
        'authority': {'path': FIXTURE, **_source_pin(frozen)},
        'original_files': dict(scope['files']),
        'original_modules': list(scope['modules']),
        'original_ordered_ids': list(scope['ordered_ids']),
        'original_outer_seconds': scope['outer_seconds'],
        'reviewed_diagnostic_source_adjustments': adjustments,
        'captured_files': {name: _source_pin(raw) for name, raw in captured.items()},
        'terminal_reread_identical': True,
        'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [],
        'whole_native': False,
    }
    if predecessors:
        proof['reviewed_scope_predecessors'] = predecessors
    if journal_adjustments:
        proof['reviewed_journal_installed_preparation_source_adjustments'] = journal_adjustments
    return scope, proof


def bind_scope_admission_to_source_capture(proof, source_digests):
    """Close the interval between source admission and the whole-source seal."""
    for name, expected in proof['captured_files'].items():
        if source_digests.get(name) != expected['sha256']:
            raise ValueError('bootstrap caller admission differs from source capture: ' + name)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope',choices=('ordinary','journal','context'),required=True)
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
    scope,source_admission=admit_original_scope(ROOT,args.scope)
    if scope!=json.loads(raw)['scopes'][args.scope]:
        raise ValueError('admitted Bootstrap scope differs from the original inventory')
    from tools.hia_selfhost_contract import file_digests
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.build_hia_service_bootstrap import build
    from hepta import hia_agent_service as api,hia_service_bootstrap_native as native
    # The explicit import below is kept separate from corpus discovery.
    before=file_digests()
    bind_scope_admission_to_source_capture(source_admission,before)
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    if args.cold_report is not None:
        from tools.hia_cold_compiler import compiler_from_cold_report
        compiler=compiler_from_cold_report(args.cold_report)
        manifest=build(args.evidence/'bootstrap',compiler,args.cold_report)
        mode='MATCHING_SOURCE_COLD_COMPLETE_CALLERS'
    else:
        compiler=args.development_compiler.resolve(strict=True)
        manifest=args.development_manifest.resolve(strict=True)
        mode='DEVELOPMENT_COMPLETE_CALLERS'
    compiler_raw=compiler.read_bytes();manifest_raw=manifest.read_bytes();manifest_value=json.loads(manifest_raw)
    if sha256(compiler_raw).hexdigest()!=manifest_value['compiler_sha256']:
        raise ValueError('caller image was not produced by its declared compiler')
    image=native.installed_service_bootstrap(str(manifest))
    runtime_environment={native.SELECTOR:str(manifest)}
    if args.scope=='journal':
        prefix='HEPTA_HIA_AGENT_JOURNAL'
    elif args.scope=='context':
        prefix='HEPTA_HIA_SERVICE_CONTEXT'
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
                    raise ValueError('journal and bootstrap were built by different compilers')
                runtime_environment[prefix+'_DEVELOPMENT_MANIFEST']=str(args.journal_development_manifest.resolve(strict=True))
            else:
                runtime_environment[prefix+'_DEVELOPMENT_COMPILER']=str(compiler)
    planned=scope['ordered_ids'];started=[];stopped=[];selected_originals=[];unselected_originals=[]
    frames=Counter();entries=Counter();active=['outside-test']
    frames_by_test={};entries_by_test={}
    closed_ids=list(CLOSED_ADMINISTRATOR_IDS.get(args.scope,()))
    if any(name not in planned for name in closed_ids):
        raise ValueError('closed administrator method is not in its pinned original suite')
    saved_selectors={};boundaries=[];boundary_errors=[];administrator_artifacts={}
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            name=test.id();active[0]=name;started.append(name)
            if name in closed_ids:
                selected=os.environ.pop(native.SELECTOR,None)
                saved_selectors[name]=selected
                boundaries.append({'test':name,'event':'start','selector_before':selected,
                    'selector_after':os.environ.get(native.SELECTOR)})
                if selected!=str(manifest):
                    boundary_errors.append({'test':name,'reason':'outer selector differs before original closed scope'})
            super().startTest(test)
        def stopTest(self,test):
            name=test.id()
            if name in closed_ids:
                before_restore=os.environ.get(native.SELECTOR)
                selected=saved_selectors.pop(name,None)
                if selected is None:os.environ.pop(native.SELECTOR,None)
                else:os.environ[native.SELECTOR]=selected
                boundaries.append({'test':name,'event':'stop','selector_before':before_restore,
                    'selector_after':os.environ.get(native.SELECTOR)})
                if before_restore is not None or selected!=str(manifest):
                    boundary_errors.append({'test':name,'reason':'original closed scope did not restore its selector boundary'})
                records={}
                for basename in ('bundle.json','composition.json'):
                    path=args.evidence/'original-component'/'four-owner-composition'/basename
                    try:
                        payload=path.read_bytes()
                    except OSError as error:
                        boundary_errors.append({'test':name,'reason':'original administrator artifact unavailable',
                            'basename':basename,'error':type(error).__name__})
                    else:
                        records[basename]={'path':str(path.resolve()),'bytes':len(payload),
                            'sha256':sha256(payload).hexdigest()}
                administrator_artifacts[name]=records
            stopped.append(name);super().stopTest(test);active[0]='outside-test'
    initializer=native.ServiceBootstrapFrame.__init__;entry=image._entry
    originals=dict(api._SERVICE_BOOTSTRAP_REFERENCES)
    def counted_frame(frame,selected,*values,**kw):
        if selected is not image:raise AssertionError('caller selected an undeclared bootstrap image')
        initializer(frame,selected,*values,**kw);frames[str(frame.mode)]+=1
        frames_by_test.setdefault(active[0],Counter())[str(frame.mode)]+=1
    def counted_entry(source,size,output,capacity,state,extent):
        request=struct.unpack('<16Q',ctypes.string_at(source,size))
        code=entry(source,size,output,capacity,state,extent)
        if code!=native.OUTPUT_BYTES or request[0]!=native.REQUEST_MAGIC:
            raise AssertionError('caller returned a different actual ABI')
        entries[str(request[1])]+=1
        entries_by_test.setdefault(active[0],Counter())[str(request[1])]+=1
        return code
    def note_retained(mode):
        if os.environ.get(native.SELECTOR) is not None:
            selected_originals.append(active[0]);raise AssertionError('selected bootstrap used retained original')
        unselected_originals.append({'test':active[0],'mode':mode})
    def retained_init(self,state_root,*,artifact_roots=()):
        note_retained(1)
        call={'callee':originals[1],'self':self,'state_root':state_root,'artifact_roots':artifact_roots}
        del self,state_root,artifact_roots
        return call.pop('callee')(call.pop('self'),call.pop('state_root'),artifact_roots=call.pop('artifact_roots'))
    def retained_close(self):
        note_retained(2)
        call={'callee':originals[2],'self':self}
        del self
        return call.pop('callee')(call.pop('self'))
    def retained_profiles(self):
        note_retained(3)
        call={'callee':originals[3],'self':self}
        del self
        return call.pop('callee')(call.pop('self'))
    def retained_profile(self,ref,name):
        note_retained(4)
        call={'callee':originals[4],'self':self,'ref':ref,'name':name}
        del self,ref,name
        return call.pop('callee')(call.pop('self'),call.pop('ref'),call.pop('name'))
    def retained_program(self,ref):
        note_retained(5)
        call={'callee':originals[5],'self':self,'ref':ref}
        del self,ref
        return call.pop('callee')(call.pop('self'),call.pop('ref'))
    began=time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ,runtime_environment))
        stack.enter_context(patch.object(native.ServiceBootstrapFrame,'__init__',counted_frame))
        stack.enter_context(patch.object(image,'_entry',counted_entry))
        stack.enter_context(patch.dict(api._SERVICE_BOOTSTRAP_REFERENCES,{1:retained_init,2:retained_close,3:retained_profiles,4:retained_profile,5:retained_program}))
        suite,actual=load_declared_suite(scope['modules'])
        if list(actual)!=planned:raise ValueError('runtime TestLoader differs from the complete pinned caller inventory')
        result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after=file_digests();stable=before==after
    stable=stable and compiler.read_bytes()==compiler_raw and manifest.read_bytes()==manifest_raw and (ROOT/FIXTURE).read_bytes()==raw
    success=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
             and started==planned and stopped==planned and stable and not selected_originals
             and sum(frames.values())>0 and sum(entries.values())>0
             and not boundary_errors and not saved_selectors and set(administrator_artifacts)==set(closed_ids)
             and all(not frames_by_test.get(name) and not entries_by_test.get(name) for name in closed_ids))
    report={'schema':'hepta.hia.service-bootstrap-complete-callers.v2','status':'PASS' if success else 'HOLD',
        'qualification_mode':mode,'scope':args.scope,'modules':scope['modules'],'planned':planned,
        'started':started,'stopped':stopped,'tests_run':result.testsRun,
        'failures':[x.id() for x,_ in result.failures],'errors':[x.id() for x,_ in result.errors],
        'skipped':[(x.id(),reason) for x,reason in result.skipped],
        'selected_retained_calls':selected_originals,'explicitly_unselected_retained_calls':unselected_originals,
        'frames_by_mode':dict(frames),'actual_entries_by_event':dict(entries),
        'frames_by_test':{key:dict(value) for key,value in frames_by_test.items()},
        'entries_by_test':{key:dict(value) for key,value in entries_by_test.items()},
        'closed_administrator_method_ids':closed_ids,'closed_administrator_boundaries':boundaries,
        'selection_boundary_errors':boundary_errors,'closed_administrator_artifacts':administrator_artifacts,
        'old_administrator_bundle_enlarged':False,'all_original_methods_claimed_bootstrap_selected':False,
        'source_before':before,'source_after':after,'source_unchanged':stable,
        'caller_source_admission':source_admission,
        'manifest_path':str(manifest),'manifest_sha256':sha256(manifest_raw).hexdigest(),
        'actual_image_sha256':image.image_sha256,'compiler_sha256':sha256(compiler_raw).hexdigest(),
        'elapsed_seconds':time.monotonic()-began,'outer_budget_seconds':scope['outer_seconds'],
        'old_admin_bundles_or_clear_environment_scopes_modified':False,'whole_native':False}
    (args.evidence/'report.json').write_bytes(canonical(report)+b'\n')
    raise SystemExit(0 if success else 1)
if __name__=='__main__':
    main()
