"""Complete original caller modules under explicit discovery selection.

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
FIXTURE='tests/fixtures/hia_service_discovery_original_r5/caller-scopes.json'
FIXTURE_SHA256='b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4'

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()

_DIAGNOSTICS_SOURCE = 'tests/hia_caller_diagnostics_admission.py'
_DIAGNOSTICS_SOURCE_PIN = {'bytes': 5185, 'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578'}
_DIAGNOSTICS_FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTICS_FIXTURE_PIN = {'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'}
_DIAGNOSTICS_CALLER = 'tests/test_hia_agent_native_tools.py'
_JOURNAL_CALLER = 'tests/test_hia_agent_journal_native.py'
_JOURNAL_HELPER = 'tests/hia_journal_installed_preparation.py'
_JOURNAL_HELPER_PIN = {'bytes': 15935, 'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797'}


def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def admit_original_scope(root, scope_name):
    """Keep the fixed complete callers, with two explicit source-only successors."""
    allowed = {'ordinary': 112, 'journal': 21, 'context': 15}
    if type(scope_name) is not str or scope_name not in allowed:
        raise ValueError('unknown complete discovery caller scope')
    root, captured = Path(root), {}

    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('discovery caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    frozen = capture(FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('caller scope bytes differ')
    scope = json.loads(frozen)['scopes'][scope_name]
    if len(scope['ordered_ids']) != allowed[scope_name]:
        raise ValueError('complete discovery caller count differs')
    diagnostics, journals = {}, {}
    for name, expected in scope['files'].items():
        raw = capture(name)
        if _source_pin(raw) == expected:
            continue
        if name == _DIAGNOSTICS_CALLER:
            helper, authority = capture(_DIAGNOSTICS_SOURCE), capture(_DIAGNOSTICS_FIXTURE)
            if (_source_pin(helper) != _DIAGNOSTICS_SOURCE_PIN
                    or _source_pin(authority) != _DIAGNOSTICS_FIXTURE_PIN):
                raise ValueError('discovery caller diagnostic authority changed')
            from tests import hia_caller_diagnostics_admission as diagnostic
            if Path(diagnostic.__file__).read_bytes() != helper or expected != diagnostic.ORIGINAL:
                raise ValueError('discovery caller imported a different diagnostic admission')
            diagnostics[name] = diagnostic.admit(name, raw, expected['sha256'], authority)
        elif name == _JOURNAL_CALLER:
            helper = capture(_JOURNAL_HELPER)
            if _source_pin(helper) != _JOURNAL_HELPER_PIN:
                raise ValueError('discovery caller Journal preparation helper changed')
            from tests import hia_journal_installed_preparation as journal
            if Path(journal.__file__).read_bytes() != helper:
                raise ValueError('discovery caller imported a different Journal admission')
            proof = journal.admit_source(root, name, raw, expected)
            for path, expected_capture in proof['captured_files'].items():
                if _source_pin(capture(path)) != expected_capture:
                    raise ValueError('discovery Journal source changed after admission: ' + path)
            journals[name] = proof
        else:
            raise ValueError('an original complete caller module changed: ' + name)
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('discovery caller captured bytes changed: ' + name)
    return scope, {
        'schema': 'hepta.hia.service-discovery-caller-source-admission.v1',
        'scope': scope_name, 'authority': {'path': FIXTURE, **_source_pin(frozen)},
        'original_files': dict(scope['files']), 'original_modules': list(scope['modules']),
        'original_ordered_ids': list(scope['ordered_ids']),
        'original_outer_seconds': scope['outer_seconds'],
        'reviewed_diagnostic_source_adjustments': diagnostics,
        'reviewed_journal_installed_preparation_source_adjustments': journals,
        'captured_files': {name: _source_pin(raw) for name, raw in captured.items()},
        'terminal_reread_identical': True, 'original_inventory_bytes_unchanged': True,
        'production_source_exceptions': [], 'whole_native': False,
    }


def bind_scope_admission_to_source_capture(proof, source_digests):
    for name, expected in proof['captured_files'].items():
        if source_digests.get(name) != expected['sha256']:
            raise ValueError('discovery caller admission differs from source capture: ' + name)


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
    scope,source_admission=admit_original_scope(ROOT,args.scope)
    raw=(ROOT/FIXTURE).read_bytes()
    from tools.hia_selfhost_contract import file_digests
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.build_hia_service_discovery import build
    from hepta import hia_agent_service as api,hia_service_discovery_native as native
    # The explicit import below is kept separate from corpus discovery.
    before=file_digests()
    bind_scope_admission_to_source_capture(source_admission,before)
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    if args.cold_report is not None:
        outer=json.loads(args.cold_report.read_bytes());nested=json.loads(Path(outer['nested_report']).read_bytes())
        compiler=Path(nested['generations'][-1]['produced_image'])
        manifest=build(args.evidence/'discovery',compiler,args.cold_report)
        mode='MATCHING_SOURCE_COLD_COMPLETE_CALLERS'
    else:
        compiler=args.development_compiler.resolve(strict=True)
        manifest=args.development_manifest.resolve(strict=True)
        mode='DEVELOPMENT_COMPLETE_CALLERS'
    compiler_raw=compiler.read_bytes();manifest_raw=manifest.read_bytes();manifest_value=json.loads(manifest_raw)
    if sha256(compiler_raw).hexdigest()!=manifest_value['compiler_sha256']:
        raise ValueError('caller image was not produced by its declared compiler')
    image=native.installed_service_discovery(str(manifest))
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
                    raise ValueError('journal and discovery were built by different compilers')
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
    initializer=native.ServiceDiscoveryFrame.__init__;entry=image._entry
    describe_original=api._SERVICE_DISCOVERY_DESCRIBE_REFERENCE
    examples_original=api._SERVICE_DISCOVERY_EXAMPLES_REFERENCE
    def counted_frame(frame,selected,*values,**kw):
        if selected is not image:raise AssertionError('caller selected an undeclared discovery image')
        initializer(frame,selected,*values,**kw);frames[str(frame.mode)]+=1
    def counted_entry(source,size,output,capacity,state,extent):
        request=struct.unpack('<16Q',ctypes.string_at(source,size))
        code=entry(source,size,output,capacity,state,extent)
        if code!=native.OUTPUT_BYTES or request[0]!=native.REQUEST_MAGIC:
            raise AssertionError('caller returned a different actual ABI')
        entries[str(request[1])]+=1;return code
    def retained_describe(self,args):
        if os.environ.get(native.SELECTOR) is not None:
            selected_originals.append(active[0]);raise AssertionError('selected describe used retained original')
        unselected_originals.append({'test':active[0],'mode':1})
        call={'callee':describe_original,'self':self,'args':args}
        del self,args
        return call.pop('callee')(call.pop('self'),call.pop('args'))
    def retained_examples():
        if os.environ.get(native.SELECTOR) is not None:
            selected_originals.append(active[0]);raise AssertionError('selected examples used retained original')
        unselected_originals.append({'test':active[0],'mode':2});return examples_original()
    began=time.monotonic()
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ,runtime_environment))
        stack.enter_context(patch.object(native.ServiceDiscoveryFrame,'__init__',counted_frame))
        stack.enter_context(patch.object(image,'_entry',counted_entry))
        stack.enter_context(patch.object(api,'_SERVICE_DISCOVERY_DESCRIBE_REFERENCE',retained_describe))
        stack.enter_context(patch.object(api,'_SERVICE_DISCOVERY_EXAMPLES_REFERENCE',retained_examples))
        suite,actual=load_declared_suite(scope['modules'])
        if list(actual)!=planned:raise ValueError('runtime TestLoader differs from the complete pinned caller inventory')
        result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after=file_digests();stable=before==after
    bind_scope_admission_to_source_capture(source_admission,after)
    stable=stable and compiler.read_bytes()==compiler_raw and manifest.read_bytes()==manifest_raw and (ROOT/FIXTURE).read_bytes()==raw
    success=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
             and started==planned and stopped==planned and stable and not selected_originals
             and sum(frames.values())>0 and sum(entries.values())>0)
    report={'schema':'hepta.hia.service-discovery-complete-callers.v1','status':'PASS' if success else 'HOLD',
        'qualification_mode':mode,'scope':args.scope,'modules':scope['modules'],'planned':planned,
        'caller_source_admission':source_admission,
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
