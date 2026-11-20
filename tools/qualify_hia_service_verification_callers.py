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

_DIAGNOSTICS_SOURCE = 'tests/hia_caller_diagnostics_admission.py'
_DIAGNOSTICS_SOURCE_PIN = {'bytes': 5185, 'sha256': '9e11b98d395229bcb38f0b36094da8bffb37e694ba1ad4afdfa998a8392dd578'}
_DIAGNOSTICS_FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
_DIAGNOSTICS_FIXTURE_PIN = {'bytes': 3545, 'sha256': '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'}
_DIAGNOSTICS_CALLER = 'tests/test_hia_agent_native_tools.py'
_JOURNAL_CALLER = 'tests/test_hia_agent_journal_native.py'
_JOURNAL_HELPER = 'tests/hia_journal_installed_preparation.py'
_JOURNAL_HELPER_PIN = {'bytes': 15935, 'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797'}


def _restore_journal_packaging_helper(raw):
    """Read the exact whole helper relation; no old source is executed."""
    if type(raw) is not bytes:
        raise ValueError('Journal packaging helper requires immutable complete bytes')
    actual = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    original_pin = {'bytes': 15935, 'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797'}
    current_pin = {'bytes': 18544, 'sha256': 'c42cb2fd0a0a6040cda6bc203d284e4bd0d5f6c7c2e76f71c50ba2113ee37aa4'}
    if actual == original_pin:
        return raw
    if actual != current_pin:
        raise ValueError('Journal packaging helper is not an exact reviewed source')
    pieces = (
        (9689, 9689, b'\n\ndef prepare_resources(root, original_resources):\n', b'\n\ndef _admit_package_policy(name, raw, expected):\n    """Accept the original policy or the exact extension-only v6 successor.\n\n    The 176 Agent, 17 capture and three integer resources are unchanged.\n    This is a whole-source inverse and replay, never a policy pin refresh.\n    """\n    if encoded(pin(raw)) == encoded(expected):\n        return\n    if (name != \'setup.py\' or encoded(expected) != encoded({\'bytes\': 4839, \'sha256\': \'be518d19561790ca7c07f54c70a3d98899b460ff717ca3d93c381cdbb5a2c89f\'})\n            or pin(raw) != {\'bytes\': 5398, \'sha256\': \'dbd27976a0d5e411da4c3affee239f66af03fcde22651237987b7a64acf330a8\'}):\n        raise ValueError(\'Journal current package policy changed: \' + name)\n    pieces = (\n        (873, 873, b\'ROOT=Path(__file__).resolve().parent\\n\', b\'_image_spec = spec_from_file_location(\\n    \\\'_hepta_native_carrier_build\\\', Path(__file__).resolve().parent / \\\'hepta/native/native_carrier_build.py\\\')\\n_image_build = module_from_spec(_image_spec)\\n_image_spec.loader.exec_module(_image_build)\\n\\nclass AllMechanicalBuildExt(_image_build.NativeCarrierBuildExt, MechanicalBuildExt):\\n    """Independent exact receipts; each original builder handles only its ABI."""\\n    pass\\n\\nROOT=Path(__file__).resolve().parent\\n\'),\n        (4632, 5048, b"setup(cmdclass={\'build_py\':AgentResourceBuild, \'build_ext\':MechanicalBuildExt},\\n      ext_modules=extensions(),\\n      package_data={\'hepta\': [\'native/slot_mechanical.c\', \'native/slot_mechanical_build.py\']})\\n", b"setup(cmdclass={\'build_py\':AgentResourceBuild, \'build_ext\':AllMechanicalBuildExt},\\n      ext_modules=extensions() + _image_build.extensions(),\\n      package_data={\'hepta\': [\'native/slot_mechanical.c\', \'native/slot_mechanical_build.py\',\\n                              \'native/native_image.c\', \'native/cell_frame.c\', \'native/native_carrier_build.py\']})\\n"),\n    )\n    original = raw\n    for old_at, new_at, before, after in reversed(pieces):\n        if original[new_at:new_at + len(after)] != after:\n            raise ValueError(\'Journal native-carrier setup inverse differs\')\n        original = original[:new_at] + before + original[new_at + len(after):]\n    if encoded(pin(original)) != encoded(expected):\n        raise ValueError(\'Journal native-carrier setup whole original differs\')\n    replay = original\n    for old_at, new_at, before, after in reversed(pieces):\n        if replay[old_at:old_at + len(before)] != before:\n            raise ValueError(\'Journal native-carrier setup replay segment differs\')\n        replay = replay[:old_at] + after + replay[old_at + len(before):]\n    if replay != raw:\n        raise ValueError(\'Journal native-carrier setup whole replay differs\')\n\n\n\ndef prepare_resources(root, original_resources):\n'),
        (10254, 12925, b"        if pin(_read(root, name, captured)) != expected:\n            raise ValueError('Journal current package policy changed: ' + name)\n", b'        _admit_package_policy(name, _read(root, name, captured), expected)\n'),
    )
    original = raw
    for old_at, new_at, old, new in reversed(pieces):
        if original[new_at:new_at + len(new)] != new:
            raise ValueError('Journal packaging helper inverse splice differs')
        original = original[:new_at] + old + original[new_at + len(new):]
    if {'bytes': len(original), 'sha256': sha256(original).hexdigest()} != original_pin:
        raise ValueError('Journal packaging helper did not restore its whole original')
    replay = original
    for old_at, new_at, old, new in reversed(pieces):
        if replay[old_at:old_at + len(old)] != old:
            raise ValueError('Journal packaging helper forward splice differs')
        replay = replay[:old_at] + new + replay[old_at + len(old):]
    if replay != raw:
        raise ValueError('Journal packaging helper whole forward replay differs')
    return original



def _source_pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def admit_original_scope(root, scope_name):
    """Keep the fixed complete callers, with two explicit source-only successors."""
    allowed = {'ordinary': 112, 'journal': 21}
    if type(scope_name) is not str or scope_name not in allowed:
        raise ValueError('unknown complete verification caller scope')
    root, captured = Path(root), {}

    def capture(name):
        raw = (root / name).read_bytes()
        if name in captured and captured[name] != raw:
            raise ValueError('verification caller source changed between captures: ' + name)
        captured[name] = raw
        return raw

    frozen = capture(FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('caller scope bytes differ')
    scope = json.loads(frozen)['scopes'][scope_name]
    if len(scope['ordered_ids']) != allowed[scope_name]:
        raise ValueError('complete verification caller count differs')
    diagnostics, journals = {}, {}
    for name, expected in scope['files'].items():
        raw = capture(name)
        if _source_pin(raw) == expected:
            continue
        if name == _DIAGNOSTICS_CALLER:
            helper, authority = capture(_DIAGNOSTICS_SOURCE), capture(_DIAGNOSTICS_FIXTURE)
            if (_source_pin(helper) != _DIAGNOSTICS_SOURCE_PIN
                    or _source_pin(authority) != _DIAGNOSTICS_FIXTURE_PIN):
                raise ValueError('verification caller diagnostic authority changed')
            from tests import hia_caller_diagnostics_admission as diagnostic
            if Path(diagnostic.__file__).read_bytes() != helper or expected != diagnostic.ORIGINAL:
                raise ValueError('verification caller imported a different diagnostic admission')
            diagnostics[name] = diagnostic.admit(name, raw, expected['sha256'], authority)
        elif name == _JOURNAL_CALLER:
            helper = capture(_JOURNAL_HELPER)
            if _source_pin(_restore_journal_packaging_helper(helper)) != _JOURNAL_HELPER_PIN:
                raise ValueError('verification caller Journal preparation helper changed')
            from tests import hia_journal_installed_preparation as journal
            if Path(journal.__file__).read_bytes() != helper:
                raise ValueError('verification caller imported a different Journal admission')
            proof = journal.admit_source(root, name, raw, expected)
            for path, expected_capture in proof['captured_files'].items():
                if _source_pin(capture(path)) != expected_capture:
                    raise ValueError('verification Journal source changed after admission: ' + path)
            journals[name] = proof
        else:
            raise ValueError('an original complete caller module changed: ' + name)
    for name, raw in captured.items():
        if (root / name).read_bytes() != raw:
            raise ValueError('verification caller captured bytes changed: ' + name)
    return scope, {
        'schema': 'hepta.hia.service-verification-caller-source-admission.v1',
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
            raise ValueError('verification caller admission differs from source capture: ' + name)


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
    scope,source_admission=admit_original_scope(ROOT,args.scope)
    raw=(ROOT/FIXTURE).read_bytes()
    from tools.hia_selfhost_contract import file_digests
    from tools.run_hia_unittest_gate import load_declared_suite
    from tools.build_hia_service_verification import build
    from hepta import hia_agent_service as api,hia_service_verification_native as native
    # The explicit import below is kept separate from corpus verification.
    before=file_digests()
    bind_scope_admission_to_source_capture(source_admission,before)
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
    bind_scope_admission_to_source_capture(source_admission,after)
    stable=stable and compiler.read_bytes()==compiler_raw and manifest.read_bytes()==manifest_raw and (ROOT/FIXTURE).read_bytes()==raw
    success=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
             and started==planned and stopped==planned and stable and not selected_originals
             and sum(frames.values())>0 and sum(entries.values())>0)
    report={'schema':'hepta.hia.service-verification-complete-callers.v1','status':'PASS' if success else 'HOLD',
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
