"""Real Git 65ce -> frozen Requests R2 -> exact 3291-file joint development.

Three independently reported jobs preserve the original R2 groups and deadlines.
The native job additionally repeats all frozen split-front observations. The
3.11 job retains original default callers and real zero-entry ABI refusal.
No prior result is inherited and no retained compiler grants current-cold status.
"""
from __future__ import annotations
import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import time
import traceback
import zipfile

import run_requests_development as r2
import joint_source as joint
from source_custody import digest, wire, write, metadata, files

EXPECTED_FRONT = (
    ('pure-source-projection/REPORT.json', None),
    ('controls-r3/RESULT.json', None),
    ('caller-matrix-r1/core-program-composite/REPORT.json',46),
    ('caller-matrix-r1/core-assembly/REPORT.json',18),
    ('caller-matrix-r1/assembly-assembly/REPORT.json',18),
    ('caller-matrix-r1/both-all/REPORT.json',64),
    ('caller-matrix-r1/default-all/REPORT.json',64),
    ('capture-controls-r2/REPORT.json',9),
    ('transport-controls-r3/REPORT.json',10),
    ('admission-controls-r2/REPORT.json',4),
    ('global-controls-r3/REPORT.json',3),
)

def collect_reports(work, specifications):
    result=[]
    for name,expected in specifications:
        path=work/name
        row={'path':name,'expected_tests':expected,'status':'MISSING'}
        if path.is_file():
            raw=path.read_bytes()
            try:
                value=json.loads(raw)
                count=value.get('tests_run')
                passed=value.get('status')=='PASS' and (expected is None or type(count) is int and count==expected)
                row.update(status='PASS' if passed else 'FAIL',bytes=len(raw),sha256=digest(raw),
                           actual_status=value.get('status'),tests_run=count)
            except BaseException:
                row.update(status='FAIL',traceback=traceback.format_exc(),sha256=digest(raw))
        result.append(row)
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--reference-source',type=Path)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--profile',choices=('native314','default311','source314'),required=True)
    args=parser.parse_args()
    checkout,inputs=args.source.resolve(strict=True),args.inputs.resolve(strict=True)
    work=args.workspace.absolute();work.mkdir(mode=0o700,exist_ok=False)
    (work/'snapshots').mkdir()
    before_inputs=files(inputs)
    source=compiler=None
    expected=None
    references={}
    held={}
    outcomes=[]
    required_reports=[]
    report={'schema':'hia.requests-front.actual-joint-development.v82.r3','status':'STARTED',
        'python':sys.version,'profile':args.profile,'commands':[],
        'original_r2_harness_commit':'8195d810dabb6f1ebdc993ae7372aa387d0d3853',
        'union_packet_blob':joint.UNION_BLOB,'union_tree':joint.UNION_TREE,
        'current_source_cold':False,'whole_native':False,'whole_normalization':False,
        'physical_recursion_closed':False,'production_activated':False,'legacy_deleted':False,
        'old_results_inherited':False,'original_work_limit_seconds':1800,
        'original_compiler_limit_seconds':20}
    started=time.monotonic_ns()
    environment=dict(os.environ)
    report['cleared_environment']=sorted(name for name in environment if name.startswith('HEPTA_'))
    for name in report['cleared_environment']:del environment[name]
    environment.update(PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1')

    def guard(label):
        actual=files(source)
        write(work/'snapshots'/(label+'-custody.json'),wire(actual))
        if actual!=expected:
            raise ValueError('complete 3291 frozen source changed: '+label)
        if files(inputs)!=before_inputs:
            raise ValueError('immutable harness input changed: '+label)
        for root,manifest in references.items():
            if files(root)!=manifest:
                raise ValueError('complete original reference/view changed: '+str(root))
        for path,identity in held.items():
            if metadata(path)!=identity:
                raise ValueError('held actual compiler/image/receipt/script changed: '+str(path))

    def group(label,tail,env=None,limit=1800):
        passed=r2.run_group(source,inputs,work,report,label,list(map(str,tail)),
                            environment if env is None else env,limit=limit)
        guard('after-'+label)
        outcomes.append({'label':label,'passed':passed})
        return passed

    def require(name,count=None):
        required_reports.append((name,count))

    try:
        version=(3,11) if args.profile=='default311' else (3,14,4)
        if (sys.implementation.name!='cpython' or platform.system()!='Linux'
                or platform.machine()!='x86_64' or sys.version_info[:len(version)]!=version
                or platform.freedesktop_os_release().get('ID')!='ubuntu'
                or platform.freedesktop_os_release().get('VERSION_ID')!='24.04'):
            raise ValueError('actual requested interpreter or Ubuntu24.04 x86-64 differs')
        report['packages']={name:importlib.metadata.version(name) for name in r2.PACKAGES}
        if report['packages']!=r2.PACKAGES:
            raise ValueError('original exact prerequisite versions differ')
        source,compiler,r2_source=r2.prepare(checkout,inputs,work,report)
        report['requests_r2_source_manifest']={n:r2.compact(v) for n,v in r2_source.items()}
        value,expected=joint.apply_union(source,inputs,report['requests_r2_source_manifest'])
        report['authored_source_files']=len(expected)
        report['authored_source_tree']=joint.tree_identity({n:r2.compact(v) for n,v in expected.items()})
        report['source_manifest']={n:r2.compact(v) for n,v in expected.items()}
        report['source_delta_paths']=list(value['files'])
        write(work/'FROZEN-SOURCE.json',wire(expected))
        environment['PYTHONPATH']=str(source)
        held[compiler]=metadata(compiler)
        held[work/'retained-B3.original-receipt.json']=metadata(work/'retained-B3.original-receipt.json')
        names,generators=joint.workflow_inventory(source)
        report['source_selectors']=list(names)
        report['generator_sequence']=generators
        guard('before-groups')

        if args.profile=='default311':
            group('default-import-and-abi-refusal',
                  [inputs/'default311.py',source,inputs/'local-image.json',work/'compatibility'])
            group('original-default-artifact-8',[inputs/'run_controls.py','--source',source,
                '--output',work/'default-control-observations','--expected','8',
                'tests.test_hia_agent_native_tools.ArtifactContractTests'])
            require('default-control-observations/REPORT.json',8)
            group('original-default-front-64',[inputs/'default64/run_default_compatibility_union.py',
                '--source',source,'--inputs',inputs/'default64',
                '--original-source-manifest',inputs/'default64/original-caller-sources.json',
                '--output',work/'default64-controls'])
            require('default64-controls/REPORT.json',64)
            group('default-front-import-boundary',[inputs/'front-original/probe_default_import_r3.py',
                '--source',source,'--output',work/'front-default-import'])
            require('front-default-import/REPORT.json')

        elif args.profile=='source314':
            for number,name in enumerate(generators):
                if not group('generator-'+str(number).zfill(3)+'-'+name,['-m','tools.generate_hia_'+name]):
                    raise ValueError('original complete generator sequence failed')
            for label,tail in (
                    ('core-only',['tools/check_hia_core_only.py']),
                    ('support-check',['tools/generate_hia_selfhost_contract.py','--check']),
                    ('language-regeneration',['tests/test_hia_selfhost_language_coverage.py','--generate-inventory'])):
                if not group(label,tail):
                    raise ValueError('original source prerequisite failed: '+label)
            group('complete-source-901',[inputs/'run_source901.py','--source',source,
                '--output',work/'source901-observations','--expected','901',
                '--expected-ids',inputs/'expected-source-901.json',*names])
            require('source901-observations/REPORT.json',901)

        else:
            # These original six R2 generation/check commands and their order are unchanged.
            commands=[['-m','tools.generate_hia_service_requests'],
                ['-m','tools.generate_hia_service_requests_foreign'],
                ['tests/test_hia_selfhost_language_coverage.py','--generate-inventory'],
                ['tools/generate_hia_selfhost_contract.py'],
                ['tools/generate_hia_selfhost_contract.py','--check'],['tools/check_hia_core_only.py']]
            for number,tail in enumerate(commands):
                if not group('generate-'+str(number),tail):
                    raise ValueError('original R2 generation/check failed')
            group('source-controls',[inputs/'run_controls.py','--source',source,
                '--output',work/'source-control-observations','--expected','40',*r2.NEW_SELECTORS])
            require('source-control-observations/REPORT.json',40)
            group('changed-compatibility-source-controls',[inputs/'run_controls.py','--source',source,
                '--output',work/'changed-compatibility-source-observations','--expected','27',*r2.COMPATIBILITY_SELECTORS])
            require('changed-compatibility-source-observations/REPORT.json',27)
            built=group('actual-build',['tools/build_hia_service_requests.py','--compiler',compiler,
                '--output',work/'image','--development'])
            if built:
                for path in sorted((work/'image').rglob('*')):
                    if path.is_file():held[path]=metadata(path)
                manifest=work/'image/development-manifest.json'
                native_env=dict(environment,HEPTA_HIA_SERVICE_REQUESTS_DEVELOPMENT_MANIFEST=str(manifest),
                    HEPTA_HIA_SERVICE_REQUESTS_EVIDENCE=str(work/'component-evidence'))
                group('native-controls',[inputs/'run_controls.py','--source',source,
                    '--output',work/'native-control-observations','--expected','11',
                    'tests.test_hia_service_requests_native.ServiceRequestsNativeTests'],native_env)
                require('native-control-observations/REPORT.json',11)
                for caller in ('agent','namespace','ledger'):
                    group('original-'+caller,['tools/qualify_hia_service_requests.py',
                        '--development-compiler',compiler,'--caller-group',caller,
                        '--evidence',work/('callers-'+caller)])
            else:
                report['blocked_requests_groups']=['native11','agent48','namespace35','ledger48']

            # Independent front gates still execute after any original Requests failure.
            if args.reference_source is None:
                raise ValueError('authentic original 64f67 reference checkout required')
            reference,reference_files=joint.prepare_front_reference(args.reference_source.resolve(strict=True),inputs,work)
            references[reference]=reference_files
            held.update(joint.prepare_front_scripts(inputs,work,compiler))
            guard('after-front-preparation')
            group('front-pure-source-projection',[work/'probe_source_projection.py',
                '--source',source,'--output',work/'pure-source-projection'])
            front_built=group('front-two-new-compilations',[work/'compile_split_ci.py'])
            build_path=work/'native-build-r1/RESULT.json'
            build=json.loads(build_path.read_bytes()) if build_path.is_file() else None
            report['front_native_build']=build
            if front_built and build is not None and build.get('status')=='DEVELOPMENT_TWO_IMAGES_BUILT':
                for path in sorted((work/'native-build-r1').rglob('*')):
                    if path.is_file():held[path]=metadata(path)
                group('front-original-controls',[work/'run_r3_controls.py'])
                group('front-global-anchor-controls',[work/'probe_split_globals_r3.py'])
                required_reports.extend(EXPECTED_FRONT)
            else:
                report['blocked_front_groups']=['original46/18/18/64/64','capture9','transport10','admission4','globals3']

            view,view_files=joint.prepare_binding_view(source,inputs,work,expected)
            references[view]=view_files
            before_binding=work/'binding-before.json'
            after_binding=work/'binding-after.json'
            group('four-foreign-bindings-before',[inputs/'probe_lazy_bindings_r2.py',
                '--source',view,'--role','before','--output',before_binding])
            group('four-foreign-bindings-after',[inputs/'probe_lazy_bindings_r2.py',
                '--source',source,'--role','after','--output',after_binding])
            binding=joint.compare_bindings(before_binding,after_binding)
            write(work/'BINDING64-COMPARISON.json',wire(binding))
            report['binding64_comparison']=binding

        guard('after-all-groups')
        report['required_group_reports']=collect_reports(work,required_reports)
        passed=(bool(outcomes) and all(row['passed'] for row in outcomes)
            and all(row['status']=='PASS' for row in report['required_group_reports'])
            and not report.get('blocked_requests_groups') and not report.get('blocked_front_groups'))
        report['status']='PASS' if passed else 'FAIL'
    except BaseException:
        report.update(status='FAIL',traceback=traceback.format_exc())
    finally:
        report['outcomes']=outcomes
        report['required_group_reports']=collect_reports(work,required_reports)
        try:
            if expected is not None:
                guard('final')
                report['final_inputs_and_source_unchanged']=True
            else:
                report['harness_inputs_unchanged']=files(inputs)==before_inputs
            if source is not None:
                observed=files(source)
                write(work/'FINAL-SOURCE.json',wire(observed))
                report['final_source_files']=len(observed)
                report['final_source_tree']=joint.tree_identity({n:r2.compact(v) for n,v in observed.items()})
        except BaseException:
            report.update(status='FAIL',custody_error=traceback.format_exc())
        report['elapsed_ns']=time.monotonic_ns()-started
        write(work/'REPORT.json',wire(report))
        raw_manifest={}
        for path in sorted(work.rglob('*')):
            relative=path.relative_to(work)
            if path.is_file() and relative.parts[0] not in ('source','binding-before-view'):
                raw_manifest[relative.as_posix()]=metadata(path)
        write(work/'RAW-MANIFEST.json',wire(raw_manifest))
        evidence=work/'COMPLETE-RAW.zip'
        with zipfile.ZipFile(evidence,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for name in sorted(raw_manifest):archive.write(work/name,name)
            archive.write(work/'RAW-MANIFEST.json','RAW-MANIFEST.json')
        with zipfile.ZipFile(evidence) as archive:
            if archive.testzip() is not None or len(archive.infolist())!=len(raw_manifest)+1:
                raise ValueError('complete raw evidence CRC or inventory differs')
            for name,identity in raw_manifest.items():
                raw=archive.read(name)
                if len(raw)!=identity['bytes'] or digest(raw)!=identity['sha256']:
                    raise ValueError('complete raw archive member changed')
        print(json.dumps({'status':report['status'],'profile':args.profile,
            'actual_commands':len(report['commands']),'evidence_bytes':evidence.stat().st_size,
            'union_tree':joint.UNION_TREE,'whole_native':False,'current_source_cold':False}),flush=True)
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
