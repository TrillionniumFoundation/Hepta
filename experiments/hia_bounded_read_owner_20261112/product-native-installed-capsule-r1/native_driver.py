"""One exact pure-product native gate and real offline installation under 180/3.

This is development verification, not a cold report or a whole-domain claim.
The outer original guardian is mandatory and independently accepted later.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import _create_directory, create, fixed_read, read, require, snapshot, wire
from native_support import (CANDIDATE, CANDIDATE_TREE, OWNER_SHA, load_fixed_module,
    observe_compiler_bundle, owned_step, source_manifest)
from git_binding import source_git


def environment():
    return {'PATH': os.environ.get('PATH',''), 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE':'1', 'PYTHONNOUSERSITE':'1'}


def controls(path, expected):
    raw, record = read(path, 1<<20)
    require(record['sha256'] == expected, 'actual control manifest differs')
    value = json.loads(raw)
    require(value['schema'] == 'hepta.hia.bounded-read-product-capsule-controls.v1'
            and value['candidate_commit'] == CANDIDATE and value['candidate_tree'] == CANDIDATE_TREE
            and value['outer_qualification_seconds'] == 180 and value['outer_cleanup_seconds'] == 3
            and value['dispatch_authorized_by_this_file'] is False,
            'fixed exact-candidate control request differs')
    actual = {name:fixed_read(path.parent/name,pin)[1] for name,pin in value['files'].items()}
    return value, record, actual


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--source-manifest',type=Path,required=True)
    parser.add_argument('--control-manifest',type=Path,required=True)
    parser.add_argument('--control-manifest-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    source,output,control=args.source_root,args.output,args.control_manifest.parent
    require(source.is_absolute() and output.is_absolute() and source!=output and source not in output.parents,
            'separate absolute source/evidence required')
    _create_directory(output)
    _create_directory(output/'processes')
    report={'schema':'hepta.hia.bounded-read-product-native-installation.v1','status':'HOLD',
        'candidate_commit':CANDIDATE,'candidate_tree':CANDIDATE_TREE,'errors':[],
        'processes':[],'finite_component_cases':55,'original_methods':8,'original_CLI_children':7,
        'original_CLI_timeout_seconds':20,'installed_case_ids':[],
        'outer_qualification_seconds_required':180,'outer_cleanup_seconds_required':3,
        'outer_guardian_verified_here':False,'fresh_B0_B1_B2_requested':True,
        'old_compiler_reused':False,'cold_qualification':False,'all_input_equivalence_proved':False,
        'whole_native_delivery_qualified':False,'source_mutation_authorized':False,
        'filesystem_and_context_operations_remain_hosted':True,
        'existing_general_installed_resource_suite_executed':False,
        'known_general_installed_resource_test_blockers':['Core expected resource range31 is stale in this v78 base',
            'the ABI descriptor must not be mapped by stem to a nonexistent native Python module']}
    before=rows=git_before=control_before=compiler_before=combined_before=None
    installation_started = False
    installation_closed = False
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and sys.version_info[:3]==(3,14,4) and os.getcwd()==str(source),
                'original isolated CPython target differs')
        require(not any(name.startswith(('HEPTA_HIA_','LD_')) or name in ('PYTHONPATH','PYTHONHOME')
                        for name in os.environ), 'ambient native selector or loader override')
        ctl,ctl_record,control_before=controls(args.control_manifest,args.control_manifest_sha256)
        report.update(control_manifest=ctl_record,control_before=control_before)
        rows,_,source_record=source_manifest(args.source_manifest)
        report['source_manifest']=source_record
        before=snapshot(source,rows)
        report['source_before']=create(output/'source-before.json',wire(before))
        git_before=source_git(source,rows)
        report['source_git_before']=git_before
        owner,owner_record=load_fixed_module('bounded_capsule_process_owner',control/'process_owner_impl.py',OWNER_SHA)
        report['process_owner_implementation']=owner_record
        python=str(Path(sys.executable).resolve(strict=True))
        fresh=[python,'-I','-S','-B',str(control/'prepare_native.py'),'--source-root',str(source),
               '--source-manifest',str(args.source_manifest),'--output',str(output/'compiler')]
        owned_step(owner,output/'processes',report,'fresh-compiler',fresh,source,environment(),60)
        raw,record=read(output/'compiler/report.json',8<<20)
        preparation=json.loads(raw)
        require(preparation['status']=='FRESH_B0_B1_B2_DEVELOPMENT_READY'
                and preparation['errors']==[] and preparation['source_preserved'] is True
                and preparation['source_git_before']==preparation['source_git_after']==git_before,
                'fresh current-source preparation did not complete')
        compiler_before=observe_compiler_bundle(source,output/'compiler')
        require(preparation['compiler_bundle_before']==preparation['compiler_bundle_after']==compiler_before,
                'actual complete fresh compiler lineage differs')
        compiler=output/'compiler/B2.image.bin'
        report['preparation']={'record':record,'compiler_bundle':compiler_before}
        finite=[python,'-I','-S','-B',str(source/'tools/qualify_hia_bounded_read.py'),
                '--compiler',str(compiler),'--development','--output',str(output/'finite')]
        owned_step(owner,output/'processes',report,'finite-gate',finite,source,environment(),180)
        # The independent reader below joins every raw group, original child,
        # compile output and nested owner. A producer status alone is not acceptance.
        from actions_verify import verify_finite
        report['finite']=verify_finite(source,output/'finite',compiler,python)
        combined_before=observe_compiler_bundle(source,output/'compiler',output/'finite/work/build')
        report['compiler_and_component_before']=combined_before
        from package_helper import run as install, IDS
        installation_started = True
        package=install(source,output,Path(python),output/'finite/work/build/bounded-read.image.bin',
            compiler,control/'installed_cases.py',
            source_sha256=read(source/'examples/hia_bootstrap/bounded_read.hiaasm',1<<20)[1]['sha256'],
            bridge_sha256=read(source/'hepta/hia_bounded_read_native.py',1<<20)[1]['sha256'],
            child_sha256=ctl['files']['installed_cases.py']['sha256'])
        require(package['status']=='DEVELOPMENT_INSTALLATION_PASS','actual offline installation did not pass')
        installation_closed = all(step.get('cleanup_closed_before_original_read') is True
                                  for step in package['processes'])
        require(installation_closed and len(package['processes']) == 5,
                'installation owners have not all closed')
        report['installed_case_ids']=list(IDS)
        report['installation']={
            'report':read(output/'installation/package-report.json',16<<20)[1],
            'installed_root':package['installed_root'],'manifest_path':package['manifest_path'],
            'case_report':package['installed_cases'],'case_request':package['installed_request'],
            'source_resource_count':105,'source_python_count':170,'native_source_resource_count':90,
            'case_methods':9,'native_read_returns':7,'scope':'DEVELOPMENT_INSTALLATION'}
        report['status']='BOUNDED_READ_PRODUCT_AND_INSTALLATION_PENDING_OUTER_GUARDIAN'
    except BaseException as error:
        report['status']='HOLD'
        report['errors'].append({'phase':'driver','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        try:
            report['all_started_inner_owners_closed']=all(
                item.get('cleanup_closed_before_original_read') is True for item in report['processes']) and (
                    not installation_started or installation_closed)
            # An unclosed nested product gate is not permission to inspect its
            # output tree. The outer finalizer owns later typed custody.
            require(report['all_started_inner_owners_closed'], 'defer live output until outer ECHILD')
            if rows is not None and before is not None:
                after=snapshot(source,rows)
                report['source_after']=create(output/'source-after.json',wire(after))
                require(after==before,'complete product source changed')
                report['source_preserved']=True
            if git_before is not None:
                report['source_git_after']=source_git(source,rows)
                require(report['source_git_after']==git_before,'exact Git source changed')
            if control_before is not None:
                _,_,report['control_after']=controls(args.control_manifest,args.control_manifest_sha256)
                require(report['control_after']==control_before,'frozen controls changed')
            if compiler_before is not None:
                report['compiler_after']=observe_compiler_bundle(source,output/'compiler')
                require(report['compiler_after']==compiler_before,'fresh compiler bundle changed')
            if combined_before is not None:
                report['compiler_and_component_after']=observe_compiler_bundle(source,output/'compiler',output/'finite/work/build')
                require(report['compiler_and_component_after']==combined_before,'actual component bundle changed')
            if report['status']=='BOUNDED_READ_PRODUCT_AND_INSTALLATION_PENDING_OUTER_GUARDIAN':
                require(report.get('source_preserved') is True and len(report['processes'])==2
                        and report['errors']==[] and len(report['installed_case_ids'])==9,
                        'final driver conjunction incomplete')
        except BaseException as error:
            report['status']='HOLD'
            report['errors'].append({'phase':'final','type':type(error).__name__,'traceback':traceback.format_exc()})
        create(output/'report.json',wire(report))
    print(json.dumps({'status':report['status'],'cold_qualification':False}),flush=True)
    return 0 if report['status']=='BOUNDED_READ_PRODUCT_AND_INSTALLATION_PENDING_OUTER_GUARDIAN' else 1


if __name__=='__main__':
    raise SystemExit(main())
