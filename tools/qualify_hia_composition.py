#!/usr/bin/env python3
"""One clean-source HIA/NDU/prover/toolchain qualification campaign.

Build the pinned NDU from source, freeze the resulting combination, then run
normal execution, negative admission, recovery, proofs and empirical gates.
Successful execution of an experiment is distinct from a positive result.
Every command is an outer wall-time measurement including startup and output.
This is reproducible research evidence, not production authorization.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_session import STREAM_PROFILE_PINS

SCHEMA = 'hepta.hia.source-composition.v3'
STREAM_PROFILE = 'zero-abstain-v1'
NDU_SOURCE_PIN = STREAM_PROFILE_PINS[STREAM_PROFILE]
REDUCTION_PROFILE = 'induction-multiload-v2'
CORE_TESTS = (
    'tests.test_hia_retained_evidence',
    'tests.test_cpp_upstream_host',
    'tests.test_hia_capability_flow', 'tests.test_hia_capability_identity',
    'tests.test_hia_capability_lifecycle',
    'tests.test_hia_capability_borrow',
    'tests.test_hia_composition_identity',
    'tests.test_hia_opcode_catalog',
    'tests.test_hia_program', 'tests.test_hia_execution_contract',
    'tests.test_hia_returned_loans', 'tests.test_hia_returned_loan_interfaces',
    'tests.test_hia_reduction_pipeline', 'tests.test_hia_reduction_release',
    'tests.test_hia_ndu_cost', 'tests.test_hia_host_region',
    'tests.test_hia_ndu_model_snapshot',
    'tests.test_hia_agent_repository_maintenance_v2',
    'tests.test_hia_agent_repository_v2_feedback_review',
    'tests.test_hia_agent_preflight',
    'tests.test_hia_agent_transport_framing',
    'tests.test_hia_agent_provider',
    'experiments.hia_agent_local_recovery_20261103.test_recovery',
    'tests.test_hia_durable_queue', 'tests.test_hia_durable_revision',
    'tests.test_hia_production_capability_witness',
    'tests.test_hia_ndu_current_profile',
    'tests.test_hia_reduction_induction', 'tests.test_hia_reduction_multiload',
    'tests.test_hia_empty_reduction', 'tests.test_hia_empty_reduction_observation',
    'tests.test_hia_empty_wrapper_candidate',
    'tests.test_hia_entry_layout', 'tests.test_hia_outlined_aot_protocol',
    'tests.test_hia_ndu_lazy_witness', 'tests.test_hia_ndu_controller_deadline', 'tests.test_hia_ndu_build_cost',
    'tests.test_hia_raw_session_cost', 'tests.test_hia_composition_raw_identity',
    'tests.test_cpp_gsl_final_action', 'tests.test_cpp_gsl_current_release',
    'tests.test_hia_agent_factorial', 'tests.test_hia_agent_edit_factorial',
    'tests.test_cpp_unique_reuse.UniqueReuseProfileTests.test_profile_flag_is_exact_boolean',
    'tests.test_modules.PackageTests.test_source_directory_alias_rejected_before_locking',
    'tests.test_modules.PackageTests.test_directory_alias_added_after_lock_rejects_locked_load',
    'tests.test_modules.PackageTests.test_nested_and_dependency_directory_links_rejected',
    'tests.test_modules.PackageTests.test_directory_link_escape_rejected',
    'tests.test_modules.PackageTests.test_regular_source_file_symlinks_remain_content_locked',
    'tests.test_modules.PackageTests.test_snapshot_is_portable_and_deterministic',
    'tests.test_modules.PackageTests.test_lock_missing_and_source_changes_fail',
    'tests.test_modules.PackageTests.test_dependency_source_changes_fail_lock',
)


def digest(path):
    h = sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024*1024), b''):
            h.update(data)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True, timeout=20).strip()


def source_identity():
    status = git('status', '--porcelain', '--untracked-files=all')
    if status:
        raise ValueError('source must be clean and committed before qualification: '+status[:1000])
    # The full Git tree pins sparse/unmaterialized historical artifacts too.
    # Hash every materialized active source/fixture; never hash build outputs.
    included = ('hepta/', 'tools/', 'tests/', 'formal/', 'benchmarks/', 'rust/', '.cargo/',
                'examples/', '.github/', 'experiments/')
    tracked = subprocess.check_output(['git','ls-files','-z'],cwd=ROOT,text=True,timeout=20).split('\0')
    paths = [name for name in tracked if name.startswith(included) and (ROOT/name).is_file()]
    roots = [name for name in ('pyproject.toml', 'toolchain-lock.json', 'rust-toolchain.toml')
             if (ROOT/name).is_file()]
    paths = sorted(set(paths+roots))
    if not paths or 'hepta/hia_program.py' not in paths or 'tools/qualify_hia_composition.py' not in paths:
        raise ValueError('missing tracked implementation identity')
    tree = {}
    for entry in subprocess.check_output(['git','ls-tree','-rz','HEAD'],cwd=ROOT,timeout=20).split(b'\0'):
        if entry:
            header,name=entry.split(b'\t',1)
            mode,kind,identity=header.decode().split()
            tree[name.decode()] = (mode,kind,identity)
    actual = {}
    for name in paths:
        path=ROOT/name
        if path.is_symlink():
            raise ValueError('active source symlink is outside this composition profile: '+name)
        raw=path.read_bytes()
        mode,kind,expected=tree.get(name,('','',''))
        observed=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if kind!='blob' or mode not in {'100644','100755'} or observed!=expected:
            raise ValueError('materialized source differs from HEAD blob: '+name)
        actual[name]=sha256(raw).hexdigest()
    return {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
            'materialized_files_sha256': actual,
            'clean': True, 'sparse_checkout': git('config', '--get', 'core.sparseCheckout') == 'true'
            if subprocess.run(['git','config','--get','core.sparseCheckout'],cwd=ROOT,
                              stdout=subprocess.DEVNULL).returncode == 0 else False}


def executable(path):
    found = shutil.which(str(path))
    if found is None:
        raise ValueError('missing tool: '+str(path))
    invocation = Path(found).absolute()
    resolved = invocation.resolve(strict=True)
    # argv[0] selects Clang's C++ driver and Rust's rustup dispatch.
    # Hash the target, but execute and retain the actual invocation path.
    result = subprocess.run([str(invocation), '--version'], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ValueError('tool did not execute: '+str(path))
    return {'path': str(invocation), 'resolved_path': str(resolved), 'sha256': digest(resolved),
            'version': (result.stdout+result.stderr).strip()}


def tool_identity(args):
    result = {name: executable(getattr(args,name)) for name in
              ('clang','clangxx','rustc','cargo','cc','lean')}
    result.update({name:executable(name) for name in ('g++','ld','nm','objdump','readelf')})
    result['python'] = executable(sys.executable)
    if 'clang version 20.' not in result['clang']['version'] or 'clang version 20.' not in result['clangxx']['version']:
        raise ValueError('this campaign requires the explicit Clang 20 profile')
    if not result['rustc']['version'].startswith('rustc 1.95.0 '):
        raise ValueError('this campaign requires Rust 1.95.0, not the historical 1.90 profile')
    lock = json.loads((ROOT/'formal/toolchain-lock.json').read_text())
    if result['lean']['sha256'] != lock['lean_binary_sha256']:
        raise ValueError('Lean binary differs from pinned formal lock')
    import z3
    from hepta.hia_optimization import _solver_identity
    if z3.get_version_string() != '4.15.4':
        raise ValueError('this campaign requires Z3 4.15.4')
    result['z3'] = _solver_identity(z3)
    return result


def unchanged(source, tools, frozen=None):
    try:
        if source_identity() != source:
            return False
        import z3
        from hepta.hia_optimization import _solver_identity
        if _solver_identity(z3) != tools['z3']:
            return False
        if any(digest(path)!=expected for path,expected in (frozen or {}).items()):
            return False
        return all(digest(item['path']) == item['sha256']
                   and str(Path(item['path']).resolve(strict=True)) == item.get('resolved_path',str(Path(item['path']).resolve(strict=True)))
                   for item in tools.values()
                   if isinstance(item,dict) and 'path' in item and 'sha256' in item)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        return False


def validate_raw_build(path, tools):
    """Bind the second protocol to a fresh build of this exact adapter/toolchain."""
    path = Path(path).resolve()
    manifest = json.loads(path.read_text())
    from tools.measure_hia_raw_model_cost import build_cost_observation
    observed_cost = build_cost_observation(manifest,path)
    adapter = ROOT / 'rust/hia-ndu-raw-model'
    files = {str(p.relative_to(adapter)):digest(p) for p in sorted(adapter.rglob('*')) if p.is_file()}
    required_true = ('original_rust_sources_unchanged', 'all_original_non_manifest_inputs_unchanged',
                     'build_inputs_unchanged', 'locked_dependencies', 'isolated_production_manifests')
    cost, command = manifest.get('build_cost', {}), manifest.get('build_command_evidence', {})
    binary = Path(manifest.get('binary', '')).resolve(strict=True)
    expected_command = [tools['cargo']['path'],'build','--manifest-path',str(path.parent/'Cargo.toml'),
                        '-p','hia-ndu-bridge','--locked','--release']
    if (manifest.get('schema') != 'hepta.hia.ndu-build.v1'
            or manifest.get('upstream', {}).get('commit') != NDU_SOURCE_PIN
            or not all(manifest.get(k) is True for k in required_true)
            or not files or manifest.get('adapter_files') != files
            or manifest.get('builder_sha256') != digest(ROOT/'tools/build_hia_ndu_bridge.py')
            or manifest.get('rustc_version', '').partition('\n')[0] != tools['rustc']['version']
            or manifest.get('cargo_version') != tools['cargo']['version']
            or manifest.get('binary_sha256') != digest(binary)
            or manifest.get('production_activation') is not False
            or cost.get('completed') is not True or type(cost.get('wall_ns')) is not int
            or cost['wall_ns'] <= 0 or observed_cost['wall_ns'] != cost['wall_ns']
            or cost.get('target_cache_at_start') != 'absent'
            or command.get('returncode') != 0 or command.get('launch_error') is not None
            or command.get('original_streams_retained') is not True
            or command.get('argv') != manifest.get('build_command')
            or command.get('argv') != expected_command or command.get('cwd') != str(ROOT)):
        raise ValueError('raw native build differs from the registered source/toolchain/empty target')
    for stream in ('stdout', 'stderr'):
        item = command.get(stream, {})
        logfile = (path.parent / item.get('path', '')).resolve(strict=True)
        if (not logfile.is_relative_to(path.parent) or not logfile.is_file()
                or logfile.stat().st_size != item.get('bytes') or digest(logfile) != item.get('sha256')):
            raise ValueError('raw build original command stream changed')
    return manifest


def run_command(directory, name, argv, *, timeout=1200, environment=None):
    stdout, stderr = directory/(name+'.stdout'), directory/(name+'.stderr')
    started = time.monotonic_ns()
    row = {'name': name, 'argv': [str(x) for x in argv], 'timeout_seconds': timeout,
           'started_unix_ns': time.time_ns()}
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    env.update(environment or {})
    row['explicit_environment'] = dict(environment or {})
    with stdout.open('xb') as out, stderr.open('xb') as err:
        row.update(returncode=None,timed_out=False,launch_error=None)
        try:
            proc = subprocess.Popen(row['argv'], cwd=ROOT, env=env, stdout=out, stderr=err,
                                    start_new_session=True)
        except OSError as error:
            row['launch_error'] = {'type':type(error).__name__,'message':str(error)}
        else:
            try:
                row['returncode'] = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                row['returncode'] = proc.wait(timeout=10)
                row['timeout_group_killed_before_reap'] = True
    row['wall_ns'] = time.monotonic_ns()-started
    row['logs'] = {p.name: {'bytes':p.stat().st_size,'sha256':digest(p)} for p in (stdout,stderr)}
    write(directory/(name+'.command.json'),row)
    return row


def regression_suite(output):
    import unittest
    from tools.qualify_hia_three_lane import _IdentityRecordingResult, _planned_test_ids
    suite = unittest.defaultTestLoader.loadTestsFromNames(CORE_TESTS)
    expected = _planned_test_ids(suite)
    result = unittest.TextTestRunner(verbosity=2, resultclass=_IdentityRecordingResult).run(suite)
    passed = (len(expected)>0 and result.wasSuccessful() and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses
              and tuple(result.started_ids)==expected and tuple(result.finished_ids)==expected)
    report = {'passed':passed, 'tests':result.testsRun, 'planned':list(expected),
              'started':result.started_ids,'finished':result.finished_ids,
              'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped)}
    write(output,report)
    return passed


def qualify(args):
    if sys.flags.optimize != 0:
        raise ValueError('qualification requires Python assertion checks enabled')
    started = time.monotonic_ns()
    output = Path(args.output).resolve()
    if output.is_relative_to(ROOT) or output.exists():
        raise ValueError('new output directory outside the source worktree required')
    source, tools = source_identity(), tool_identity(args)
    output.mkdir(parents=True)
    ledger = output/'commands'; ledger.mkdir()
    plan = {'schema':SCHEMA,'source':source,'tools':tools,'ndu_source_pin':NDU_SOURCE_PIN,
            'ndu_stream_profile':STREAM_PROFILE,'reduction_profile':REDUCTION_PROFILE,
            'registered_unix_ns':time.time_ns(),'host':{'system':platform.system(),
            'machine':platform.machine(),'release':platform.release()},
            'lanes':['core','capability_proof','capability_lifecycle','capability_borrow','memory_proof','core_proof','register_proof',
                     'production_capabilities','sequential_core','ndu_budget_model',
                     'continuation','reduction','ndu_full_cost','cpp_unique_reset','cpp_source_refusals',
                     'gsl_upstream_upgrade','migration_resources','host_region','agent_tool_controls',
                     'ndu_model_planner','ndu_lazy_witness','outlined_aot','raw_ndu_correctness','raw_ndu_service_cost',
                     'cpp_unique_reuse','cpp_reuse_source_refusals'],
            'raw_ndu_profile':'raw-model-v1; separate executable and protocol, same upstream pin',
            'raw_ndu_object_source':str(Path(args.ndu_object_source or args.ndu_source).resolve()),
            'proof_scope':'general model theorems, selected-program all-input checks and finite tests are distinct; syntax-kernel research branch is not silently included',
            'hardware_scope':'Linux x86_64 host-region execution and lifecycle controls; no device/DMA guarantee',
            'performance_results_are_not_assumed_positive':True,
            'general_agent_advantage_gate':'separate complete prospective model study required',
            'authority':'DENY_ALL','safety_certificate':False}
    write(output/'PLAN.json',plan)
    frozen={str(output/'PLAN.json'):digest(output/'PLAN.json')}
    execution_env={'PYTHONOPTIMIZE':'0','CARGO_HOME':str(Path(args.cargo_home).resolve()),
                   'CARGO_TARGET_DIR':str(output/'rust-shadow-target'),
                   'RUSTC':tools['rustc']['path'],'CLANG':tools['clang']['path'],
                   'CLANGXX':tools['clangxx']['path'],'HEPTA_CLANG':tools['clang']['path'],
                   'HEPTA_TEST_CLANG':tools['clang']['path'],
                   'HIA_TEST_CLANG20':tools['clang']['path'],
                   'PATH':os.pathsep.join((str(Path(tools['clang']['path']).parent),
                                          str(Path(tools['cargo']['path']).parent),os.environ.get('PATH','')))}
    rows = []
    passed = {}
    def step(name,command,timeout=1200,environment=None):
        if not unchanged(source,tools,frozen):
            raise ValueError('composition source or tools changed before '+name)
        row = run_command(ledger,name,command,timeout=timeout,environment={**execution_env,**(environment or {})}); rows.append(row)
        if not unchanged(source,tools,frozen):
            raise ValueError('composition source or tools changed during '+name)
        return row['returncode']==0 and not row['timed_out']
    py = [sys.executable,'-B']
    try:
        build_command = py+['tools/measure_hia_ndu_build.py','--output',str(output/'ndu-build'),
            '--ndu-source',str(Path(args.ndu_source).resolve()),'--target-dir',str(output/'cargo-target'),
            '--cargo',tools['cargo']['path'],'--rustc',tools['rustc']['path'],
            '--cargo-home',str(Path(args.cargo_home).resolve()),'--expected-source',NDU_SOURCE_PIN]
        if args.offline:
            build_command.append('--offline')
        if not step('ndu-build',build_command):
            raise ValueError('fixed native NDU failed to build; see retained command evidence')
        identity = output/'ndu-build/build/identity.json'
        manifest = json.loads(identity.read_text())
        bridge = Path(manifest['binary']).resolve()
        if (manifest['identity']['source_commit']!=NDU_SOURCE_PIN or
                manifest['identity']['rustc']!=tools['rustc']['version'] or
                manifest['binary_sha256']!=digest(bridge)):
            raise ValueError('NDU output does not belong to the registered composition')
        raw_build = output/'raw-ndu-build'
        raw_receipt = raw_build/'build-receipt.json'
        if not step('raw-ndu-build', py+['tools/build_hia_raw_model_bridge.py',
                '--upstream',str(Path(args.ndu_object_source or args.ndu_source).resolve()),
                '--output',str(raw_build),'--cargo',tools['cargo']['path']],
                environment={'CARGO_TARGET_DIR':str(output/'raw-cargo-target'),
                             'CARGO_NET_OFFLINE':'true' if args.offline else 'false',
                             'GIT_NO_LAZY_FETCH':'1'}):
            raise ValueError('raw native NDU failed to build; original streams retained')
        raw_manifest = validate_raw_build(raw_receipt,tools)
        raw_bridge = Path(raw_manifest['binary']).resolve()
        combination = {**plan, 'ndu_build_identity_sha256':digest(identity),
                       'ndu':manifest, 'raw_ndu':raw_manifest,
                       'raw_ndu_build_receipt_sha256':digest(raw_receipt),
                       'plan_sha256':digest(output/'PLAN.json')}
        write(output/'COMBINATION.json',combination)
        frozen.update({str(identity):digest(identity),str(bridge):digest(bridge),
                       str(raw_receipt):digest(raw_receipt),str(raw_bridge):digest(raw_bridge),
                       str(output/'COMBINATION.json'):digest(output/'COMBINATION.json')})
        fetch=[tools['cargo']['path'],'fetch','--locked','--manifest-path',str(ROOT/'rust/hia-core-shadow/Cargo.toml')]
        if args.offline:
            fetch.append('--offline')
        passed['rust_shadow_dependencies']=step('rust_shadow_dependencies',fetch)
        passed['rust_shadow_build']=step('rust_shadow_build',[
            tools['cargo']['path'],'build','--release','--locked','--offline',
            '--manifest-path',str(ROOT/'rust/hia-core-shadow/Cargo.toml')])
        passed['core'] = step('core',py+['tools/qualify_hia_composition.py','--regression-output',str(output/'CORE.json')])
        for name,script,target in (
            ('capability_proof','verify_hia_capabilities.py','CAPABILITY_PROOF.json'),
            ('memory_proof','verify_memory.py','MEMORY_PROOF.json'),
            ('core_proof','verify_formal.py','CORE_PROOF.json')):
            passed[name] = step(name,py+['tools/'+script,'--lean',tools['lean']['path'],'--output',str(output/target)])
        passed['capability_lifecycle'] = step('capability_lifecycle',py+[
            'tools/verify_hia_capability_lifecycle.py','--lean',tools['lean']['path'],
            '--output',str(output/'capability-lifecycle')])
        passed['capability_borrow'] = step('capability_borrow',py+[
            'tools/verify_hia_capability_borrow.py','--lean',tools['lean']['path'],
            '--output',str(output/'capability-borrow')])
        passed['register_proof'] = step('register_proof',py+['tools/qualify_hia_register_safety.py',
            '--lean',tools['lean']['path'],'--output-directory',str(output/'register-proof')])
        shadow = output/'rust-shadow-target/release/hia-core-shadow'
        if passed['rust_shadow_build']:
            frozen[str(shadow)] = digest(shadow)
            passed['production_capabilities'] = step('production_capabilities',py+[
                'tools/verify_hia_capabilities.py','--lean',tools['lean']['path'],
                '--production-output-directory',str(output/'production-capabilities'),
                '--rust-shadow',str(shadow),'--rust-shadow-sha256',frozen[str(shadow)]])
        else:
            passed['production_capabilities'] = False
        passed['sequential_core'] = step('sequential_core',py+['tools/qualify_hia_sequential_core.py',
            '--core',str(ROOT/'formal/selected_sequential_u32.hia.json'),
            '--output',str(output/'sequential-core'),'--timeout-ms','30000'])
        passed['ndu_budget_model'] = step('ndu_budget_model',[
            tools['lean']['path'],str(ROOT/'formal/HiaNduBudgetErasure.lean')])
        passed['continuation'] = step('continuation',py+['tools/qualify_hia_continuation.py',
            '--workdir',str(output/'continuation'),'--clang',tools['clang']['path']])
        passed['reduction'] = step('reduction',py+['tools/qualify_hia_reduction_release.py',
            '--output',str(output/'reduction'),'--clang',tools['clang']['path'],'--rustc',tools['rustc']['path'],
            '--profile',REDUCTION_PROFILE])
        passed['outlined_aot'] = step('outlined_aot',py+['tools/qualify_hia_outlined_aot.py',
            '--output',str(output/'outlined-aot'),'--clang',tools['clang']['path'],'--rustc',tools['rustc']['path']])
        passed['ndu_full_cost'] = step('ndu_full_cost',py+['tools/qualify_hia_ndu_cost.py',
            '--output',str(output/'ndu-cost'),'--clang',tools['clang']['path'],'--rustc',tools['rustc']['path'],
            '--bridge',str(bridge),'--identity',str(identity),'--bridge-built-this-campaign',
            '--stream-profile',STREAM_PROFILE])
        passed['ndu_lazy_witness'] = step('ndu_lazy_witness',py+['tools/qualify_hia_ndu_lazy_witness.py',
            '--expected-source',source['commit'],'--bridge',str(bridge),'--identity',str(identity),
            '--output',str(output/'ndu-lazy-witness')])
        passed['raw_ndu_correctness'] = step('raw_ndu_correctness',py+['tools/qualify_hia_raw_model.py',
            '--binary',str(raw_bridge),'--build',str(raw_receipt),
            '--output',str(output/'raw-correctness'),'--include-stream'])
        raw_cost = output/'raw-service-cost'
        passed['raw_ndu_service_freeze'] = step('raw_ndu_service_freeze',py+[
            'tools/measure_hia_raw_session_cost.py','freeze','--binary',str(raw_bridge),
            '--build',str(raw_receipt),'--output',str(raw_cost)])
        if passed['raw_ndu_service_freeze']:
            frozen[str(raw_cost/'REGISTRATION.json')] = digest(raw_cost/'REGISTRATION.json')
            passed['raw_ndu_service_cost'] = step('raw_ndu_service_cost',py+[
                'tools/measure_hia_raw_session_cost.py','run','--output',str(raw_cost)])
        else:
            passed['raw_ndu_service_cost'] = False
        passed['cpp_unique_reset'] = step('cpp_unique_reset',py+['tools/qualify_cpp_unique_reset.py',
            '--workdir',str(output/'cpp-unique-reset'),'--clang',tools['clang']['path'],
            '--clangxx',tools['clangxx']['path'],'--cc',tools['cc']['path']])
        passed['cpp_source_refusals'] = step('cpp_source_refusals',py+['tools/qualify_cpp_unique_reset.py',
            '--source-refusals-only','--workdir',str(output/'cpp-source-refusals'),
            '--clangxx',tools['clangxx']['path'],'--clang',tools['clang']['path'],'--cc',tools['cc']['path']])
        passed['cpp_unique_reuse'] = step('cpp_unique_reuse',py+['tools/qualify_cpp_unique_reuse.py',
            '--workdir',str(output/'cpp-unique-reuse'),'--clang',tools['clang']['path'],
            '--clangxx',tools['clangxx']['path'],'--cc',tools['cc']['path']])
        passed['cpp_reuse_source_refusals'] = step('cpp_reuse_source_refusals',py+['tools/qualify_cpp_unique_reuse.py',
            '--source-refusals-only','--workdir',str(output/'cpp-reuse-source-refusals'),
            '--clangxx',tools['clangxx']['path'],'--clang',tools['clang']['path'],'--cc',tools['cc']['path']])
        passed['gsl_upstream_upgrade'] = step('gsl_upstream_upgrade',py+['tools/qualify_cpp_gsl_final_action.py',
            '--output',str(output/'gsl-upgrade'),'--clang',tools['clang']['path'],
            '--cxx',tools['g++']['path'],'--cc',tools['cc']['path'],'--include-current-upstream'])
        passed['migration_resources'] = step('migration_resources',py+['tools/qualify_migration_resource_profiles.py',
            '--output',str(output/'migration-resources'),'--clang',tools['clang']['path'],
            '--cxx',tools['g++']['path'],'--cc',tools['cc']['path']])
        passed['host_region'] = step('host_region',py+['tools/qualify_hia_host_region.py',
            '--output',str(output/'host-region'),'--clang',tools['clang']['path']])
        passed['agent_tool_controls'] = step('agent_tool_controls',py+['tools/qualify_hia_agent_repository_maintenance_v2.py',
            'controls','--output',str(output/'agent-controls'),'--clang',tools['clang']['path']])
        passed['ndu_model_planner'] = step('ndu_model_planner',py+['tools/qualify_hia_ndu_budget_erasure.py',
            '--output',str(output/'ndu-model-planner')])
        report = {'status':'completed','qualifications':passed,'qualification_commands_passed':all(passed.values()),
                  'p0_same_combination_build_execute_reject_cancel_recover':all(passed.get(k,False) for k in
                      ('rust_shadow_dependencies','rust_shadow_build','core',
                       'capability_proof','capability_lifecycle','capability_borrow','memory_proof','core_proof','register_proof',
                       'production_capabilities','sequential_core','ndu_budget_model',
                       'continuation','reduction','outlined_aot','ndu_full_cost','ndu_model_planner','ndu_lazy_witness','host_region',
                       'raw_ndu_correctness','raw_ndu_service_cost','cpp_unique_reuse','cpp_reuse_source_refusals',
                       'gsl_upstream_upgrade')),
                  'all_seven_research_targets_closed':False,
                  'capability_lifecycle_assessment':'capability-lifecycle/REPORT.json',
                  'capability_borrow_assessment':'capability-borrow/REPORT.json',
                  'performance_assessment':'reduction/RESULT.json',
                  'outlined_performance_assessment':'outlined-aot/RESULT.json',
                  'raw_ndu_assessment':'raw-service-cost/RESULT.json',
                  'ndu_lazy_witness_assessment':'ndu-lazy-witness/RESULT.json',
                  'ndu_assessment':'ndu-cost/REPORT.json',
                  'ndu_model_planner_assessment':'ndu-model-planner/RESULT.json'}
        if passed['raw_ndu_service_cost']:
            raw = json.loads((raw_cost/'RESULT.json').read_text())
            commands = {row['name']:row['wall_ns'] for row in rows}
            services = {name:value['standalone_service_ns'] for name,value in raw['arms'].items()}
            inner_build = raw_manifest['build_cost']['wall_ns']
            outer_build = commands['raw-ndu-build']
            runner_remainder = commands['raw_ndu_service_cost'] - sum(services.values())
            if outer_build < inner_build or runner_remainder < 0:
                raise ValueError('raw service outer/inner nonoverlapping cost clocks disagree')
            shared = runner_remainder + commands['raw_ndu_service_freeze']
            report['raw_ndu_outer_cost_completion'] = {
                'native_build_outer_wall_ns':outer_build,'native_build_inner_wall_ns':inner_build,
                'native_build_additional_charged_ns':outer_build-inner_build,
                'whole_service_command_wall_ns':commands['raw_ndu_service_cost'],
                'registration_command_wall_ns':commands['raw_ndu_service_freeze'],
                'common_runner_and_registration_remainder_ns':shared,
                'conservative_solo_service_cost_by_arm_ns':{
                    name:outer_build+service+shared for name,service in services.items()},
                'allocation_rule':'Each descriptive standalone service pays the complete observed outer build, its service, and all common caller/registration remainder once.',
                'not_an_independently_executed_solo_campaign':True,
                'application_execution_included':False,'historical_preparation_or_human_cost_ns':None}
        if passed['ndu_full_cost']:
            ndu=json.loads((output/'ndu-cost/REPORT.json').read_text())
            command_cost={row['name']:row['wall_ns'] for row in rows}
            inner_build=manifest['build_cost']['wall_ns']
            outer_build=command_cost['ndu-build']
            service_sum=sum(row['service_wall_ns'] for row in ndu['episodes'])
            if outer_build<inner_build or command_cost['ndu_full_cost']<ndu['offline_wall_ns']+service_sum:
                raise ValueError('outer/inner cost clocks or nonoverlapping phase accounting disagree')
            common_remainder=command_cost['ndu_full_cost']-ndu['offline_wall_ns']-service_sum
            totals={name:value+common_remainder+((outer_build-inner_build) if name=='native_ndu' else 0)
                    for name,value in ndu['shared_cost_policy']['arm_full_cost_ns'].items()}
            report['ndu_outer_cost_completion']={
                'native_build_outer_wall_ns':outer_build,'native_build_inner_wall_ns':inner_build,
                'native_build_additional_charged_ns':outer_build-inner_build,
                'whole_qualification_command_wall_ns':command_cost['ndu_full_cost'],
                'common_unallocated_runner_overhead_ns':common_remainder,
                'conservative_solo_campaign_cost_by_policy_ns':totals,
                'allocation_rule':'Every policy pays the full common campaign remainder once; native additionally pays outer minus inner bridge build. Original nested report is retained unchanged.',
                'not_an_independently_executed_solo_campaign':True}
    except Exception as error:
        report = {'status':'failed','qualification_commands_passed':False,'qualifications':passed,
                  'p0_same_combination_build_execute_reject_cancel_recover':False,
                  'error':{'type':type(error).__name__,'message':str(error)},
                  'all_seven_research_targets_closed':False}
    report.update(schema=SCHEMA,source=source,commands=rows,
                  source_and_tools_unchanged=unchanged(source,tools,frozen),
                  frozen_artifacts_sha256=frozen,
                  elapsed_ns=time.monotonic_ns()-started,
                  cost_scope='outer child command walls include startup/imports/final output; nested costs must not be added twice',
                  authority='DENY_ALL',safety_certificate=False)
    if not report['source_and_tools_unchanged']:
        report['qualification_commands_passed']=False
        report['p0_same_combination_build_execute_reject_cancel_recover']=False
    write(output/'RESULT.json',report)
    return report


def main():
    if sys.flags.optimize != 0:
        raise ValueError('qualification requires Python assertion checks enabled')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--regression-output',type=Path)
    for name in ('output','ndu-source','cargo-home','clang','clangxx','rustc','cargo','cc','lean'):
        parser.add_argument('--'+name)
    parser.add_argument('--offline',action='store_true')
    parser.add_argument('--ndu-object-source',help='optional read-only complete Git object mirror of the same NDU pin')
    args=parser.parse_args()
    if args.regression_output:
        return 0 if regression_suite(args.regression_output) else 1
    if any(getattr(args,name.replace('-','_')) is None for name in
           ('output','ndu-source','cargo-home','clang','clangxx','rustc','cargo','cc','lean')):
        parser.error('all composition/tool/source arguments are required')
    result=qualify(args)
    print(json.dumps({k:result.get(k) for k in
                     ('status','qualification_commands_passed','qualifications','error')},sort_keys=True))
    return 0 if result['qualification_commands_passed'] and result['source_and_tools_unchanged'] else 1


if __name__=='__main__':
    raise SystemExit(main())
