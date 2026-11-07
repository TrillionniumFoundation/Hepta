#!/usr/bin/env python3
"""Actual local evidence runner; artifacts remain research-only and DENY_ALL."""
from __future__ import annotations
from datetime import datetime,timezone
from hashlib import sha256
from pathlib import Path
import json
import os
import platform
import random
import re
import resource
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from hia_candidate.core import catalog_digest,canonical_bytes,verify,Refused
from hia_candidate.migrate_c import migrate
from hia_candidate.native import compile_and_probe,probe_native_layout,cross_compile_aarch64_object
from hia_candidate.cpp_bridge import qualify_cpp
from hia_candidate.optimizer import eliminate_wrapping_add_zero
from hia_candidate.study import qualify_finite_planners
from hia_candidate.runtime import run
from hia_candidate.activation import AdmissionStore

REPORTS=ROOT/'reports';REPORTS.mkdir(exist_ok=True)


def write_json(rel,obj):
    path=REPORTS/rel;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(json.dumps(obj,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False).encode()+b'\n')


def main():
    env=os.environ.copy();env['PYTHONPATH']=str(ROOT)
    cmd=[sys.executable,'-m','unittest','discover','-s','tests','-v']
    t=subprocess.run(cmd,env=env,cwd=ROOT,text=True,capture_output=True,timeout=180)
    (REPORTS/'test-stdout.log').write_text(t.stdout)
    (REPORTS/'test-stderr.log').write_text(t.stderr)
    match=re.search(r'Ran (\d+) tests',t.stderr)
    if t.returncode or not match or 'skipped=' in t.stderr:
        raise SystemExit('FAIL: tests failed, incomplete, or skipped (see reports/test-stderr.log)')
    ntests=int(match.group(1))
    rng=random.Random(20261031)
    probes=[0,1,2,3,255,256,1024,65535,2**31-1,2**32-1]
    probes.extend(rng.randrange(2**32) for _ in range(118))
    source_reports=[]
    for fixture in ('add_zero','advanced'):
        m=migrate(ROOT/'fixtures'/'c'/f'{fixture}.c')
        native=compile_and_probe(m.verified,output=REPORTS/'native'/fixture,
                                 vectors=probes,iterations=3000)
        entry={'fixture':fixture,'migration':m.evidence(),'native':native}
        if fixture=='add_zero':
            change=eliminate_wrapping_add_zero(m.verified)
            if change is None:
                raise SystemExit('expected permitted add-zero candidate missing')
            comparison=compile_and_probe(change.candidate,
                        output=REPORTS/'native'/'add_zero_optimized',vectors=probes,iterations=3000)
            entry['optimization']={'rule':change.rule,
                'source_digest':change.source_digest,'candidate_digest':change.candidate_digest,
                'finite_test_vectors':change.test_vectors,
                'native_candidate':comparison,
                'gross_speed_advantage_qualified':False,
                'full_net_positive_advantage_qualified':False}
        source_reports.append(entry)
    write_json('P3_P5_native.json',source_reports)
    owned=verify((ROOT/'examples'/'buffer_roundtrip.hia.json').read_bytes())
    write_json('P1_resource_cases.json',{
        'normal':run(owned,[4]).json(),
        'trap_with_stopped_ledger':run(owned,[0]).json(),
        'allocator_fault':run(owned,[4],fail_allocation_at=1).json(),
        'quota_stop':run(owned,[4],max_ticks=4).json(),
        'native_memory_proven':False})
    baseline=migrate(ROOT/'fixtures'/'c'/'add_zero.c').verified
    optimized=eliminate_wrapping_add_zero(baseline).candidate
    with tempfile.TemporaryDirectory() as scratch:
        st=AdmissionStore(scratch)
        initialized=st.initialize(baseline)
        injected_failure=None
        try:st.activate(optimized,0,failure_hook='after_store')
        except Refused as exc:injected_failure=exc.code
        after_failure=AdmissionStore(scratch).read_state()
        activated=st.activate(optimized,0)
        restarted=AdmissionStore(scratch)
        executed=restarted.execute([42])
        rolled_back=restarted.rollback(1)
        write_json('P7_interpreter_activation.json',{
            'initial_generation':initialized['generation'],
            'injected_refusal':injected_failure,
            'generation_after_injected_failure':after_failure['generation'],
            'activation_generation':activated['generation'],
            'restart_result':executed,
            'rollback_generation':rolled_back['generation'],
            'active_after_rollback':rolled_back['active_digest'],
            'real_process_crash_tested':False,'production_authority':False})
    arm=cross_compile_aarch64_object(migrate(ROOT/'fixtures'/'c'/'add_zero.c').verified,
                                     REPORTS/'native'/'arm64')
    write_json('P2_arm64_object.json',arm)
    layout=probe_native_layout(REPORTS/'native'/'layout')
    write_json('P2_host_layout.json',layout)
    cpp=qualify_cpp(REPORTS/'native'/'cpp')
    write_json('P4_cpp.json',cpp)
    planner=qualify_finite_planners()
    write_json('P6_planner_controls.json',planner)
    source_digest={}
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or any(part in {'reports','__pycache__','.git'} for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix in {'.py','.json','.md','.c','.cpp','.toml'}:
            source_digest[str(path.relative_to(ROOT))]=sha256(path.read_bytes()).hexdigest()
    write_json('SOURCE_MANIFEST.json',{'files':source_digest,
                   'source_manifest_sha256':sha256(canonical_bytes(source_digest)).hexdigest()})
    limits={
        'P0':{'pilot':'PASS','full':'OPEN','missing':'not integrated with canonical HIA v8; no independent Rust/LLVM refinement qualification'},
        'P1':{'pilot':'PASS','full':'OPEN','missing':'single block and byte ownership only; no interprocedural lifetimes, async cancel, general unsafe/FFI or native RSS bound'},
        'P2':{'pilot':'PASS','full':'OPEN','missing':'host C scalar/layout probes only; ARM64 native execution, actual MMIO/DMA, C++ binary ABI and backend refinement not established'},
        'P3':{'pilot':'PASS','full':'OPEN','missing':'single function unsigned C expression, no real upstream project maintenance or pointer translation'},
        'P4':{'pilot':'PASS','full':'OPEN','missing':'synthetic C++ C-ABI/RAII revisions only, no third-party library full migration or human time audit'},
        'P5':{'pilot':'PASS','full':'OPEN','missing':'one bounded algebraic rewrite; no generic e-graph, SMT, strong Rust/Clang baseline or net-positive holdout evidence'},
        'P6':{'pilot':'PASS','full':'OPEN','missing':'finite Q32-shaped proxy, not real native NDU; no measured additional value over DP'},
        'P7':{'pilot':'PASS','full':'OPEN','missing':'interpreter-only CAS/restart tests; no real OSR, production authority, signed attestation, Agent hidden tasks or physical p99/RSS gates'}
    }
    host={'python':sys.version,'platform':platform.platform(),
          'arch':platform.machine(),'process_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    write_json('P0_P7_ACCEPTANCE.json',{
        'evidence_schema':'hepta.hia.experimental.p0-p7-acceptance.v1',
        'created_utc':datetime.now(timezone.utc).isoformat(),
        'connected_github_write':'BLOCKED_403_ACCOUNT_SUSPENDED',
        'repository_integration':False,'release_qualified':False,
        'overall':'RESEARCH_ONLY_DENY_ALL',
        'local_tests':{'count':ntests,'failed':0,'skipped':0,'real_native_C_CXX':True},
        'opcode_catalog_sha256':catalog_digest(),
        'native_scalar_probe_samples_per_compiler_per_fixture':len(probes),
        'host':host,'gates':limits})
    print(json.dumps({'status':'LOCAL_RESEARCH_PILOT_PASS','tests':ntests,
          'migrated_C_functions':len(source_reports),'per_compiler_probe_vectors':len(probes),
          'C_native_compilers':2,'aarch64_object_only':True,'CPP_native_binary_variants':len(cpp['rows']),
          'full_gate_closures':0,'Github_push':'BLOCKED_403'},ensure_ascii=False,indent=2))

if __name__=='__main__':main()
