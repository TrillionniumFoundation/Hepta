"""Fresh integrated Core controls and installed Agent qualification; not whole native delivery."""
from pathlib import Path
from hashlib import sha256
import json,os,shutil,subprocess,sys,time,zipfile
import yaml
B=Path(__file__).resolve().parents[1];R=B/'agent-core-slice-development';E=B/'evidence';P=B/'venv/bin/python'
RAW=Path('/var/tmp/hia-ci4');REPORT=E/'agent-core-slice-final-qualification-03.json'
HEAD='e2fd1c582d7967fb24dab55e6b1c2a2a835929a8';os.umask(0o077)
def git(*args):return subprocess.check_output(['git',*args],cwd=R,text=True).strip()
def stable():assert git('rev-parse','HEAD')==HEAD and not git('status','--porcelain','--untracked-files=all')
stable();assert not RAW.exists() and not REPORT.exists()
usage=shutil.disk_usage(RAW.parent);stat=os.statvfs(RAW.parent)
assert usage.free>=8<<30 and stat.f_favail>=100000,(usage,stat.f_favail)
RAW.mkdir(mode=0o700);temporary=RAW/'temporary';temporary.mkdir()
env={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_HIA_') and k not in {'PYTHONPATH','PYTHONHOME'}}
env.update(PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(temporary),PATH=str(P.parent)+':/usr/local/bin:/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',RUSTC=str(B/'toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin/rustc'))
# Admit only actual separately attested prerequisite binaries. Old missing receipts
# are not rewritten and these fresh builds are not relabelled as their outputs.
prerequisites={}
for profile,prefix,manifest_key in [('original','HEPTA_NDU','HEPTA_NDU_BUILD'),('raw','HEPTA_RAW_MODEL','HEPTA_RAW_MODEL_BUILD'),('dynamic','HEPTA_DYNAMIC_POLICY','HEPTA_DYNAMIC_POLICY_MANIFEST')]:
 folder=E/('core-controls-ndu-'+profile+'-prerequisite-01');receipt=folder/'build-receipt.json';d=json.loads(receipt.read_bytes());binary=Path(d['binary'])
 assert sha256(binary.read_bytes()).hexdigest()==d['binary_sha256'] and d['original_rust_sources_unchanged'] is True
 env[prefix+('_BINARY' if profile=='dynamic' else '_BRIDGE')]=str(binary)
 env[manifest_key]=str(folder if profile=='original' else receipt)
 prerequisites[str(receipt)]=sha256(receipt.read_bytes()).hexdigest()
for profile,prefix in [('finite','HEPTA_FINITE_NDU'),('stream','HEPTA_NDU_STREAM')]:
 folder=E/('ndu-'+profile+'-build-01');receipt=folder/'identity.json';d=json.loads(receipt.read_bytes());binary=folder/'native/hepta-hia-ndu-bridge'
 assert sha256(binary.read_bytes()).hexdigest()==d['compiled_binary_sha256']
 env[prefix+'_BRIDGE']=str(binary);env[prefix+'_IDENTITY']=str(receipt);env[prefix+'_UPSTREAM']=str(B/(profile+'-ndu-upstream'))
 prerequisites[str(receipt)]=sha256(receipt.read_bytes()).hexdigest()
rust=B/'toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin'
env.update(PATH=str(rust)+':'+env['PATH'],CARGO_NET_OFFLINE='true',HEPTA_RUSTC=str(rust/'rustc'),HIA_TEST_SOURCE_RUSTC=str(rust/'rustc'),CLANG='/usr/bin/clang-20',HEPTA_TEST_CLANG='/usr/bin/clang-20')
start=time.monotonic();steps=[]
report=dict(status='RUNNING',source_commit=HEAD,git_clean_before=True,steps=steps,evidence_root=str(RAW),high_level_source_language='REMOVED',old_mixed_language_projection_pass_claimed=False,whole_native_delivery_qualified=False,production_activated=False,storage_preflight=dict(free_bytes=usage.free,free_inodes=stat.f_favail,reserve_bytes=8<<30,native_ext4=True),all_nine_whole_obligations='OPEN',actual_prerequisite_receipts=prerequisites,prior_fixed_source_attempt='FAIL retained; 319 tests had7errors/58skips')
def dump():REPORT.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
def run(name,args,*,cwd=R,environment=env,timeout=360):
 stable();path=RAW/(name+'.log');t=time.monotonic()
 with path.open('x') as log:p=subprocess.run(list(map(str,args)),cwd=cwd,env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
 row=dict(name=name,returncode=p.returncode,wall_seconds=time.monotonic()-t,log_sha256=sha256(path.read_bytes()).hexdigest());steps.append(row);dump();print(json.dumps(row),flush=True)
 if p.returncode:raise RuntimeError('qualification failed: '+name)
 stable()
dump()
try:
 workflow=R/'.github/workflows/hia-core.yml';source=yaml.safe_load(workflow.read_text())['jobs']['source']['steps'];report['workflow_sha256']=sha256(workflow.read_bytes()).hexdigest();dump()
 for index,step in enumerate(source):
  if 'run' not in step:continue
  script=RAW/f'ci-source-{index}.sh';script.write_text('set -euo pipefail\n'+step['run']);run(f'core-installed-source-step-{index}',['bash',script])
 sys.path.insert(0,str(R))
 from tools.qualify_hia_selfhost_cli import independent_reference
 oracle=independent_reference();(RAW/'independent-native-echo-oracle.json').write_text(json.dumps(oracle,indent=2,sort_keys=True)+'\n')
 cold=RAW/'core-installed-cold.json';run('core-installed-cold',[P,'-B',R/'tools/replay_hia_selfhost_cold.py','--output',cold])
 actual=json.loads(cold.read_bytes());nested=json.loads(Path(actual['nested_report']).read_bytes())
 assert actual['status']=='COLD_SELFHOST_REPLAY_PASS' and len(actual['checks'])==11 and all(actual['checks'].values())
 assert nested['status']=='SELF_HOSTED_FIXED_CORE_PASS' and len(nested['checks'])==5049 and all(nested['checks'].values())
 assert actual['qualification_wall_limit_seconds']==180 and actual['cleanup_wall_limit_seconds']==3
 compiler=Path(nested['generations'][-1]['produced_image']);assert len(set(actual['generation_sha256']))==1
 report['cold_checks']=len(actual['checks']);report['native_checks']=len(nested['checks']);dump()
 from tools.hia_evidence_archive import verify_archive
 archives=list(compiler.parent.rglob('*.zip'));assert len(archives)==38,len(archives)
 report['cold_lossless_archives']=[]
 for archive in archives:
  manifest=verify_archive(archive);report['cold_lossless_archives'].append(dict(path=str(archive),sha256=sha256(archive.read_bytes()).hexdigest(),files=len(manifest['files']),unpacked_bytes=manifest['unpacked_bytes'],packed_bytes=archive.stat().st_size))
 dump()
 run('core-installed-language',[P,'-B',R/'tests/test_hia_selfhost_language_coverage.py','--output',RAW/'core-installed-language.json'])
 language=json.loads((RAW/'core-installed-language.json').read_bytes());assert language['status']=='SELFHOST_LANGUAGE_COVERAGE_PASS' and all(language['checks'].values())
 for row in language['fixture_archives']:verify_archive(row['archive'])
 report['language_checks']=len(language['checks']);report['language_fixture_archives']=language['fixture_archives'];dump()
 native_env={**env,'HEPTA_HIA_AGENT_STDIO_COLD_REPORT':str(cold)}
 modules=['tests.test_hia_agent_slice_native','tests.test_hia_agent_stdio','tests.test_hia_core_json_cli','tests.test_hia_elf_linker','tests.test_hia_selfhost_process_owner','tests.test_hia_core_only','tests.test_hia_evidence_archive','tests.test_hia_agent_entry','tests.test_hia_cli_seven_stage','tests.test_hia_edit_query','tests.test_hia_edit_batch','tests.test_hia_patch_impact','tests.test_hia_round4_routes','tests.test_hia_program','tests.test_hia_capability_flow','tests.test_hia_program_tools','tests.test_hia_agent_identity_native','tests.test_hia_agent_installed_resources','tests.test_hia_ndu_optimizer_transport','tests.test_hia_ndu_optimizer_budget']
 run('core-installed-components',[P,'-B',E/'run_core_integrated_unittests_strict_02.py',*modules,'-v'],environment=native_env)
 run('core-integrated-restored-controls',[P,'-B',E/'run_core_integrated_unittests_strict_02.py',*['tests.test_hia_source_head_identity', 'tests.test_hia_adaptive_retirement', 'tests.test_hia_agent_native_tools', 'tests.test_hia_finite_v8_heap', 'tests.test_hia_guarded_batch', 'tests.test_hia_host_region', 'tests.test_hia_host_region_admission_transaction', 'tests.test_hia_host_region_borrow_admission', 'tests.test_hia_host_region_borrow_rollback_receipt', 'tests.test_hia_host_region_completed_pin_retirement', 'tests.test_hia_host_region_finalization_receipt', 'tests.test_hia_host_region_job_identity', 'tests.test_hia_host_region_lease_authority', 'tests.test_hia_host_region_lease_identity_collision', 'tests.test_hia_host_region_lease_mprotect_receipt', 'tests.test_hia_host_region_lease_token_revocation', 'tests.test_hia_host_region_owner_registry_identity', 'tests.test_hia_host_region_owner_retirement', 'tests.test_hia_host_region_prestart_admission', 'tests.test_hia_host_region_prestart_pin_release_receipt', 'tests.test_hia_host_region_prestart_retirement_receipt', 'tests.test_hia_host_region_public_release_receipt', 'tests.test_hia_host_region_quarantine_receipt', 'tests.test_hia_host_region_race', 'tests.test_hia_host_region_recovery_mprotect_receipt', 'tests.test_hia_host_region_recovery_receipt', 'tests.test_hia_host_region_recovery_snapshot', 'tests.test_hia_host_region_recovery_zero_fault', 'tests.test_hia_host_region_write_receipt', 'tests.test_hia_integrated_workflow', 'tests.test_hia_machine_leaf_registers', 'tests.test_hia_native_byte_abi', 'tests.test_hia_native_differential', 'tests.test_hia_ndu_current_profile', 'tests.test_hia_ndu_graph', 'tests.test_hia_ndu_policy', 'tests.test_hia_ndu_session', 'tests.test_hia_next_evaluation', 'tests.test_hia_optimization_cli', 'tests.test_hia_partial_record_scenarios', 'tests.test_hia_program_native', 'tests.test_hia_round4_routes', 'tests.test_hia_rust_crosscheck', 'tests.test_hia_rust_owned_memory', 'tests.test_hia_rust_scoped_cleanup', 'tests.test_hia_zero_heap_loops'],'-v'],environment=native_env)
 app=RAW/'agent-identity-install-installed-01'
 run('core-installed-identity-build',[P,'-B','-m','tools.build_hia_agent_identity','--compiler',compiler,'--cold-report',cold,'--output',app])
 agent_modules=['tests.test_hia_agent_native_tools','tests.test_hia_agent_native_proof_contract','tests.test_hia_agent_native_lease_snapshot','tests.test_hia_native_startup_isolation']
 run('core-installed-default-agent',[P,'-B',E/'run_core_integrated_unittests_strict_02.py','-v',*agent_modules])
 selected={**env,'HEPTA_HIA_AGENT_IDENTITY_MANIFEST':str(app/'manifest.json')}
 run('core-installed-selected-agent',[P,'-B',E/'run_core_integrated_unittests_strict_02.py','-v',*agent_modules],environment=selected)
 run('core-installed-isolated-worker',[P,'-B',E/'exercise_agent_core_slice_worker_03.py'])
 from hepta.hia_agent_assembly import assemble_program
 document=assemble_program((R/'examples/hia_bootstrap/bytesum.hiaasm').read_bytes()).as_dict();payload=json.dumps(document,separators=(',',':')).encode()
 from tools.build_hia_agent_stdio import build
 installed=RAW/'installed-native';installed.mkdir();profile_rows={}
 for index,profile in enumerate(['flat','elf','exec']):
  binary=build(RAW/profile,compiler,cold,output_profile=profile);copy=installed/profile;shutil.copy2(binary,copy)
  cap=subprocess.run([str(copy),'capabilities'],cwd=installed,env={'PATH':'','HOME':'/nonexistent','LANG':'C'},capture_output=True,timeout=20)
  assert cap.returncode==0 and not cap.stderr and json.loads(cap.stdout)['build_profile']==index
  if profile=='exec':program=assemble_program(oracle['echo_source'].encode().replace(b'v8 selfhost\n',b'v8 selfhost_exec\n',1)).as_dict()
  else:program={**document,'module':'selfhost_elf' if profile=='elf' else document['module']}
  wire=json.dumps(program,separators=(',',':')).encode()
  verify=subprocess.run([str(copy),'verify'],input=wire,cwd=installed,env={'PATH':'','HOME':'/nonexistent','LANG':'C'},capture_output=True,timeout=20)
  assert verify.returncode==0 and not verify.stderr and json.loads(verify.stdout)['status']=='verified',(profile,verify)
  if profile=='exec':
   result=subprocess.run([str(copy),'compile'],input=wire,capture_output=True,timeout=20,env={'PATH':''});assert result.returncode==0 and not result.stderr
   echo=installed/'generated-echo';echo.write_bytes(result.stdout);echo.chmod(0o700)
   for row in oracle['echo']:
    execution=subprocess.run([str(echo)],input=bytes.fromhex(row['input_hex']),capture_output=True,timeout=20,env={'PATH':''});assert (execution.returncode,execution.stdout,execution.stderr)==(0,bytes.fromhex(row['output_hex']),b'')
  profile_rows[profile]=dict(sha256=sha256(copy.read_bytes()).hexdigest(),verified=True,explicit_program_module=program['module'],native_runtime_python_required=False)
 report['installed_native_profiles']=profile_rows;dump()
 export=RAW/'wheel-source';cold_source=cold.with_suffix('.cold')/'source';shutil.copytree(cold_source,export)
 for name,want in actual['source_manifest'].items():assert sha256((export/name).read_bytes()).hexdigest()==want
 run('core-installed-wheel',[P,'-B','-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',RAW/'wheels',export],cwd=RAW)
 wheel,=(RAW/'wheels').glob('hia_core-*.whl')
 from tools.check_hia_core_only import FORBIDDEN_MODULES
 with zipfile.ZipFile(wheel) as z:assert all('hepta/'+name+'.py' not in z.namelist() for name in FORBIDDEN_MODULES)
 target=RAW/'installed';run('core-installed-wheel-install',[P,'-B','-m','pip','install','--no-index','--no-deps','--target',target,wheel],cwd=RAW)
 assert not (target/'bin/hepta').exists()
 from tests.test_hia_agent_entry import CHILD,fixture
 guard=RAW/'import-guard';guard.mkdir();(guard/'sitecustomize.py').write_text(CHILD.split('from hepta.cli import')[0])
 installed_env={**env,'PATH':'','PYTHONPATH':str(guard)+os.pathsep+str(target)};entry=target/'bin/hia'
 sourcefile=RAW/'installed-input.hia';sourcefile.write_text(json.dumps(fixture()));query=RAW/'query.json';response=RAW/'response.json';revised=RAW/'revised.hia';obj=RAW/'installed.o';response.write_text('{"op":"int.sub.wrap"}')
 for label,args in [('capabilities',['capabilities']),('verify',['verify',sourcefile]),('edit-query',['edit-query',sourcefile,'--function','calculate','--block','entry','--value','y','--fields','op','-o',query]),('edit-apply',['edit-apply',sourcefile,'--query',query,'--response',response,'-o',revised]),('build',['build',revised,'-o',obj])]:
  run('core-installed-hosted-'+label,[entry,*args],cwd=RAW,environment=installed_env)
 from hepta.hia_program_runtime import execute_program
 assert obj.read_bytes().startswith(b'\x7fELF') and execute_program(revised.read_bytes(),'caller',[9])['result']==8
 run('core-installed-selected-native-install',[P,'-B',E/'exercise_agent_core_slice_selected_03.py'])
 run('core-installed-B3-native-graph',[P,'-B',E/'exercise_agent_core_slice_selected_graph_03.py'])
 run('core-installed-final-tree-check',[P,'-B','tools/check_hia_core_only.py'])
 assert not git('diff','f1bea765d6dee078faeaa2d7ea3f3f992785b617',HEAD,'--','examples/hia_bootstrap',':(exclude)examples/hia_bootstrap/agent_identity.hiaasm',':(exclude)examples/hia_bootstrap/agent_slice.hiaasm')
 report.update(status='PASS',git_clean_after=not git('status','--porcelain','--untracked-files=all'),installed_hosted_entry_requires_python=True,installed_scalar_identity_component_qualified=True,installed_wheel_sha256=sha256(wheel.read_bytes()).hexdigest(),existing_native_compiler_frontend_stdio_linker_bytes_unchanged=True)
except BaseException as error:
 report.update(status='FAIL',exception=repr(error));raise
finally:
 report['wall_seconds']=time.monotonic()-start;dump();print(json.dumps({k:report.get(k) for k in ['status','source_commit','wall_seconds','exception']}),flush=True)
