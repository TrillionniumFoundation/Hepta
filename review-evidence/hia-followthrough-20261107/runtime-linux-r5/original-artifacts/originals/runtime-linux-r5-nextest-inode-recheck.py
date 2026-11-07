"""Recheck only the two failed nextest gates on a private inode-sufficient mount."""
from pathlib import Path
import datetime,hashlib,json,os,resource,subprocess,time
r=Path('/home/qq/hepta-hia-unified-20261107-372e7da9/runtime-linux-gate');s=r/'source'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def snapshot():return {str(p.relative_to(s)):sha(p) for p in sorted(s.rglob('*')) if p.is_file() and '.git' not in p.relative_to(s).parts}
prior_path=r/'linux-r5-final-gates.json';assert sha(prior_path)=='398d93d009c2566f5eb60715682c8b64f83809891e4dbb16fb6ae408ac69f1ca';prior=json.loads(prior_path.read_text())
assert prior['completed_utc'] and prior['source_unchanged'] and prior['passed']==False
assert prior['published_commit']=='942d470d155c65ba7235eb19c5bbfd07f1ce2ad0'
projection_path=r/'runtime-r5-expected-input-projection.json';assert sha(projection_path)==prior['expected_projection_sha256']=='f6f2061d675d02f75b86d7120fc657aa681531d46c6117052530a7522ddcf794';projection=json.loads(projection_path.read_text());assert snapshot()==projection and len(projection)==959
retained=prior['stages'][:5];failed=prior['stages'][5:];assert [x['name'] for x in retained]==['fmt','check-all-features','check-no-default','clippy-all-features','clippy-no-default'];assert all(x['exit_code']==0 for x in retained)
assert [x['name'] for x in failed]==['nextest-all-features','nextest-no-default'] and all(x['exit_code']==100 for x in failed)
for x in prior['stages']:assert sha(Path(x['log']))==x['log_sha256']
for x in prior['cargo_target_inventory']:assert x['matches_complete_pinned_target_source_inventory'] and x['target_count']==19
for info in [prior['nextest'],prior['ripgrep']]:assert sha(Path(info['path']))==info['sha256']
root_tmp=Path('/home/qq/hia-tmp-l7');assert not root_tmp.exists();root_tmp.mkdir(mode=0o700);assert root_tmp.resolve()==root_tmp and root_tmp.stat().st_uid==os.getuid() and root_tmp.stat().st_mode&0o777==0o700 and len(str(root_tmp).encode())<=32
st=os.statvfs(root_tmp);assert st.f_favail>=65536
original_nofile=resource.getrlimit(resource.RLIMIT_NOFILE);resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192));os.umask(0o022)
env=os.environ.copy();env.update(CARGO_HOME='/home/qq/.cargo',CARGO_TARGET_DIR=str(r/'target'),CARGO_BUILD_JOBS='4',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',TMPDIR=str(root_tmp),PATH='/home/qq/hepta-hia-agent-native-20261106-f4e250f91ef4/tools/bin:/home/qq/.cargo/bin:'+env.get('PATH','/usr/bin:/bin'))
report={k:prior[k] for k in ['base_commit','published_commit','published_tree','patch_sha256','source_manifest_sha256','qualified_files_sha256','qualified_file_count','platform','machine','expected_projection_sha256','expected_target_inventory_sha256','cargo_target_inventory','nextest','ripgrep','input_scope','input_exclusions']}
report.update(schema='hepta-runtime-identical-source-gate-matrix-with-environment-recheck-v1',started_utc=utc(),runner_sha256=sha(Path(__file__)),prior_failed_attempt={'path':str(prior_path),'sha256':sha(prior_path),'passed':False,'reason':'tmp inode exhaustion; source unchanged; prior failed results remain unchanged'},retained_successful_stage_receipts=[dict(x,receipt_source_sha256=sha(prior_path)) for x in retained],rechecked_stages=[],environment={'TMPDIR':str(root_tmp),'umask':'022','prior_nofile':original_nofile,'qualified_nofile':resource.getrlimit(resource.RLIMIT_NOFILE),'inodes_available_before':st.f_favail,'bytes_available_before':st.f_bavail*st.f_frsize})
output=r/'linux-r5-inode-recheck-gates.json';assert not output.exists()
def save():output.write_text(json.dumps(report,indent=2)+'\n')
save()
for original in failed:
 argv=original['argv'];assert '--all-targets' in argv and '--retries' in argv and argv[argv.index('--retries')+1]=='0' and '--no-fail-fast' in argv and argv[argv.index('--test-threads')+1]=='1'
 name=original['name'];log=r/('linux-r5-inode-recheck-'+name+'.log');assert not log.exists();stage={'name':name,'argv':argv,'status':'running','started_utc':utc(),'log':str(log)};report['rechecked_stages'].append(stage);save();print(json.dumps(stage),flush=True);started=time.monotonic()
 with log.open('wb') as stream:rc=subprocess.run(argv,cwd=s,env=env,stdout=stream,stderr=subprocess.STDOUT).returncode
 stage.update(status='completed',exit_code=rc,elapsed_seconds=time.monotonic()-started,log_sha256=sha(log),log_bytes=log.stat().st_size);save();print(json.dumps(stage),flush=True)
 print('\n'.join(line for line in log.read_text(errors='replace').splitlines() if 'Summary [' in line or ' FAIL ' in line or line.startswith(('error:','error['))),flush=True)
report['source_unchanged']=snapshot()==projection;report['completed_utc']=utc();report['passed']=report['source_unchanged'] and all(x['exit_code']==0 for x in report['retained_successful_stage_receipts']+report['rechecked_stages']);save();print(json.dumps(report),flush=True)
raise SystemExit(0 if report['passed'] else 1)
