"""Observe the qualified c81a release and its real local MCP refusal behavior."""
from pathlib import Path
import hashlib,json,os,stat,subprocess,sys
r=Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9');s=r/'source'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():return {str(p.relative_to(s)):sha(p) for p in sorted(s.rglob('*')) if p.is_file() and '.git' not in p.relative_to(s).parts}
build_path=r/'mac-r6-final-gates.json';build=json.loads(build_path.read_text())
assert build['published_commit']=='c81a938150d2e533843a42af77739cb888812338' and build['published_tree']=='aa10bb33f641bc208a3fd11bef5737f6ba026f90'
assert build['passed'] and build['source_unchanged'] and build['completed_utc']
assert [x['name'] for x in build['stages']]==['fmt','check-all-features','check-no-default','clippy-all-features','clippy-no-default','cache-cold-regression','nextest-all-features','nextest-no-default','release'] and all(x['exit_code']==0 for x in build['stages'])
expected_path=r/'runtime-r6-expected-input-projection.json';assert sha(expected_path)==build['qualified_files_sha256']=='3173737df8ac231a28cd29c3e9505514570be340bf0b13b6834b760eaff15832';expected=json.loads(expected_path.read_text());assert snapshot()==expected
before_path=r/'mac-r6-final-source-files.json';assert sha(before_path)==sha(expected_path)
after_path=r/'mac-r6-final-source-after.json';assert not after_path.exists();after_path.write_text(json.dumps(snapshot(),indent=2,sort_keys=True)+'\n');assert sha(after_path)==sha(before_path)
artifacts={}
for name in ['hepta-runtime','hepta-runtime-jobctl']:
 p=r/'target/release'/name;a=p.lstat();assert stat.S_ISREG(a.st_mode) and not p.is_symlink() and a.st_uid==os.getuid();digest=sha(p);b=p.lstat();assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns);assert digest==build['binary_sha256'][name]
 artifacts[name]={'path':str(p),'bytes':a.st_size,'sha256':digest,'mode':oct(stat.S_IMODE(a.st_mode)),'uid':a.st_uid,'device':a.st_dev,'inode':a.st_ino,'links':a.st_nlink,'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns}
report={'schema':'hepta-runtime-c81a-release-observation-v1','published_commit':build['published_commit'],'published_tree':build['published_tree'],'build_receipt_path':str(build_path),'build_receipt_sha256':sha(build_path),'qualified_source_file_count':len(expected),'source_before_sha256':sha(before_path),'source_after_sha256':sha(after_path),'source_unchanged':True,'artifacts':artifacts,'observer_sha256':sha(Path(__file__)),'production_modified':False}
output=r/'mac-r6-release-artifacts.json';assert not output.exists();output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'release_observation':report,'observation_sha256':sha(output)}),flush=True)
helper=r/'runtime-mac-refusal-tests-final.py';assert sha(helper)=='ef31942fc42df69329187b27e583ed70a6c3205db06c9d328a1a72e0a766ddd7'
rc=subprocess.run([sys.executable,str(helper),'--build-receipt',build_path.name,'--tag','mac-r6-final'],cwd=r).returncode
refusal=r/'mac-r6-final-refusal-tests.json';result=json.loads(refusal.read_text()) if refusal.is_file() else None
assert snapshot()==expected
print(json.dumps({'refusal_exit_code':rc,'refusal_receipt_sha256':sha(refusal) if refusal.exists() else None,'refusal_passed':result.get('passed') if result else False,'source_after_acceptance_unchanged':True,'production_modified':False}),flush=True)
raise SystemExit(0 if rc==0 and result and result['passed'] else 1)
