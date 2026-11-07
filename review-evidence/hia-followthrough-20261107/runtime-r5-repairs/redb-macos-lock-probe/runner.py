from pathlib import Path
import datetime,hashlib,json,os,signal,subprocess
ROOT=Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
assert ROOT.resolve()==ROOT and ROOT.stat().st_uid==os.getuid()
DEST=ROOT/'redb-mac-lock-r1'
DEST.mkdir(mode=0o700)
SOURCE='use redb::{ReadableDatabase, ReadableTable};\nuse std::fs::{File, OpenOptions};\nuse std::io;\nuse std::os::fd::AsRawFd;\nuse std::os::unix::fs::OpenOptionsExt;\nuse std::path::Path;\nuse std::process::{Command, Stdio};\nuse std::time::{Duration, Instant};\n\nfn ofd_lock(file: &File) -> io::Result<()> {\n    let mut lock: libc::flock = unsafe { std::mem::zeroed() };\n    lock.l_type = libc::F_WRLCK;\n    lock.l_whence = libc::SEEK_SET as libc::c_short;\n    loop {\n        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &mut lock) } == 0 {\n            return Ok(());\n        }\n        let error = io::Error::last_os_error();\n        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }\n    }\n}\nfn open(file: File) -> Result<redb::Database, redb::DatabaseError> {\n    let mut builder = redb::Database::builder();\n    builder.set_cache_size(1024 * 1024);\n    builder.create_file(file)\n}\nfn other(path: &Path) -> File {\n    OpenOptions::new().read(true).write(true).open(path).unwrap()\n}\nfn child(path: &Path, expected: bool) {\n    let file = other(path);\n    let flock_blocked = matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock));\n    drop(file);\n    let redb_blocked = matches!(open(other(path)), Err(redb::DatabaseError::DatabaseAlreadyOpen));\n    println!("{{\\"child\\":true,\\"expected_blocked\\":{expected},\\"flock_blocked\\":{flock_blocked},\\"redb_blocked\\":{redb_blocked}}}");\n    assert_eq!(flock_blocked, expected);\n    assert_eq!(redb_blocked, expected);\n}\nfn check(path: &Path, expected: bool, phase: &str) {\n    let mut child = Command::new(std::env::current_exe().unwrap())\n        .arg("child").arg(path).arg(if expected {"blocked"} else {"free"})\n        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();\n    let deadline = Instant::now() + Duration::from_secs(5);\n    loop {\n        if child.try_wait().unwrap().is_some() { break; }\n        if Instant::now() >= deadline {\n            child.kill().unwrap();\n            let _ = child.wait();\n            panic!("owned competitor exceeded timeout at {phase}");\n        }\n        std::thread::sleep(Duration::from_millis(2));\n    }\n    let output = child.wait_with_output().unwrap();\n    print!("{}", String::from_utf8_lossy(&output.stdout));\n    eprint!("{}", String::from_utf8_lossy(&output.stderr));\n    assert!(output.status.success(), "competitor failed at {phase}");\n    println!("{{\\"phase\\":\\"{phase}\\",\\"passed\\":true}}");\n}\nfn main() {\n    let args: Vec<_> = std::env::args().collect();\n    if args.get(1).map(String::as_str) == Some("child") {\n        return child(Path::new(&args[2]), args[3] == "blocked");\n    }\n    let root = Path::new(&args[1]);\n    let old_path = root.join("old-flock.redb");\n    let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&old_path).unwrap();\n    file.try_lock().unwrap();\n    let old_guard = file.try_clone().unwrap();\n    let original_failed = matches!(open(file), Err(redb::DatabaseError::DatabaseAlreadyOpen));\n    println!("{{\\"original_flock_then_redb_self_conflict\\":{original_failed}}}");\n    assert!(original_failed, "expected actual Mac original failure");\n    drop(old_guard);\n    let new_path = root.join("new-ofd.redb");\n    let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&new_path).unwrap();\n    ofd_lock(&file).unwrap();\n    let hint = file.try_clone().unwrap();\n    check(&new_path, true, "ofd_before_seal");\n    let db = open(file).unwrap();\n    check(&new_path, true, "same_fd_after_redb_open");\n    let table = redb::TableDefinition::<u64, u64>::new("probe");\n    let write = db.begin_write().unwrap();\n    write.open_table(table).unwrap().insert(10, 17).unwrap();\n    write.commit().unwrap();\n    assert_eq!(db.begin_read().unwrap().open_table(table).unwrap().get(10).unwrap().unwrap().value(), 17);\n    check(&new_path, true, "after_commit");\n    drop(db);\n    drop(hint);\n    check(&new_path, false, "after_all_owned_descriptors_close");\n    println!("{}", r#"{"passed":true,"unlock_between_verification_and_database_open":false,"production_modified":false}"#);\n}\n'
(DEST/'probe.rs').write_text(SOURCE)
deps=ROOT/'target/debug/deps'
selected={name:sorted(deps.glob('lib'+name+'-*.rlib'))[0] for name in ('redb','libc')}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rows={k:{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)} for k,p in selected.items()}
report={'schema':'hepta-runtime-redb-lock-probe-v1','host':'macos','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_sha256':sha(DEST/'probe.rs'),'selected_libraries':rows,'production_modified':False,'source_and_target_written':False,'commands':[]}
def run(args,tag,timeout):
 with (DEST/(tag+'.stdout')).open('wb') as out,(DEST/(tag+'.stderr')).open('wb') as err:
  p=subprocess.Popen(args,cwd=ROOT/'source',stdout=out,stderr=err,start_new_session=True)
  try:code=p.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGKILL);p.wait();code=124
 row={'argv':args,'exit_code':code,'stdout_sha256':sha(DEST/(tag+'.stdout')),'stderr_sha256':sha(DEST/(tag+'.stderr'))}
 report['commands'].append(row)
 (DEST/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return code
rustc='/opt/homebrew/opt/rustup/bin/rustc'
assert run([rustc,'--version','--verbose'],'rustc-version',15)==0
cmd=[rustc,'--edition=2021',str(DEST/'probe.rs'),'-L','dependency='+str(deps),'-o',str(DEST/'probe')]
for name,p in selected.items():cmd.extend(['--extern',name+'='+str(p)])
compiled=run(cmd,'compile',60)
if compiled==0:run([str(DEST/'probe'),str(DEST)],'execution',30)
report['libraries_unchanged']=all(sha(p)==rows[k]['sha256'] for k,p in selected.items())
report['passed']=len(report['commands'])==3 and all(row['exit_code']==0 for row in report['commands']) and report['libraries_unchanged']
report['completed_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(DEST/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report),flush=True)
print((DEST/('execution.stdout' if compiled==0 else 'compile.stderr')).read_text(),flush=True)
raise SystemExit(0 if report['passed'] else 1)
