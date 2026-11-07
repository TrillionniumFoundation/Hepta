use redb::{ReadableDatabase, ReadableTable};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn ofd_lock(file: &File) -> io::Result<()> {
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    loop {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &mut lock) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
    }
}
fn open(file: File) -> Result<redb::Database, redb::DatabaseError> {
    let mut builder = redb::Database::builder();
    builder.set_cache_size(1024 * 1024);
    builder.create_file(file)
}
fn other(path: &Path) -> File {
    OpenOptions::new().read(true).write(true).open(path).unwrap()
}
fn child(path: &Path, expected: bool) {
    let file = other(path);
    let flock_blocked = matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock));
    drop(file);
    let redb_blocked = matches!(open(other(path)), Err(redb::DatabaseError::DatabaseAlreadyOpen));
    println!("{{\"child\":true,\"expected_blocked\":{expected},\"flock_blocked\":{flock_blocked},\"redb_blocked\":{redb_blocked}}}");
    assert_eq!(flock_blocked, expected);
    assert_eq!(redb_blocked, expected);
}
fn check(path: &Path, expected: bool, phase: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("child").arg(path).arg(if expected {"blocked"} else {"free"})
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() { break; }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("owned competitor exceeded timeout at {phase}");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "competitor failed at {phase}");
    println!("{{\"phase\":\"{phase}\",\"passed\":true}}");
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("child") {
        return child(Path::new(&args[2]), args[3] == "blocked");
    }
    let root = Path::new(&args[1]);
    let old_path = root.join("old-flock.redb");
    let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&old_path).unwrap();
    file.try_lock().unwrap();
    let old_guard = file.try_clone().unwrap();
    let original_failed = matches!(open(file), Err(redb::DatabaseError::DatabaseAlreadyOpen));
    println!("{{\"original_flock_then_redb_self_conflict\":{original_failed}}}");
    assert!(original_failed, "expected actual Mac original failure");
    drop(old_guard);
    let new_path = root.join("new-ofd.redb");
    let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&new_path).unwrap();
    ofd_lock(&file).unwrap();
    let hint = file.try_clone().unwrap();
    check(&new_path, true, "ofd_before_seal");
    let db = open(file).unwrap();
    check(&new_path, true, "same_fd_after_redb_open");
    let table = redb::TableDefinition::<u64, u64>::new("probe");
    let write = db.begin_write().unwrap();
    write.open_table(table).unwrap().insert(10, 17).unwrap();
    write.commit().unwrap();
    assert_eq!(db.begin_read().unwrap().open_table(table).unwrap().get(10).unwrap().unwrap().value(), 17);
    check(&new_path, true, "after_commit");
    drop(db);
    drop(hint);
    check(&new_path, false, "after_all_owned_descriptors_close");
    println!("{}", r#"{"passed":true,"unlock_between_verification_and_database_open":false,"production_modified":false}"#);
}
