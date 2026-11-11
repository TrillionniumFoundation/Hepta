"""NEW actual static-ELF namespace filesystem development corpus.

Every HIA entry is replayed byte-for-byte with observed real syscall replies.
SQLite observations are bound to this CI interpreter's actual sqlite_source_id.
They do not silently qualify the old SQLite 3.46.1 migration or ordinary store.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import argparse, ctypes, errno, fcntl, hashlib, importlib.util, json, os
from pathlib import Path
import select, signal, sqlite3, stat, struct, subprocess, time, traceback, unittest

CLIENT_SHA = "00981a3f7bbd195dd5522858d6c032e19a4789900317ff8637be1d811a77893d"
REPLAY_SHA = "d81356c9bdee5889f562720048b1ac654cfd74f02cb16bb61ff55f1e675c3881"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    args = parser.parse_args()
    assert sys.version_info[:3] == (3, 12, 14)
    pins = {}
    def pin(path, expected=None):
        path = Path(path).resolve()
        raw = path.read_bytes()
        row = dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE(path.stat().st_mode))
        if expected is not None:
            assert row["sha256"] == expected
        if str(path) in pins:
            assert row == pins[str(path)]
        pins[str(path)] = row
        return raw
    def load(name, path, expected):
        raw = pin(path, expected)
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module
    context = json.loads(pin(args.context))
    evidence = Path(context["namespace_evidence"])
    ref = Path(context["reference"])
    tree = Path(context["namespace_working"])
    out = evidence / "carrier-native-r1"
    out.mkdir(parents=True, exist_ok=False)
    (out / "source").mkdir()
    fixture_root = Path(context["base"]) / "namespace-ci-fs-r3/carrier-fixtures-r1"
    fixture_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    snapshot_root = out / "fixtures"
    cas = snapshot_root / "cas"
    cas.mkdir(parents=True)
    build = json.loads(pin(evidence / "carrier-build-r1/summary.json"))
    assert build["status"] == "PASS_BUILD_ONLY" and build["source_pins_unchanged"]
    assert build["packer_entries"] == 8 and len(build["packer_controls"]) == 8
    executable = Path(build["executable"]["path"])
    raw_elf = pin(executable, build["executable"]["sha256"])
    assert len(raw_elf) == build["executable"]["bytes"] and raw_elf[:4] == b"\x7fELF"
    assert stat.S_IMODE(executable.stat().st_mode) == 0o755
    sys.path.insert(0, str(ref))
    from hepta.hia_agent_assembly import assemble_program
    program_source = pin(tree / "examples/hia_bootstrap/agent_namespace_filesystem_r3.hiaasm",
                         build["kernel_source_sha256"])
    program = assemble_program(program_source)
    transport = load("namespace_carrier_private_fixture", args.client, CLIENT_SHA)
    playback = load("namespace_carrier_trace_replay", args.replay, REPLAY_SHA)
    parent_helper = out / "parent-death-helper.py"
    parent_helper.write_text(
        "import hashlib,importlib.util,json,os,sys,time\nfrom pathlib import Path\n"
        "client,executable,output,cwd,ready=sys.argv[1:]\n"
        "raw=Path(client).read_bytes()\n"
        "assert hashlib.sha256(raw).hexdigest()==" + repr(CLIENT_SHA) + "\n"
        "s=importlib.util.spec_from_file_location('carrier_fixture',client)\n"
        "m=importlib.util.module_from_spec(s)\n"
        "exec(compile(raw,client,'exec'),m.__dict__)\n"
        "c=m.Carrier(executable,output,cwd)\n"
        "c.call(16)\n"
        "r=Path(ready);t=r.with_suffix('.tmp')\n"
        "t.write_text(json.dumps({'parent':os.getpid(),'native':c.process.pid}))\n"
        "os.replace(t,r)\n"
        "while True: time.sleep(1)\n")
    pin(parent_helper)
    pin(__file__)
    for module in tuple(sys.modules.values()):
        name = getattr(module, "__file__", None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ref) and path.suffix == ".py":
                pin(path)
    for number, (path, row) in enumerate(pins.items()):
        target = out / "source" / str(number) / Path(path).name
        target.parent.mkdir(parents=True)
        target.write_bytes(Path(path).read_bytes()); target.chmod(row["mode"])
    save(out / "source-before.json", pins)
    with sqlite3.connect(":memory:") as db:
        sqlite_identity = dict(version=sqlite3.sqlite_version,
            source_id=db.execute("select sqlite_source_id()").fetchone()[0],
            compile_options=[row[0] for row in db.execute("pragma compile_options")])
    save(out / "sqlite-identity.json", sqlite_identity)
    report = dict(status="INCOMPLETE", scope="NEW_ACTUAL_FS_CARRIER_COMPONENT_NOT_ORDINARY_STORE",
        sqlite=sqlite_identity, legacy_sqlite3461_claimed=False, physical_store_closed=False,
        migration_closed=False, public_root_policy_closed=False, replay=[], observations={})

    def snapshot(root, label):
        rows = []
        for path in [root, *sorted(root.rglob("*"))]:
            info = path.lstat()
            row = dict(path="." if path == root else path.relative_to(root).as_posix(),
                       type=stat.S_IFMT(info.st_mode), mode=stat.S_IMODE(info.st_mode),
                       uid=info.st_uid, gid=info.st_gid, device=info.st_dev, inode=info.st_ino,
                       links=info.st_nlink, bytes=info.st_size)
            if stat.S_ISLNK(info.st_mode):
                row["target_bytes_hex"] = os.fsencode(os.readlink(path)).hex()
            elif stat.S_ISREG(info.st_mode):
                raw = path.read_bytes(); h = sha(raw); target = cas / h
                if not target.exists():
                    target.write_bytes(raw)
                assert target.read_bytes() == raw
                row.update(content_bytes=len(raw), sha256=h, cas="cas/" + h)
            rows.append(row)
        save(snapshot_root / (label + ".json"), rows)

    def replay_instance(directory, fatal_code=0):
        value = playback.replay(program, directory, fatal_code=fatal_code)
        value["directory"] = str(directory)
        report["replay"].append(value)
        return value

    class ActualCarrier(unittest.TestCase):
        def setUp(self):
            self.label = self._testMethodName
            self.fx = fixture_root / self.label
            self.fx.mkdir(mode=0o700)
            self.case = out / "cases" / self.label
            self.case.mkdir(parents=True)
            self.addCleanup(snapshot, self.fx, self.label + "-final")

        def carrier(self, suffix="native", **kw):
            return transport.Carrier(executable, self.case / suffix, self.fx, **kw)

        def test_01_all_twenty_two_actual_primitives(self):
            with self.carrier() as c:
                h, _ = c.call(16)
                self.assertEqual(h[8], os.geteuid())
                begin = time.monotonic_ns()
                h, _ = c.call(12)
                stamp = h[8] * 1000000000 + h[9]
                self.assertLessEqual(begin, stamp); self.assertLessEqual(stamp, time.monotonic_ns())
                h, body = c.call(20, 4096)
                self.assertEqual(body, os.fsencode(self.fx.resolve()) + b"\0")
                self.assertEqual(h[8], len(body))
                c.call(13, 0, 1000000)
                h, body = c.call(14, 32, 0)
                self.assertEqual((h[8], len(body)), (32, 32))
                h, _ = c.call(1, 0, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600, body=b"alpha")
                token = h[8]
                h, _ = c.call(3, token, 0, body=b"ab\0cd123")
                self.assertEqual(h[8], 8)
                h, body = c.call(2, token, 20, 0)
                self.assertEqual((h[8], body), (8, b"ab\0cd123"))
                h, body = c.call(2, token, 20, 100)
                self.assertEqual((h[8], body), (0, b""))
                h, _ = c.call(3, token, 0, body=b"")
                self.assertEqual(h[8], 0)
                c.call(5, token, 3)
                h, body = c.call(4, token)
                info = (self.fx / "alpha").stat()
                self.assertEqual(tuple(h[i] for i in (8, 9, 10, 11, 12, 13, 24)),
                    (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_nlink))
                self.assertEqual(body, b"")
                h, body = c.call(15, token)
                self.assertEqual(len(body), 144)
                self.assertEqual(struct.unpack_from("<QQQ", body),
                    (info.st_dev, info.st_ino, info.st_nlink))
                c.call(21, token, 0o640)
                self.assertEqual(stat.S_IMODE((self.fx / "alpha").stat().st_mode), 0o640)
                c.call(6, token)
                c.call(11, token, fcntl.LOCK_EX | fcntl.LOCK_NB)
                c.call(11, token, fcntl.LOCK_UN)
                c.call(17, token, 1, 120, 1)
                c.call(17, token, 2, 120, 1)
                c.call(7, 0, 0, 5, body=b"alpha" + b"renamed")
                self.assertFalse((self.fx / "alpha").exists())
                self.assertEqual((self.fx / "renamed").read_bytes(), b"ab\0")
                c.call(22, 0, 0o600, body=b"renamed")
                self.assertEqual(stat.S_IMODE((self.fx / "renamed").stat().st_mode), 0o600)
                h, _ = c.call(1, 0, os.O_RDONLY | os.O_DIRECTORY, 0, body=b".")
                directory = h[8]
                c.call(10, directory, 0o700, body=b"child")
                self.assertTrue((self.fx / "child").is_dir())
                (self.fx / "link").symlink_to("renamed")
                h, body = c.call(18, directory, 0x100, body=b"link")
                self.assertTrue(stat.S_ISLNK(h[10])); self.assertEqual(len(body), 144)
                h, body = c.call(19, directory, 32, body=b"link")
                self.assertEqual((h[8], body), (7, b"renamed"))
                c.call(8, token)
                c.call(9, directory, 0, body=b"renamed")
                c.call(9, directory, 0, body=b"link")
                c.call(9, directory, 0x200, body=b"child")
                c.call(8, directory)
                c.close_all()
                maps, fds = c.snapshot_owned_process("after-close-all")
                self.assertFalse(any(b"w" in line.split()[1] and b"x" in line.split()[1]
                                     for line in maps.splitlines()))
                self.assertEqual(sorted(row["fd"] for row in fds), [1, 2, 3])
            replay = replay_instance(c.output)
            self.assertEqual(set(map(int, replay["primitive_operation_counts"])), set(range(1, 23)))
            self.assertEqual(next(x["raw_return"] for x in replay["primitive_events"] if x["operation"] == 1), 0)
            report["observations"]["all22_actual_primitives"] = True
            report["observations"]["actual_raw_fd_zero"] = True
            report["observations"]["actual_uid"] = os.geteuid()

        def test_02_known_errno_preserves_context(self):
            with self.carrier() as c:
                c.call(1, 0, os.O_RDONLY, 0, body=b"missing", expect_errno=errno.ENOENT)
                h, _ = c.call(1, 0, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600, body=b"present")
                token = h[8]
                c.call(3, token, 0, body=b"accepted-after-error")
                c.call(8, token)
                c.close_all()
            replay = replay_instance(c.output)
            opens = [x["raw_return"] for x in replay["primitive_events"] if x["operation"] == 1]
            self.assertEqual(opens, [((-errno.ENOENT) & transport.MASK), 0])
            self.assertEqual((self.fx / "present").read_bytes(), b"accepted-after-error")

        def test_03_more_than_one_slot_page_and_close_once(self):
            with self.carrier() as c:
                tokens = []
                for index in range(17):
                    h, _ = c.call(1, 0, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600,
                                  body=("file-" + str(index)).encode())
                    tokens.append(h[8])
                self.assertEqual(len(set(tokens)), 17)
                self.assertEqual(tokens, sorted(tokens))
                c.close_all()
                _, fds = c.snapshot_owned_process("after-close-all")
                self.assertEqual(sorted(row["fd"] for row in fds), [1, 2, 3])
            replay = replay_instance(c.output)
            self.assertEqual(replay["primitive_operation_counts"], {"1":17, "8":17})
            self.assertGreaterEqual(replay["growth_continuations"], 2)

        def test_04_actual_permanent_rejection_no_syscall(self):
            for case in ("short-input", "reserved-input", "replayed-call"):
                with self.subTest(case=case):
                    with self.carrier(case) as c:
                        if case == "short-input":
                            raw = b"x"
                        elif case == "reserved-input":
                            raw = bytearray(transport.frame(2, session=c.session, call=1,
                                operation=16, lease=1001))
                            struct.pack_into("<Q", raw, 14 * 8, 1)
                        else:
                            c.call(16)
                            raw = transport.frame(2, session=c.session, call=1,
                                                  operation=16, lease=1001)
                        h, _ = c.request(raw, label="reject")
                        self.assertEqual(h[1], 0xfffffffd)
                        first_reason = h[19]
                        h, _ = c.request(transport.frame(1, session=(7, 9)), label="persistent")
                        self.assertEqual((h[1], h[19]), (0xfffffffd, first_reason))
                    replay = replay_instance(c.output)
                    self.assertEqual(replay["actual_primitive_acks"], 1 if case == "replayed-call" else 0)

        def test_05_truncated_transport_releases_actual_process_lock(self):
            with self.carrier() as c:
                h, _ = c.call(1, 0, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600, body=b"lock-file")
                token = h[8]
                c.call(17, token, 1, 120, 1)
                observer = os.open(self.fx / "lock-file", os.O_RDWR)
                try:
                    with self.assertRaises(OSError) as raised:
                        fcntl.lockf(observer, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 120, os.SEEK_SET)
                    self.assertIn(raised.exception.errno, (errno.EAGAIN, errno.EACCES))
                    partial = struct.pack("<Q", 256) + b"truncated"
                    (self.case / "partial-transport.bin").write_bytes(partial)
                    c._write(partial, time.monotonic() + 30)
                    c.expected_exit = 111
                    c.finish(111)
                    fcntl.lockf(observer, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 120, os.SEEK_SET)
                    fcntl.lockf(observer, fcntl.LOCK_UN, 1, 120, os.SEEK_SET)
                finally:
                    os.close(observer)
            replay_instance(c.output, fatal_code=111)
            report["observations"]["truncated_transport_process_lock_released"] = True

        def test_06_real_sqlite_wal_writer_byte120_both_directions(self):
            database = self.fx / "state.sqlite3"
            connection = sqlite3.connect(database, timeout=0, isolation_level=None)
            transcript = []
            def sql(text):
                try:
                    result = connection.execute(text).fetchall()
                    transcript.append(dict(sql=text, status="RETURNED", rows=result))
                    return result
                except BaseException as error:
                    transcript.append(dict(sql=text, status="RAISED",
                        error_class=type(error).__name__, error=str(error),
                        sqlite_errorcode=getattr(error, "sqlite_errorcode", None),
                        sqlite_errorname=getattr(error, "sqlite_errorname", None)))
                    raise
            try:
                self.assertEqual(sql("pragma journal_mode=WAL"), [("wal",)])
                sql("pragma synchronous=FULL")
                sql("create table observed(value integer)")
                shared = self.fx / "state.sqlite3-shm"
                self.assertTrue(shared.is_file())
                before = shared.stat()
                with self.carrier() as c:
                    h, _ = c.call(1, 0, os.O_RDWR, 0, body=b"state.sqlite3-shm")
                    token = h[8]
                    h, _ = c.call(4, token)
                    self.assertEqual((h[8], h[9]), (before.st_dev, before.st_ino))
                    sql("begin immediate")
                    c.call_number += 1
                    h, _ = c.request(transport.frame(2, session=c.session, call=c.call_number,
                        operation=17, args=(token, 1, 120, 1), lease=1000 + c.call_number),
                        label="native-blocked-by-real-sqlite")
                    self.assertEqual(h[1], 0)
                    self.assertIn(h[7], (errno.EACCES, errno.EAGAIN))
                    sql("rollback")
                    c.call(17, token, 1, 120, 1)
                    with self.assertRaises(sqlite3.OperationalError) as raised:
                        sql("begin immediate")
                    self.assertEqual(raised.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                    c.call(17, token, 2, 120, 1)
                    sql("begin immediate"); sql("insert into observed values(7)"); sql("commit")
                    self.assertEqual(sql("select value from observed"), [(7,)])
                    c.call(8, token); c.close_all()
                replay_instance(c.output)
                snapshot(self.fx, self.label + "-connection-open")
                report["observations"]["actual_wal_byte120_both_directions"] = True
                report["observations"]["actual_wal_shared_inode"] = dict(device=before.st_dev, inode=before.st_ino)
            finally:
                save(self.case / "sql-transcript.json", transcript)
                connection.close()

        def test_07_closing_alias_drops_posix_inode_lock(self):
            original = self.fx / "original"
            original.write_bytes(bytes(256))
            os.link(original, self.fx / "alias")
            native = original.stat()
            self.assertEqual(native.st_ino, (self.fx / "alias").stat().st_ino)
            observer = os.open(original, os.O_RDWR)
            try:
                with self.carrier() as c:
                    h, _ = c.call(1, 0, os.O_RDWR, 0, body=b"original")
                    first = h[8]
                    c.call(17, first, 1, 120, 1)
                    with self.assertRaises(OSError) as raised:
                        fcntl.lockf(observer, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 120, os.SEEK_SET)
                    self.assertIn(raised.exception.errno, (errno.EACCES, errno.EAGAIN))
                    h, _ = c.call(1, 0, os.O_RDWR, 0, body=b"alias")
                    second = h[8]
                    self.assertNotEqual(first, second)
                    c.call(8, second)
                    # POSIX process locks are inode-scoped: closing any alias drops them.
                    fcntl.lockf(observer, fcntl.LOCK_EX | fcntl.LOCK_NB, 1, 120, os.SEEK_SET)
                    fcntl.lockf(observer, fcntl.LOCK_UN, 1, 120, os.SEEK_SET)
                    c.call(8, first); c.close_all()
                replay_instance(c.output)
            finally:
                os.close(observer)
            report["observations"]["actual_alias_close_drops_lock"] = True
            report["observations"]["inode_registry_policy_still_required"] = True

        def test_08_raw_symlink_and_parent_path_observations(self):
            (self.fx / "directory").mkdir()
            (self.fx / "directory/file").write_bytes(b"through-parent")
            (self.fx / "parent").symlink_to("directory", target_is_directory=True)
            (self.fx / "final").symlink_to("directory/file")
            with self.carrier() as c:
                h, _ = c.call(1, 0, os.O_RDONLY | os.O_NOFOLLOW, 0, body=b"parent/file")
                token = h[8]
                _, body = c.call(2, token, 64, 0)
                self.assertEqual(body, b"through-parent")
                c.call(8, token)
                c.call(1, 0, os.O_RDONLY | os.O_NOFOLLOW, 0, body=b"final", expect_errno=errno.ELOOP)
                h, _ = c.call(18, 0, 0x100, body=b"final")
                self.assertTrue(stat.S_ISLNK(h[10]))
                _, body = c.call(19, 0, 64, body=b"final")
                self.assertEqual(body, b"directory/file")
                c.close_all()
            replay_instance(c.output)

        def test_09_parent_death_terminates_owned_native_child(self):
            self.assertTrue(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"))
            ready = self.case / "ready.json"
            native_dir = self.case / "native"
            helper = parent_helper
            expected_parent = os.getpid()
            libc = ctypes.CDLL(None, use_errno=True)
            call = libc.prctl
            call.argtypes = [ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
            call.restype = ctypes.c_int
            def parent_lifetime():
                if call(1, signal.SIGKILL, 0, 0, 0):
                    raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG")
                if os.getppid() != expected_parent:
                    os.kill(os.getpid(), signal.SIGKILL)
            process = None; pidfd = None
            with (self.case / "parent.stdout").open("wb") as stdout, (self.case / "parent.stderr").open("wb") as stderr:
                try:
                    process = subprocess.Popen([sys.executable,"-I","-S","-B",str(helper),
                        str(args.client.resolve()),str(executable),str(native_dir),str(self.fx),str(ready)],
                        stdout=stdout,stderr=stderr,stdin=subprocess.DEVNULL,
                        start_new_session=True,preexec_fn=parent_lifetime)
                    deadline = time.monotonic() + 30
                    while not ready.exists():
                        self.assertIsNone(process.poll(), "test parent exited before ready")
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.02)
                    ids = json.loads(ready.read_bytes())
                    self.assertEqual(ids["parent"], process.pid)
                    pidfd = os.pidfd_open(ids["native"])
                    proc_raw = (Path("/proc") / str(ids["native"]) / "stat").read_bytes()
                    (self.case / "native-proc-before.stat").write_bytes(proc_raw)
                    fields = proc_raw[proc_raw.rfind(b")") + 2:].split()
                    self.assertEqual(int(fields[1]), process.pid)
                    os.killpg(process.pid, signal.SIGKILL)
                    self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
                    poller = select.poll(); poller.register(pidfd, select.POLLIN)
                    events = poller.poll(5000)
                    self.assertTrue(events, "native child survived parent death")
                    save(self.case / "death-observation.json", dict(
                        status="OWNED_NATIVE_CHILD_EXIT_OBSERVED_BY_PIDFD",
                        parent_pid=process.pid,native_pid=ids["native"],pidfd_events=events,
                        parent_returncode=process.returncode,native_exit_code="NOT_READ_NOT_OUR_CHILD",
                        selected_source_pdeathsig=True))
                finally:
                    if process is not None and process.returncode is None:
                        try: os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                        process.wait()
                    if pidfd is not None:
                        try: signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                        except ProcessLookupError: pass
                        os.close(pidfd)
            # Trace replay is separate from process outcome; no exit0 is claimed.
            replay_instance(native_dir)
            report["observations"]["parent_death_child_termination"] = True

        def test_10_empty_close_all_permanently_closed(self):
            with self.carrier() as c:
                c.close_all()
                h, _ = c.request(transport.frame(2,session=c.session,call=2,
                    operation=16,lease=1002),label="after-closed")
                self.assertEqual(h[1],0xfffffffd)
                h, _ = c.request(transport.frame(1,session=(4,5)),label="after-poison")
                self.assertEqual(h[1],0xfffffffd)
            result = replay_instance(c.output)
            self.assertEqual(result["actual_primitive_acks"],0)

    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ActualCarrier)
        ids = [test.id() for test in suite]
        assert len(ids) == len(set(ids)) == 10
        with (out / "unittest.log").open("w", encoding="utf-8") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        tests = dict(test_ids=ids, tests_loaded=len(ids), tests_run=result.testsRun,
            failures=[(t.id(),s) for t,s in result.failures],
            errors=[(t.id(),s) for t,s in result.errors],
            skipped=[(t.id(),s) for t,s in result.skipped],
            expected_failures=[(t.id(),s) for t,s in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        save(out / "tests.json", tests); report["tests"] = tests
        assert result.testsRun == len(ids) and result.wasSuccessful()
        assert not any(tests[k] for k in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert report["replay"] and all(row["status"] == "PASS" for row in report["replay"])
        report.update(status="PASS", native_entries=sum(r["native_entries"] for r in report["replay"]),
            vm_entries=sum(r["vm_entries"] for r in report["replay"]),
            actual_primitive_acks=sum(r["actual_primitive_acks"] for r in report["replay"]),
            process_traces_replayed=len(report["replay"]))
    except BaseException as error:
        report.update(status="FAIL", error_class=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        after = {}
        for path in pins:
            p = Path(path); raw = p.read_bytes()
            after[path] = dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(p.stat().st_mode))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=after==pins)
        if after != pins: report["status"] = "FAIL"
        save(out / "summary.json",report)
        print(json.dumps(dict(status=report["status"],scope=report["scope"],
            tests_run=report.get("tests",{}).get("tests_run"),
            native_entries=report.get("native_entries"),
            process_traces_replayed=len(report["replay"]),
            source_pins_unchanged=report["source_pins_unchanged"])),flush=True)
    raise SystemExit(0 if report["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
