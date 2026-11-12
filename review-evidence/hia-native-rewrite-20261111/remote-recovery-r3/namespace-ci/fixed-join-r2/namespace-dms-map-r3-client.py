"""Private fixture transport for the new fixed four-image DMS/map ELF.
Python records explicit test requests and raw outcomes. DMS HIA owns every
child request, map/memory continuation, actual FS initialization and retirement.
A strace launcher is an explicit fault control, never ordinary runtime.
"""
from __future__ import annotations
import ctypes, errno, hashlib, json, os, resource, select, signal, stat
import struct, subprocess, sys, threading, time
from pathlib import Path

MAGIC = int.from_bytes(b"HIANDM03", "little")
TRACE_MAGIC = int.from_bytes(b"HIANDT03", "little")
MASK = (1 << 64) - 1
LIMITS = dict(cpu_seconds=90, wall_seconds=180, address_bytes=1 << 30,
              core_bytes=0, request_wall_seconds=30, normal_reap_wall_seconds=30,
              killed_reap_wall_seconds=5)
LIMIT_MAGIC = int.from_bytes(b"NSLIMIT1", "little")
# This finite fixture pre-exec launcher only installs kernel limits and the
# parent-death signal, emits its actual limits, closes the private ready FD,
# then execs the exact ELF or explicit strace control. It owns no HIA policy.
# A fresh interpreter avoids preexec_fn in a process with watchdog threads.
LIMIT_LAUNCHER = """import ctypes, os, resource, struct, sys
ready = int(sys.argv[1])
parent = int(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
if libc.prctl(1, 9, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG")
if os.getppid() != parent:
    os._exit(125)
resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
raw = struct.pack("<8Q", int.from_bytes(b"NSLIMIT1", "little"),
    *resource.getrlimit(resource.RLIMIT_CPU),
    *resource.getrlimit(resource.RLIMIT_AS),
    *resource.getrlimit(resource.RLIMIT_CORE), os.getpid())
at = 0
while at < len(raw):
    try:
        count = os.write(ready, raw[at:])
    except InterruptedError:
        continue
    if count <= 0:
        raise OSError("zero limit receipt write")
    at += count
os.close(ready)
os.execv(sys.argv[3], sys.argv[3:])
"""

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def frame(command, *, session=(71,83), call=0, action=0, lease=0, handle=0,
          a=0,b=0,c=0,d=0,e=0,f=0,g=0,h=0,i=0,body=b""):
    return struct.pack("<32Q",MAGIC,command,*session,call,action,lease,handle,
        a,b,c,d,e,f,g,h,len(body),i,*([0]*14))+body

class Carrier:
    def __init__(self, executable, output, cwd, *, session=(71,83), initialize=True, launcher=()):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.session = session
        self.call_number = 0
        self.requests = []
        self.completed = False
        self.expected_exit = 0
        self.started = time.monotonic_ns()
        self.deadline = time.monotonic() + LIMITS["wall_seconds"]
        self.process = None
        self._reap_lock = threading.Lock()
        self._observed = None
        self._watchdog = None
        self._watchdog_fired = False
        self._watchdog_error = None
        self._wall_kill_sent = False
        self._ready_read = self._ready_write = None
        self.native_identity = None
        self.launcher = list(map(str, launcher))
        self.trace_file = (self.output / "trace.bin").open("wb")
        executable = Path(executable).resolve()
        raw = executable.read_bytes()
        self.executable_pin = dict(path=str(executable), bytes=len(raw), sha256=sha(raw),
                                   mode=stat.S_IMODE(executable.stat().st_mode))
        env = dict(PATH="", HOME="", LC_ALL="C", LANG="C")
        try:
            self._ready_read, self._ready_write = os.pipe2(os.O_CLOEXEC)
            argv = [sys.executable, "-I", "-S", "-c", LIMIT_LAUNCHER,
                    str(self._ready_write), str(os.getpid()), *self.launcher, str(executable)]
            self.process = subprocess.Popen(argv, cwd=cwd, env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.trace_file,
                bufsize=0, start_new_session=True, pass_fds=(self._ready_write,))
            os.close(self._ready_write); self._ready_write = None
            self.trace_file.close()
            self._watchdog = threading.Timer(max(0, self.deadline - time.monotonic()), self._expire)
            self._watchdog.daemon = True
            self._watchdog.start()
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            os.set_blocking(self._ready_read, False)
            ready = bytearray()
            ready_deadline = min(self.deadline, time.monotonic() + LIMITS["request_wall_seconds"])
            while len(ready) < 64:
                remaining = ready_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("private process limit installation deadline")
                readable, _, _ = select.select([self._ready_read], [], [], remaining)
                if not readable:
                    raise TimeoutError("private process limit installation deadline")
                try:
                    chunk = os.read(self._ready_read, 64 - len(ready))
                except (InterruptedError, BlockingIOError):
                    continue
                if not chunk:
                    raise EOFError("private process limit receipt truncated")
                ready.extend(chunk)
            os.close(self._ready_read); self._ready_read = None
            (self.output / "limit-receipt.bin").write_bytes(ready)
            actual_limits = struct.unpack("<8Q", ready)
            assert actual_limits == (LIMIT_MAGIC, 90, 90, 1 << 30, 1 << 30, 0, 0, self.process.pid)
            save(self.output / "start.json", dict(pid=self.process.pid, cwd=str(cwd),
                 executable=self.executable_pin, env=env, standalone_private_component=True,
                 actual_children_chosen_by_HIA_only=True, limits=LIMITS,
                 actual_limit_receipt=list(actual_limits),
                 limit_launcher_sha256=sha(LIMIT_LAUNCHER.encode()),
                 limit_launcher_interpreter=sys.executable,
                 parent_pid=os.getpid(),explicit_fault_launcher=self.launcher))
            if initialize:
                header, _ = self.request(frame(1,session=session,a=171,b=183,f=3,g=420,h=3), label="initialize")
                assert header[1]==0 and header[4]==0 and header[5]==1
                assert header[6:8]==(0,0) and header[12]==1 and header[22]==3
                self._bind_native_identity()
        except BaseException as error:
            try:
                self.abort()
            except BaseException as cleanup:
                error.add_note("Carrier construction cleanup: " + repr(cleanup))
            raise

    def _write(self, raw, deadline):
        view = memoryview(raw)
        descriptor = self.process.stdin.fileno()
        at = 0
        while at < len(raw):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("private carrier request deadline")
            _, ready, _ = select.select([], [descriptor], [], remaining)
            if not ready:
                raise TimeoutError("private carrier request deadline")
            try:
                count = os.write(descriptor, view[at:])
            except InterruptedError:
                continue
            except BlockingIOError:
                continue
            if count <= 0:
                raise OSError("zero-length write to private carrier")
            at += count

    def _read(self, count, deadline):
        result = bytearray()
        descriptor = self.process.stdout.fileno()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("private carrier response deadline")
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                raise TimeoutError("private carrier response deadline")
            try:
                raw = os.read(descriptor, min(65536, count - len(result)))
            except InterruptedError:
                continue
            except BlockingIOError:
                continue
            if not raw:
                raise EOFError(("private carrier response truncated", count, len(result)))
            result.extend(raw)
        return bytes(result)

    def request(self, raw, *, label="request"):
        assert not self.completed
        raw = bytes(raw)
        index = len(self.requests)
        directory = self.output / "requests" / str(index)
        directory.mkdir(parents=True)
        (directory / "input.bin").write_bytes(raw)
        row = dict(index=index, label=label, input_bytes=len(raw), input_sha256=sha(raw),
                   status="INCOMPLETE")
        self.requests.append(row)
        save(directory / "result.json", row)
        start = time.monotonic_ns()
        try:
            deadline = min(self.deadline, time.monotonic() + LIMITS["request_wall_seconds"])
            self._write(struct.pack("<Q", len(raw)) + raw, deadline)
            capacity = struct.unpack("<Q", self._read(8, deadline))[0]
            # Resource guard for this finite test corpus, not a production quota.
            assert 256 <= capacity <= 16 << 20, ("unexpected fixture output capacity", capacity)
            output = self._read(capacity, deadline)
            (directory / "output.bin").write_bytes(output)
            header = struct.unpack_from("<32Q", output)
            assert header[0] == MAGIC and header[1] in (0,0xfffffffd)
            assert header[16]<=len(output)-256 and header[22]==3 and not any(header[29:])
            row.update(status="COMPLETE", output_bytes=len(output), output_sha256=sha(output),
                       header=list(header), elapsed_ns=time.monotonic_ns() - start)
            save(directory / "result.json", row)
            save(self.output / "requests.json", self.requests)
            return header, output[256:256 + header[16]]
        except BaseException as error:
            row.update(status="FAIL", error_class=type(error).__name__, error=str(error),
                       elapsed_ns=time.monotonic_ns() - start)
            save(directory / "result.json", row)
            save(self.output / "requests.json", self.requests)
            raise

    def call(self,command,handle=0,*,a=0,b=0,c=0,d=0,e=0,f=0,g=0,h=0,i=0,
             body=b"",expect_code=0,expect_errno=0):
        self.call_number+=1
        header,payload=self.request(frame(command,session=self.session,call=self.call_number,
            handle=handle,a=a,b=b,c=c,d=d,e=e,f=f,g=g,h=h,i=i,body=body,
            lease=1000+self.call_number),label="command-"+str(command))
        assert (header[1],header[6],header[7])==(0,expect_code,expect_errno),(command,header)
        assert header[4]==self.call_number
        # Terminal q12 is the selected node isUnlocked, not a dedicated phase.
        # The whole traced workspace is checked by the independent VM replay.
        return header,payload

    def filesystem(self,operation,*,a=0,b=0,c=0,d=0,body=b"",expect_errno=0):
        header,payload=self.call(16,a=operation,b=a,c=b,d=c,e=d,body=body)
        assert header[23]==len(payload) and len(payload)>=256
        result=struct.unpack_from("<32Q",payload)
        assert result[0]==int.from_bytes(b"HIANFR03","little")
        assert result[1]==0 and result[6]==operation and result[7]==expect_errno
        assert result[16]<=len(payload)-256 and result[22]==3
        return result,payload[256:256+result[16]]

    def _bind_native_identity(self):
        assert self.process is not None and self.process.returncode is None
        if self.launcher:
            # The explicit strace process owns one tracee. Read only this exact
            # known parent's direct children; never search unrelated processes.
            children = Path("/proc") / str(self.process.pid) / "task" / str(self.process.pid) / "children"
            candidates = [int(value) for value in children.read_text().split()]
            assert len(candidates) == 1, ("expected exact owned strace tracee", candidates)
            pid = candidates[0]
        else:
            pid = self.process.pid
        root = Path("/proc") / str(pid)
        actual = (root / "exe").read_bytes()
        assert (len(actual), sha(actual)) == (self.executable_pin["bytes"], self.executable_pin["sha256"])
        suffix = (root / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        parent = int(suffix[1]); start_ticks = int(suffix[19])
        assert parent == (self.process.pid if self.launcher else os.getpid())
        actual = dict(cpu=list(resource.prlimit(pid, resource.RLIMIT_CPU)),
                      address=list(resource.prlimit(pid, resource.RLIMIT_AS)),
                      core=list(resource.prlimit(pid, resource.RLIMIT_CORE)))
        assert actual == dict(cpu=[90,90], address=[1 << 30,1 << 30], core=[0,0])
        self.native_identity = dict(pid=pid, parent_pid=parent, start_ticks=start_ticks,
                                    executable_sha256=self.executable_pin["sha256"], actual_limits=actual)
        save(self.output / "native-identity.json", self.native_identity)
        return pid

    def owned_native_pid(self):
        if self.native_identity is None:
            return self._bind_native_identity()
        row = self.native_identity
        root = Path("/proc") / str(row["pid"])
        suffix = (root / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        assert (int(suffix[1]), int(suffix[19])) == (row["parent_pid"], row["start_ticks"])
        original = Path(self.executable_pin["path"]).stat()
        actual = (root / "exe").stat()
        assert (actual.st_dev, actual.st_ino) == (original.st_dev, original.st_ino)
        return row["pid"]

    def snapshot_owned_process(self, label):
        root = Path("/proc") / str(self.owned_native_pid())
        maps = (root / "maps").read_bytes()
        (self.output / (label + ".maps")).write_bytes(maps)
        descriptors = []
        for path in sorted((root / "fd").iterdir(), key=lambda p: int(p.name)):
            descriptors.append(dict(fd=int(path.name), target=os.readlink(path)))
        save(self.output / (label + ".fds.json"), descriptors)
        # This reads only the exact test child; it never scans unrelated processes.
        return maps, descriptors

    def _wait_once_locked(self):
        process = self.process
        if process is None or process.returncode is not None:
            return self._observed
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if not pid:
            return None
        process.returncode = os.waitstatus_to_exitcode(status)
        self._observed = dict(wait_status=status, returncode=process.returncode,
            usage=dict(user=usage.ru_utime, system=usage.ru_stime, maxrss_kib=usage.ru_maxrss))
        return self._observed

    def _kill_locked(self):
        # All wait4/reap and kill decisions share this lock. An unreaped child
        # anchors the process-group ID; no timer can signal a recycled PID.
        if self.process is not None and self.process.returncode is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _expire(self):
        try:
            with self._reap_lock:
                if self._wait_once_locked() is None and self.process is not None:
                    self._watchdog_fired = True
                    self._wall_kill_sent = True
                    self._kill_locked()
        except BaseException as error:
            self._watchdog_error = repr(error)

    def _stop_watchdog(self):
        timer = self._watchdog
        if timer is not None:
            timer.cancel()
            if timer is not threading.current_thread():
                timer.join(timeout=1)
                assert not timer.is_alive(), "wall watchdog cleanup incomplete"

    def _budget_observation(self):
        return dict(limits=LIMITS, wall_watchdog_fired=self._watchdog_fired,
                    wall_kill_sent=self._wall_kill_sent, watchdog_error=self._watchdog_error,
                    actual_native_identity=self.native_identity)

    def _reap(self, timeout, force=False):
        if self.process is None:
            return None
        deadline = min(self.deadline, time.monotonic() + timeout)
        killed_at = None
        while True:
            with self._reap_lock:
                observed = self._wait_once_locked()
                if observed is not None:
                    return observed
                now = time.monotonic()
                if killed_at is None and (force or now >= deadline or self._wall_kill_sent):
                    if now >= self.deadline:
                        self._wall_kill_sent = True
                    self._kill_locked()
                    killed_at = now
            if killed_at is not None and time.monotonic() - killed_at >= LIMITS["killed_reap_wall_seconds"]:
                raise TimeoutError("SIGKILL sent but exact child wait4 cleanup incomplete")
            time.sleep(0.01)

    def finish(self, expected_exit=0):
        if self.completed:
            assert self.process.returncode == expected_exit
            return
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        observed = self._reap(LIMITS["normal_reap_wall_seconds"])
        self._stop_watchdog()
        if self.process.stdout is not None and not self.process.stdout.closed:
            extra = self.process.stdout.read() or b""
            self.process.stdout.close()
        else:
            extra = b""
        (self.output / "unframed-stdout.bin").write_bytes(extra)
        trace = (self.output / "trace.bin").read_bytes()
        now = Path(self.executable_pin["path"]).read_bytes()
        result = dict(observed or {}, **self._budget_observation(), expected_exit=expected_exit,
                      elapsed_ns=time.monotonic_ns() - self.started,
                      trace_bytes=len(trace), trace_sha256=sha(trace),
                      source_unchanged=(len(now), sha(now)) ==
                          (self.executable_pin["bytes"], self.executable_pin["sha256"]),
                      unframed_stdout_bytes=len(extra), unframed_stdout_sha256=sha(extra))
        save(self.output / "process.json", result)
        self.completed = True
        assert not result["wall_kill_sent"] and result["watchdog_error"] is None, result
        assert result["source_unchanged"]
        assert self.process.returncode == expected_exit, result
        assert extra == b"", ("unexpected unframed stdout", extra[:128])
        return result

    def abort(self):
        observed = None
        try:
            if self.process is not None:
                observed = self._reap(1, force=True)
        finally:
            self._stop_watchdog()
            save(self.output / "abort.json", dict(observed or {}, **self._budget_observation()))
            if self.process is not None:
                for stream in (self.process.stdin, self.process.stdout):
                    if stream is not None and not stream.closed:
                        stream.close()
            for name in ("_ready_read", "_ready_write"):
                descriptor = getattr(self, name)
                if descriptor is not None:
                    os.close(descriptor); setattr(self, name, None)
            if not self.trace_file.closed:
                self.trace_file.close()

    def __enter__(self):
        return self

    def __exit__(self, typ, value, tb):
        if value is None:
            try:
                self.finish(self.expected_exit)
            except BaseException as error:
                try:
                    self.abort()
                except BaseException as cleanup:
                    error.add_note("Carrier finish cleanup: " + repr(cleanup))
                raise
        else:
            try:
                self.abort()
            except BaseException as cleanup:
                value.add_note("Carrier test cleanup: " + repr(cleanup))
        return False
