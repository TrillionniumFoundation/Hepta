"""Private fixture transport for the new fixed four-image DMS/map ELF.
Python records explicit test requests and raw outcomes. DMS HIA owns every
child request, map/memory continuation, actual FS initialization and retirement.
A strace launcher is an explicit fault control, never ordinary runtime.
"""
from __future__ import annotations
import ctypes, errno, hashlib, json, os, resource, select, signal, stat
import struct, subprocess, time
from pathlib import Path

MAGIC = int.from_bytes(b"HIANDM03", "little")
TRACE_MAGIC = int.from_bytes(b"HIANDT03", "little")
MASK = (1 << 64) - 1

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
        self.process = None
        self.trace_file = (self.output / "trace.bin").open("wb")
        executable = Path(executable).resolve()
        raw = executable.read_bytes()
        self.executable_pin = dict(path=str(executable), bytes=len(raw), sha256=sha(raw),
                                   mode=stat.S_IMODE(executable.stat().st_mode))
        env = dict(PATH="", HOME="", LC_ALL="C", LANG="C")
        try:
            self.process = subprocess.Popen([*map(str,launcher),str(executable)], cwd=cwd, env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.trace_file,
                bufsize=0, start_new_session=True)
            self.trace_file.close()
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            save(self.output / "start.json", dict(pid=self.process.pid, cwd=str(cwd),
                 executable=self.executable_pin, env=env, standalone_private_component=True,
                 actual_children_chosen_by_HIA_only=True,
                 parent_pid=os.getpid(),explicit_fault_launcher=list(map(str,launcher))))
            if initialize:
                header, _ = self.request(frame(1,session=session,a=171,b=183,f=3,g=420,h=3), label="initialize")
                assert header[1]==0 and header[4]==0 and header[5]==1
                assert header[6:8]==(0,0) and header[12]==1 and header[22]==3
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
            deadline = time.monotonic() + 30
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

    def snapshot_owned_process(self, label):
        root = Path("/proc") / str(self.process.pid)
        maps = (root / "maps").read_bytes()
        (self.output / (label + ".maps")).write_bytes(maps)
        descriptors = []
        for path in sorted((root / "fd").iterdir(), key=lambda p: int(p.name)):
            descriptors.append(dict(fd=int(path.name), target=os.readlink(path)))
        save(self.output / (label + ".fds.json"), descriptors)
        # This reads only the exact test child; it never scans unrelated processes.
        return maps, descriptors

    def _reap(self, timeout, force=False):
        process = self.process
        if process is None or process.returncode is not None:
            return None
        deadline = time.monotonic() + timeout
        usage = status = None
        if force:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while status is None:
            pid, code, measured = os.wait4(process.pid, os.WNOHANG)
            if pid:
                status, usage = code, measured
                process.returncode = os.waitstatus_to_exitcode(code)
                break
            if time.monotonic() >= deadline:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(0.01)
        return dict(wait_status=status, returncode=process.returncode,
                    usage=dict(user=usage.ru_utime, system=usage.ru_stime,
                               maxrss_kib=usage.ru_maxrss))

    def finish(self, expected_exit=0):
        if self.completed:
            assert self.process.returncode == expected_exit
            return
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        observed = self._reap(30)
        if self.process.stdout is not None and not self.process.stdout.closed:
            extra = self.process.stdout.read() or b""
            self.process.stdout.close()
        else:
            extra = b""
        (self.output / "unframed-stdout.bin").write_bytes(extra)
        trace = (self.output / "trace.bin").read_bytes()
        now = Path(self.executable_pin["path"]).read_bytes()
        result = dict(observed or {}, expected_exit=expected_exit,
                      elapsed_ns=time.monotonic_ns() - self.started,
                      trace_bytes=len(trace), trace_sha256=sha(trace),
                      source_unchanged=(len(now), sha(now)) ==
                          (self.executable_pin["bytes"], self.executable_pin["sha256"]),
                      unframed_stdout_bytes=len(extra), unframed_stdout_sha256=sha(extra))
        save(self.output / "process.json", result)
        self.completed = True
        assert result["source_unchanged"]
        assert self.process.returncode == expected_exit, result
        assert extra == b"", ("unexpected unframed stdout", extra[:128])
        return result

    def abort(self):
        if self.process is not None and self.process.returncode is None:
            observed = self._reap(1, force=True)
            save(self.output / "abort.json", observed)
        if self.process is not None:
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()
        if not self.trace_file.closed:
            self.trace_file.close()

    def __enter__(self):
        return self

    def __exit__(self, typ, value, tb):
        if value is None:
            try:
                self.finish(self.expected_exit)
            except BaseException:
                self.abort()
                raise
        else:
            try:
                self.abort()
            except BaseException as cleanup:
                value.add_note("Carrier test cleanup: " + repr(cleanup))
        return False
