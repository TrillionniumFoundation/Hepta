"""Diagnostic native loan handshakes bound to one verified Core location.

This is an explicitly instrumented Linux/x86-64 experiment, never a production
lowering or a performance instrument. It observes the first execution of one
local loan and adds two records and one host acknowledgement to that interval.
No user callback, foreign pointer, arbitrary IR or library path is admitted.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
from threading import Condition, Event, Thread
from time import monotonic, sleep

from .artifact_publication import publish_verified, verify_published, withdraw_own_link
from .clang_capture import run_bounded
from .elf_shared_abi import inspect_owned_shared_elf
from . import hia_native_differential as native
from . import hia_program_llvm as llvm
from .hia_program import verify_program
from .native_tool_identity import digest_executable

PROFILE = "hepta.hia.native-loan-probe.v1"
CONFIGURE = "__hia_loan_probe_configure"
_MAGIC = 0x4849414C4F414E31
_RECORD = struct.Struct("<QQQQQ")
_ACK = b"\xa5"


def _reject(message):
    raise native.HIADifferentialRejected("E_HIA_LOAN_PROBE: " + message)


def checked_site(site):
    if (type(site) is not tuple or len(site) != 3
            or any(type(part) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,127}", part) is None
                   for part in site)):
        _reject("site must be an exact (function, block, loan) identifier tuple")
    return tuple(site)


def _locate(core, site):
    site = checked_site(site)
    document = core.as_dict()
    function = next((fn for fn in document["functions"] if fn["name"] == site[0]), None)
    block = next((block for block in function["blocks"] if block["id"] == site[1]), None) if function else None
    if block is None:
        _reject("loan site function/block is absent")
    call_graph = {fn["name"]: {op["attrs"]["function"] for basic in fn["blocks"]
                              for op in basic["ops"] if op["op"] == "call"}
                  for fn in document["functions"]}
    pending, visited = list(call_graph[site[0]]), set()
    while pending:
        callee = pending.pop()
        if callee == site[0]:
            _reject("selected loan function must not recursively re-enter itself")
        if callee not in visited:
            visited.add(callee)
            pending.extend(call_graph[callee])
    matches = [(index, op) for index, op in enumerate(block["ops"])
               if op["op"] in {"borrow.read", "borrow.mut"}
               and op["out"][0]["name"] == site[2]]
    if len(matches) != 1:
        _reject("site must identify one direct buffer borrow")
    start, borrow = matches[0]
    ends = [(index, op) for index, op in enumerate(block["ops"])
            if op["op"] == "loan.end" and op["args"] == [site[2]]]
    if len(ends) != 1 or ends[0][0] <= start:
        _reject("selected loan must end later in the same verified block")
    owner = borrow["args"][0]
    allocation = [(index, op) for index, op in enumerate(block["ops"][:start])
                  if op["op"] in {"buffer.new", "buffer.try_new"}
                  and op["out"][0]["name"] == owner]
    if len(allocation) != 1:
        _reject("selected borrow requires a local allocation in the same block")
    end, end_op = ends[0]
    witness = {"function": site[0], "block": site[1], "loan": site[2],
               "owner": owner, "borrow_operation": borrow["op"],
               "allocation_index": allocation[0][0], "borrow_index": start, "end_index": end,
               "observed_dynamic_occurrence": "first only", "same_block_end_required": True,
               "selected_function_reentrant": False,
               "diagnostic_zero_initialization": "forced for selected function allocations"}
    return document, function, borrow, end_op, witness


# The diagnostic protocol uses only fixed read(0) and write(1) Linux syscalls.
# It adds no dynamic imports, and the ordinary native observer's seccomp policy
# already permits descriptor IO. The ~{memory} clobber and volatile byte reads
# make these observable instrumentation points; this is still compiler trust,
# not a formal proof of instruction scheduling or uninstrumented refinement.
_RUNTIME = r'''
@__hia_probe_event_fd = internal global i32 -1
@__hia_probe_ack_fd = internal global i32 -1
@__hia_probe_state = internal global i32 0

define i32 @__hia_loan_probe_configure(i32 %event, i32 %ack) noinline {
entry:
  %old = load volatile i32, ptr @__hia_probe_event_fd
  %fresh = icmp eq i32 %old, -1
  %eok = icmp sge i32 %event, 3
  %aok = icmp sge i32 %ack, 3
  %different = icmp ne i32 %event, %ack
  %ok0 = and i1 %fresh, %eok
  %ok1 = and i1 %aok, %different
  %ok = and i1 %ok0, %ok1
  br i1 %ok, label %ready, label %bad
ready:
  store volatile i32 %event, ptr @__hia_probe_event_fd
  store volatile i32 %ack, ptr @__hia_probe_ack_fd
  ret i32 0
bad:
  call void @abort()
  unreachable
}

define internal void @__hia_probe_record(i64 %phase, %hia.buffer %view) noinline {
entry:
  %pointer = extractvalue %hia.buffer %view, 0
  %length = extractvalue %hia.buffer %view, 1
  %positive = icmp ne i64 %length, 0
  br i1 %positive, label %read_bytes, label %record
read_bytes:
  %first_byte = load volatile i8, ptr %pointer, align 1
  %last_index = sub i64 %length, 1
  %last_ptr = getelementptr i8, ptr %pointer, i64 %last_index
  %last_byte = load volatile i8, ptr %last_ptr, align 1
  %first_wide = zext i8 %first_byte to i64
  %last_wide = zext i8 %last_byte to i64
  br label %record
record:
  %first = phi i64 [ 0, %entry ], [ %first_wide, %read_bytes ]
  %last = phi i64 [ 0, %entry ], [ %last_wide, %read_bytes ]
  %packet = alloca [5 x i64], align 8
  %p1 = getelementptr [5 x i64], ptr %packet, i64 0, i64 1
  %p2 = getelementptr [5 x i64], ptr %packet, i64 0, i64 2
  %p3 = getelementptr [5 x i64], ptr %packet, i64 0, i64 3
  %p4 = getelementptr [5 x i64], ptr %packet, i64 0, i64 4
  store i64 5208766240033689137, ptr %packet, align 8
  store i64 %phase, ptr %p1, align 8
  store i64 %length, ptr %p2, align 8
  store i64 %first, ptr %p3, align 8
  store i64 %last, ptr %p4, align 8
  %fd32 = load volatile i32, ptr @__hia_probe_event_fd
  %fd = sext i32 %fd32 to i64
  %written = call i64 asm sideeffect "syscall", "={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},~{flags}"(i64 1, i64 %fd, ptr %packet, i64 40)
  %ok = icmp eq i64 %written, 40
  br i1 %ok, label %done, label %bad
done:
  ret void
bad:
  call void @abort()
  unreachable
}

define internal void @__hia_probe_begin(%hia.buffer %view) noinline {
entry:
  %state = load volatile i32, ptr @__hia_probe_state
  %first = icmp eq i32 %state, 0
  br i1 %first, label %observe, label %done
observe:
  store volatile i32 1, ptr @__hia_probe_state
  call void @__hia_probe_record(i64 1, %hia.buffer %view)
  %ack = alloca i8, align 1
  %fd32 = load volatile i32, ptr @__hia_probe_ack_fd
  %fd = sext i32 %fd32 to i64
  %read = call i64 asm sideeffect "syscall", "={rax},{rax},{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory},~{dirflag},~{fpsr},~{flags}"(i64 0, i64 %fd, ptr %ack, i64 1)
  %read_ok = icmp eq i64 %read, 1
  br i1 %read_ok, label %check, label %bad
check:
  %byte = load i8, ptr %ack, align 1
  %ack_ok = icmp eq i8 %byte, -91
  br i1 %ack_ok, label %done, label %bad
done:
  ret void
bad:
  call void @abort()
  unreachable
}

define internal void @__hia_probe_end(%hia.buffer %view) noinline {
entry:
  %state = load volatile i32, ptr @__hia_probe_state
  %active = icmp eq i32 %state, 1
  br i1 %active, label %observe, label %done
observe:
  call void @__hia_probe_record(i64 2, %hia.buffer %view)
  store volatile i32 2, ptr @__hia_probe_state
  br label %done
done:
  ret void
}
'''


def _implementation_hash():
    digest = sha256(llvm._implementation_hash().encode())
    for name in ("hia_native_loan_probe.py", "hia_native_version_dispatch.py", "hia_native_differential.py"):
        digest.update(name.encode() + b"\0" + (Path(__file__).parent / name).read_bytes() + b"\0")
    return digest.hexdigest()


def emit_probe(core, site):
    """Regenerate ordinary IR, substitute one deterministically re-emitted body."""
    before = _implementation_hash()
    core = verify_program(core)
    if core.structured_bytes is not None or core.as_dict()["schema"] not in {
            "hepta.hia.program.v1", "hepta.hia.program.v2", "hepta.hia.program.v3",
            "hepta.hia.program.v4", "hepta.hia.program.v5", "hepta.hia.program.v6"}:
        _reject("loan diagnostic admits primitive v1-v6 only")
    document, function, begin, end, witness = _locate(core, site)
    ordinary = llvm.emit_program_llvm(core)
    parent = llvm._Emitter(document, llvm.TARGET, core.scalar_entrypoints)
    number = parent.indices[function["name"]]
    normal_body = llvm._FunctionEmitter(parent, function, number).render()

    class ProbeEmitter(llvm._FunctionEmitter):
        def __init__(self, *args):
            super().__init__(*args)
            # The probe observes endpoint bytes even when ordinary execution
            # never reads them. Such diagnostics invalidate the ordinary
            # unread-allocation optimization, so preserve Core's zero bytes.
            self.zero_bytes = "true"

        def operation(self, operation):
            super().operation(operation)
            if operation is begin:
                self.line("call void @__hia_probe_begin(" + self.scalar(site[2]) + ")")
            elif operation is end:
                # The owner is usable again after loan.end; observe it before
                # the next Core instruction (including any owner.drop).
                self.line("call void @__hia_probe_end(" + self.scalar(witness["owner"]) + ")")

    probe_body = ProbeEmitter(parent, function, number).render()
    if ordinary.text.count(normal_body) != 1:
        _reject("ordinary emitter body identity is not unique")
    text = ordinary.text.replace(normal_body, probe_body, 1) + _RUNTIME
    if len(text.encode("ascii")) > llvm.MAX_LLVM_BYTES or _implementation_hash() != before:
        _reject("probe emission budget or implementation identity changed")
    return {"text": text, "sha256": sha256(text.encode()).hexdigest(),
            "ordinary_llvm_sha256": ordinary.sha256, "core_sha256": core.sha256,
            "implementation_sha256": before, "exports": tuple(sorted((*ordinary.exports, CONFIGURE))),
            "site": witness, "profile": PROFILE}


def compile_probe(core, site, output, clang):
    """Compile only internally re-emitted diagnostic IR; inspect/publish bytes."""
    core = verify_program(core)
    ir = emit_probe(core, site)
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        _reject("loan probe requires Linux x86-64")
    found = shutil.which(clang)
    if found is None:
        _reject("actual Clang 20+ required")
    compiler = Path(found).resolve()
    compiler_digest = digest_executable(compiler)
    version = run_bounded([str(compiler), "--version"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    target = run_bounded([str(compiler), "-dumpmachine"], timeout=10, stdout_limit=65536, stderr_limit=65536)
    if (version.returncode or target.returncode
            or re.search(r"clang version (?:2[0-9]|[3-9][0-9])\.", version.stdout) is None
            or target.stdout.strip() not in {llvm.TARGET, "x86_64-pc-linux-gnu"}):
        _reject("actual Clang 20+ Linux x86-64 driver required")
    destination = Path(os.path.abspath(output))
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        _reject("new diagnostic output path required")
    with tempfile.TemporaryDirectory(prefix=".hia-loan-probe-", dir=destination.parent) as directory:
        source, artifact = Path(directory) / "probe.ll", Path(directory) / "probe.so"
        source.write_text(ir["text"], encoding="ascii")
        flags = ["--target=" + llvm.TARGET, "-x", "ir", "-O3", "-fPIC", "-shared"]
        compiled = run_bounded([str(compiler), *flags, str(source), "-o", str(artifact)],
                               timeout=60, stdout_limit=65536, stderr_limit=1048576)
        if compiled.returncode:
            _reject("Clang rejected diagnostic IR: " + compiled.stderr[:3000])
        data = llvm._read_artifact(artifact)
        inventory = inspect_owned_shared_elf(data, ir["exports"])
        if digest_executable(compiler) != compiler_digest or emit_probe(core, site) != ir:
            _reject("diagnostic source, site or compiler changed during build")
        published = publish_verified(artifact, destination, data)
        try:
            if digest_executable(compiler) != compiler_digest or _implementation_hash() != ir["implementation_sha256"]:
                _reject("diagnostic identity changed during publication")
            verify_published(artifact, destination, data)
        except BaseException:
            withdraw_own_link(artifact, destination)
            raise
    receipt = {"schema": "hepta.hia.native-loan-probe-build.v1", "ok": True,
               "status": "native_compiled_not_executed", "profile": PROFILE, "target": llvm.TARGET,
               "kind": "shared", "core_sha256": ir["core_sha256"], "llvm_ir_sha256": ir["sha256"],
               "ordinary_llvm_ir_sha256": ir["ordinary_llvm_sha256"],
               "implementation_sha256": ir["implementation_sha256"],
               "artifact_sha256": published["sha256"], "artifact_bytes": published["bytes"],
               "exports": list(ir["exports"]), "binary_inventory": inventory, "flags": flags,
               "toolchain": {"path": str(compiler), "sha256": compiler_digest,
                             "version": version.stdout.splitlines()[0], "default_target": target.stdout.strip()},
               "loan_probe_site": ir["site"], "llvm_ir": ir["text"],
               "claims": {"diagnostic_instrumentation": True, "production_artifact": False,
                          "same_uninstrumented_timing": False, "backend_refinement_proved": False}}
    return ir, receipt


# Reuse the exact pre-dlopen isolation setup, with no weakening of its policy.
_ENTRY_MARKER = "lib, symbol, word, packed = sys.argv[1:]\n"
if native._WORKER.count(_ENTRY_MARKER) != 1:
    raise RuntimeError("native observer entry boundary changed; probe must be reviewed")
_WORKER = native._WORKER.split(_ENTRY_MARKER, 1)[0] + r'''
lib, symbol, word, packed, event_fd, ack_fd = sys.argv[1:]
args = json.loads(packed)
library = ctypes.CDLL(lib)
configure = getattr(library, "__hia_loan_probe_configure")
configure.argtypes = [ctypes.c_int32, ctypes.c_int32]
configure.restype = ctypes.c_int32
if configure(int(event_fd), int(ack_fd)) != 0:
    raise RuntimeError("native loan probe configuration failed")
c = ctypes.c_int32 if word == "i32" else ctypes.c_uint32
f = getattr(library, symbol)
f.argtypes = [c] * len(args)
f.restype = c
print(json.dumps({"value": int(f(*args))}, separators=(",", ":")), flush=True)
'''


class NativeLoanExecution:
    """One bounded diagnostic child. Constructed only by the dispatcher.

    A held call has a finite native timeout even when its caller never resumes
    it. Snapshot reports partial observations after failure; wait rethrows it.
    """

    def __init__(self, *, version, generation, function, word, arguments, timeout, release):
        self._version, self._generation = version, generation
        self._function, self._word, self._arguments = function, word, arguments
        self._timeout, self._release = timeout, release
        self._condition = Condition()
        self._resume = Event()
        self._events, self._done, self._error, self._result = [], False, None, None
        self._ack_sent = False
        self._thread = Thread(target=self._run, name="hia-native-loan-probe", daemon=False)
        self._thread.start()

    def wait_active(self, *, timeout=5.0):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            _reject("active wait timeout must be in (0,10]")
        deadline = monotonic() + timeout
        with self._condition:
            while not self._events and not self._done:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    _reject("selected native loan was not observed within wait deadline")
                self._condition.wait(remaining)
            if self._error:
                raise self._error
            if not self._events or self._ack_sent or self._done:
                _reject("selected native loan is no longer held")
            return self.snapshot()

    def resume(self):
        with self._condition:
            if self._done or not self._events or self._ack_sent or self._resume.is_set():
                _reject("resume requires one currently held native loan")
            self._resume.set()

    def wait(self, *, timeout=10.0):
        if type(timeout) not in (int, float) or not 0 < timeout <= 12:
            _reject("completion wait timeout must be in (0,12]")
        deadline = monotonic() + timeout
        with self._condition:
            while not self._done:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    _reject("native loan execution still owns its dispatch reference")
                self._condition.wait(remaining)
            if self._error:
                raise self._error
            return json.loads(json.dumps(self._result))

    def snapshot(self):
        with self._condition:
            return {"schema": "hepta.hia.native-loan-observation.v1", "generation": self._generation,
                    "program_sha256": self._version.core_sha256,
                    "artifact_sha256": self._version.artifact_sha256,
                    "site": self._version.receipt()["loan_probe_site"],
                    "events": json.loads(json.dumps(self._events)), "ack_sent": self._ack_sent,
                    "done": self._done, "held": bool(self._events) and not self._ack_sent and not self._done,
                    "error": None if self._error is None else {"type": type(self._error).__name__, "message": str(self._error)},
                    "claims": {"diagnostic_instrumentation": True, "selected_loan_only": True,
                               "full_resource_ledger_observed": False, "all_bytes_observed": False,
                               "production_timing_qualified": False, "backend_refinement_proved": False}}

    def _record(self, raw):
        magic, phase, length, first, last = _RECORD.unpack(raw)
        with self._condition:
            expected = len(self._events) + 1
            if (magic != _MAGIC or phase != expected or phase not in (1, 2)
                    or length > (1 << 63) - 1 or first > 255 or last > 255
                    or (length == 0 and (first or last))
                    or (phase == 2 and (not self._ack_sent or length != self._events[0]["bytes"]))):
                _reject("invalid, duplicate or out-of-order native loan record")
            self._events.append({"event": "loan_started" if phase == 1 else "loan_ended",
                                 "bytes": length, "first_byte": first, "last_byte": last,
                                 "selected_loan_active": phase == 1})
            self._condition.notify_all()

    def _observe(self):
        descriptors = []
        try:
            event_read, event_write = os.pipe2(os.O_CLOEXEC)
            descriptors += [event_read, event_write]
            ack_read, ack_write = os.pipe2(os.O_CLOEXEC)
            descriptors += [ack_read, ack_write]
            os.set_blocking(event_read, False)
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                proc = subprocess.Popen([sys.executable, "-I", "-S", "-c", _WORKER,
                    "/proc/self/fd/" + str(self._version.descriptor), self._function, self._word,
                    json.dumps(self._arguments, separators=(",", ":")), str(event_write), str(ack_read)],
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                    env={"LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
                    pass_fds=(self._version.descriptor, event_write, ack_read), start_new_session=True)
                for fd in (event_write, ack_read):
                    os.close(fd)
                    descriptors.remove(fd)
                deadline = monotonic() + self._timeout
                timed_out, residual_group = False, False
                pending = b""
                try:
                    while True:
                        try:
                            chunk = os.read(event_read, 81)
                        except BlockingIOError:
                            chunk = b""
                        pending += chunk
                        if len(pending) + _RECORD.size * len(self._events) > 2 * _RECORD.size:
                            _reject("native loan record budget exceeded")
                        while len(pending) >= _RECORD.size:
                            self._record(pending[:_RECORD.size])
                            pending = pending[_RECORD.size:]
                        with self._condition:
                            if self._events and self._resume.is_set() and not self._ack_sent:
                                if os.write(ack_write, _ACK) != 1:
                                    _reject("native loan acknowledgement write failed")
                                self._ack_sent = True
                        status = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                        if status is not None:
                            # A final event can arrive between the preceding read and exit.
                            try:
                                tail = os.read(event_read, 81)
                            except BlockingIOError:
                                tail = b""
                            pending += tail
                            while len(pending) >= _RECORD.size:
                                self._record(pending[:_RECORD.size])
                                pending = pending[_RECORD.size:]
                            if pending:
                                _reject("truncated native loan record")
                            residual_group = native._has_in_group_descendant(proc.pid)
                            break
                        remaining = deadline - monotonic()
                        if remaining <= 0:
                            timed_out = True
                            break
                        sleep(min(0.005, remaining))
                finally:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        proc.wait(timeout=2)
                if timed_out:
                    _reject("native child timed out while loan execution remained tracked; process group terminated")
                if residual_group:
                    _reject("native child left surviving descendants")
                out.seek(0)
                err.seek(0)
                stdout, stderr = out.read(4097), err.read(4097)
                if len(stdout) >= 4096 or len(stderr) >= 4096:
                    _reject("native child exceeded output budget")
                if proc.returncode == -signal.SIGABRT and not stdout and not stderr:
                    return "trap", None
                if proc.returncode != 0 or stderr:
                    _reject("native child exited with unexpected error/signal " + str(proc.returncode))
                try:
                    observed = json.loads(stdout)
                except (ValueError, UnicodeError) as error:
                    raise native.HIADifferentialRejected("E_HIA_LOAN_PROBE: invalid native result") from error
                low, high = native._TYPES[self._word]
                if (type(observed) is not dict or set(observed) != {"value"}
                        or type(observed["value"]) is not int or not low <= observed["value"] <= high
                        or stdout != native._canonical(observed) + b"\n"):
                    _reject("native child result differs from canonical scalar record")
                if len(self._events) != 2 or not self._ack_sent:
                    _reject("normal return did not observe the selected loan interval")
                return "value", observed["value"]
        finally:
            for fd in descriptors:
                os.close(fd)

    def _run(self):
        try:
            outcome, value = self._observe()
            self._result = {"schema": "hepta.hia.native-loan-execution.v1", "generation": self._generation,
                            "program_sha256": self._version.core_sha256,
                            "artifact_sha256": self._version.artifact_sha256,
                            "status": "returned" if outcome == "value" else "trapped", "value": value,
                            "native_observation": outcome, "observation": None,
                            "claims": {"actual_native_child_executed": True, "sealed_image_used": True,
                                       "diagnostic_instrumentation": True, "native_trap_reason_proved": False,
                                       "full_resource_ledger_observed": False, "external_state_migrated": False}}
        except BaseException as error:
            self._error = error
        finally:
            try:
                self._release()
            except BaseException as error:
                self._error = self._error or error
            finally:
                with self._condition:
                    self._done = True
                    if self._result is not None:
                        self._result["observation"] = self.snapshot()
                    self._condition.notify_all()
