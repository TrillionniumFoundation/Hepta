"""Verified, immutable native generations for a finite total scalar HIA profile.

This is a Linux x86-64 in-process lifecycle, not arbitrary live code patching.
Each candidate is independently compared with the original baseline before a
fresh direct-LLVM build.  Only a generation pointer changes; active leases keep
their original sealed artifact alive.  LLVM, the loader, Python and the host
remain trusted.  Finite native probes are not a backend refinement proof.
"""
from __future__ import annotations

from collections import deque
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import stat
import tempfile
import threading
import time

from .elf_shared_abi import inspect_owned_shared_elf
from .hia_program import integer_range, scalar_value_valid, verify_program
from .hia_program_llvm import TARGET, build_program_native, emit_program_llvm
from .hia_program_runtime import execute_program
from .hia_native_retirement import NativeRetirement, PathIdentityPin, observe_directory, remove_directory
from .native_mapping_identity import NativeMappingRejected, verify_loaded_symbols


PROFILE = "hepta.hia.scalar-multiversion.linux-x86_64.v1"
PROVED_TOTAL_PROFILE = "hepta.hia.scalar-multiversion-proved-total.linux-x86_64.v1"
_PROVABLE_OPS = frozenset({"int.div.checked", "int.rem.checked"})
_CTYPES = {"bool": ctypes.c_bool, "i8": ctypes.c_int8, "u8": ctypes.c_uint8,
           "i16": ctypes.c_int16, "u16": ctypes.c_uint16,
           "i32": ctypes.c_int32, "u32": ctypes.c_uint32,
           "i64": ctypes.c_int64, "u64": ctypes.c_uint64,
           "isize": ctypes.c_int64, "usize": ctypes.c_uint64}
_OPS = frozenset({"const", "select", "int.cast", "int.add.wrap", "int.sub.wrap",
                  "int.mul.wrap", "bit.and", "bit.or", "bit.xor", "bit.not",
                  "bool.not", "bool.and", "bool.or", "compare.eq", "compare.ne",
                  "compare.lt", "compare.le", "compare.gt", "compare.ge"})
_MAX_FUNCTIONS = 16
_MAX_BLOCKS = 64
_MAX_OPS = 2048
_MAX_ARTIFACT = 64 * 1024 * 1024


class MultiversionRejected(ValueError):
    """A program, proof, artifact or lifecycle transition was rejected."""


def _reject(message):
    raise MultiversionRejected("E_HIA_MULTIVERSION: " + message)


class PublicationCancellation:
    """One cancellation/commit decision, synchronized with the pointer swap.

    Cancellation is cooperative during proof and compilation. An accepted
    cancellation guarantees that this token cannot subsequently publish. A
    commit makes later cancellation return False. No caller callback runs
    under the native runtime lock.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._committed = False

    def cancel(self):
        with self._lock:
            if self._committed:
                return False
            self._event.set()
            return True

    def cancelled(self):
        return self._event.is_set()

    def committed(self):
        with self._lock:
            return self._committed

    def __copy__(self):
        _reject("publication cancellation has one synchronization owner")

    def __deepcopy__(self, memo):
        return self.__copy__()


@dataclass(frozen=True, slots=True)
class ScalarABI:
    function: str
    parameters: tuple[str, ...]
    result: str


@dataclass(frozen=True, slots=True)
class GenerationInfo:
    generation: int
    program_sha256: str
    input_sha256: str
    artifact_sha256: str
    artifact_bytes: int
    abi: tuple[ScalarABI, ...]
    translation_proofs: int
    native_probe_calls: int
    baseline: bool
    admission_profile: str = PROFILE
    totality_proofs: int = 0
    loaded_mapping: bytes = b""

    def as_dict(self):
        return {"generation": self.generation, "program_sha256": self.program_sha256,
                "input_sha256": self.input_sha256,
                "artifact_sha256": self.artifact_sha256, "artifact_bytes": self.artifact_bytes,
                "abi": [{"function": a.function, "parameters": list(a.parameters),
                         "result": a.result} for a in self.abi],
                "translation_proofs": self.translation_proofs,
                "native_probe_calls": self.native_probe_calls, "baseline": self.baseline,
                "admission_profile": self.admission_profile,
                "totality_proofs": self.totality_proofs,
                "loaded_mapping": json.loads(self.loaded_mapping) if self.loaded_mapping else None}


def _admit(document, *, prove_total=False, timeout_ms=2000):
    """Reverify exact bytes, then close the extra total/native-callable profile."""
    program = verify_program(document)
    data = program.as_dict()
    functions = data["functions"]
    if not 1 <= len(functions) <= _MAX_FUNCTIONS:
        _reject("finite profile requires one to sixteen functions")
    if program.scalar_entrypoints != frozenset(f["name"] for f in functions):
        _reject("every function must be an exported scalar function")
    abi = []
    for function in functions:
        parameters = tuple(p["type"] for p in function["params"])
        bad_effects = (set(function["effects"]) - {"trap"} if prove_total else function["effects"])
        if (bad_effects or len(parameters) > 16
                or any(t not in _CTYPES for t in parameters)
                or len(function["returns"]) != 1 or function["returns"][0] not in _CTYPES):
            _reject("only effect-free scalar signatures with one scalar result are admitted")
        blocks = function["blocks"]
        if len(blocks) > _MAX_BLOCKS or sum(len(b["ops"]) for b in blocks) > _MAX_OPS:
            _reject("finite block/instruction budget exceeded")
        graph = {}
        for block in blocks:
            if any(p["type"] not in _CTYPES for p in block["params"]):
                _reject("resource block parameters are outside the scalar profile")
            for op in block["ops"]:
                proved_operation = (prove_total and op["op"] in _PROVABLE_OPS
                                    and op["out"][0]["type"] in {"u8", "u16"})
                if (op["op"] not in _OPS and not proved_operation
                        or op["op"] == "int.cast" and op["attrs"]["mode"] != "wrap"
                        or any(p["type"] not in _CTYPES for p in op["out"])):
                    _reject("instruction may trap, allocate, call or escape the total scalar profile")
            term = block["term"]
            if term["op"] == "ret" or prove_total and term["op"] == "trap":
                graph[block["id"]] = ()
            elif term["op"] == "jump":
                graph[block["id"]] = (term["target"],)
            elif term["op"] == "branch":
                graph[block["id"]] = (term["then"]["target"], term["else"]["target"])
            else:
                _reject("trapping terminators are outside the total scalar profile")
        # The canonical verifier checks edges/types; this separate finite
        # topological check rules out unbounded native loops, even if unreachable
        # under a condition that a producer claims to be false.
        incoming = {name: 0 for name in graph}
        for targets in graph.values():
            for target in targets:
                incoming[target] += 1
        ready = [name for name, count in incoming.items() if count == 0]
        visited = 0
        while ready:
            name = ready.pop()
            visited += 1
            for target in graph[name]:
                incoming[target] -= 1
                if incoming[target] == 0:
                    ready.append(target)
        if visited != len(graph):
            _reject("cyclic control flow is outside the total scalar profile")
        abi.append(ScalarABI(function["name"], parameters, function["returns"][0]))
    abi = tuple(sorted(abi, key=lambda a: a.function))
    totality = []
    if prove_total:
        from . import hia_scalar_totality as total
        from . import hia_translation_validation as encoding
        for signature in abi:
            proof = total.validate_scalar_totality(program, function=signature.function,
                                                  timeout_ms=timeout_ms)
            expected = {"schema": total.SCHEMA, "profile": total.PROFILE,
                        "scope": "selected_public_scalar_function", "status": "proved",
                        "function": signature.function, "program_sha256": program.sha256,
                        "input_sha256": program.input_sha256,
                        "validator_sha256": total._implementation_digest(),
                        "encoder_sha256": encoding._implementation_digest(),
                        "encoder_profile": encoding.PROFILE}
            if (type(proof) is not dict or any(proof.get(k) != v for k, v in expected.items())
                    or proof.get("structural_verification") is not True
                    or type(proof.get("claims")) is not dict
                    or proof["claims"].get("all_inputs_return_normally_proved") is not True
                    or type(proof.get("solver")) is not dict
                    or proof["solver"].get("result") != "unsat"):
                _reject("fresh scalar totality did not prove every input returns normally")
            # Freeze evidence independently of a validator-owned mutable dict.
            totality.append(json.dumps(proof, sort_keys=True, separators=(",", ":"),
                                       allow_nan=False).encode())
    return program, abi, tuple(totality)


def _admissible(document):
    """The original syntactically total profile remains the default contract."""
    program, abi, _proofs = _admit(document)
    return program, abi


def _prove(baseline, candidate, abi, timeout_ms):
    from .hia_translation_validation import PROFILE as proof_profile, SCHEMA as proof_schema, validate_translation
    for signature in abi:
        proof = validate_translation(baseline, candidate, function=signature.function,
                                     timeout_ms=timeout_ms)
        # No caller receipt/ok flag is accepted. Even the fresh verifier result
        # must bind the exact independently reverified program/input pair.
        expected = {"schema": proof_schema, "profile": proof_profile,
                    "scope": "selected_public_scalar_function",
                    "status": "proved", "function": signature.function,
                    "before_sha256": baseline.sha256, "after_sha256": candidate.sha256,
                    "before_input_sha256": baseline.input_sha256,
                    "after_input_sha256": candidate.input_sha256}
        if type(proof) is not dict or any(proof.get(k) != v for k, v in expected.items()):
            status = proof.get("status", "malformed") if type(proof) is dict else "malformed"
            _reject("independent translation validation did not prove the exact pair: " + str(status))


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_artifact(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 64 <= before.st_size <= _MAX_ARTIFACT:
            _reject("native artifact is not a bounded regular file")
        data = stream.read(before.st_size + 1)
        if (len(data) != before.st_size or _file_identity(os.fstat(stream.fileno())) != _file_identity(before)
                or _file_identity(path.lstat()) != _file_identity(before)):
            _reject("native artifact changed during its exact read")
    return data, (before.st_dev, before.st_ino)


def _sealed_fd(data):
    import fcntl
    fd = os.memfd_create("hepta-hia-" + sha256(data).hexdigest(), os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _reject("sealed artifact write made no progress")
            view = view[written:]
        # Linux UAPI (linux/fcntl.h): Python built against older headers may
        # omit these names while the running kernel supports sealing. These
        # fixed Linux commands still execute and must pass kernel readback.
        seals = 0x0001 | 0x0002 | 0x0004 | 0x0008
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        if fcntl.fcntl(fd, getattr(fcntl, "F_GET_SEALS", 1034)) != seals or os.pread(fd, len(data) + 1, 0) != data:
            _reject("immutable artifact seal/readback failed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _probe_vectors(signature):
    def values(typ):
        if typ == "bool":
            return [False, True]
        lo, hi = integer_range(typ)
        return list(dict.fromkeys([lo, lo + 1, lo // 2, 0, 1, hi // 2, hi // 2 + 1, hi - 1, hi]
                                  + ([-1] if lo < 0 else [])))
    zero = tuple(False if t == "bool" else 0 for t in signature.parameters)
    cases = {zero}
    domains = [values(t) for t in signature.parameters]
    for index, domain in enumerate(domains):
        for value in domain:
            vector = list(zero)
            vector[index] = value
            cases.add(tuple(vector))
    for offset in range(7):
        cases.add(tuple(domain[(offset + i) % len(domain)] for i, domain in enumerate(domains)))
    return tuple(sorted(cases))


@dataclass
class _Generation:
    info: GenerationInfo
    fd: int
    library: object
    functions: dict
    artifact: Path
    inode: tuple[int, int]
    identity_pin: PathIdentityPin
    leases: int = 0
    retired: bool = False
    totality: tuple[bytes, ...] = ()


class GenerationLease:
    """One generation snapshot; closing waits for this lease's native calls."""
    def __init__(self, runtime, generation, selection_epoch):
        self._runtime, self._generation = runtime, generation
        self._lock = threading.RLock()
        self._closed = False
        self.selection_epoch = selection_epoch

    @property
    def info(self):
        return self._generation.info

    def call(self, function, arguments):
        with self._lock:
            if self._closed:
                _reject("generation lease is closed")
            signatures = {a.function: a for a in self.info.abi}
            if type(function) is not str or function not in signatures:
                _reject("unknown function in this generation")
            signature = signatures[function]
            if type(arguments) not in (tuple, list):
                _reject("native arguments must be an exact scalar list or tuple")
            arguments = tuple(arguments)
            if (len(arguments) != len(signature.parameters)
                    or any(not scalar_value_valid(v, t) for v, t in zip(arguments, signature.parameters))):
                _reject("native arguments differ from the exact scalar ABI")
            return self._generation.functions[function](*arguments)

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._runtime._release(self._generation)

    def __enter__(self):
        with self._lock:
            if self._closed:
                _reject("generation lease is closed")
        return self

    def __exit__(self, *unused):
        self.close()

    def __copy__(self):
        _reject("leases have one close owner; acquire another lease instead of copying")

    def __deepcopy__(self, memo):
        return self.__copy__()


class ScalarMultiversionRuntime:
    """Build verified generations and switch only between complete artifacts.

    The caller owns this runtime and its Python process. There is no persisted
    receipt import, untrusted DSO entrypoint, native pointer escape, heap-state
    migration, crash recovery or cross-process publication protocol.
    """
    def __init__(self, baseline, directory, *, clang="clang", validation_timeout_ms=2000,
                 max_live_generations=8, prove_total=False):
        if (platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}
                or not hasattr(os, "memfd_create")):
            _reject("Linux x86-64 with sealing-capable memfd is required")
        if type(validation_timeout_ms) is not int or not 1 <= validation_timeout_ms <= 30000:
            _reject("translation validation timeout must be 1..30000 milliseconds")
        if type(max_live_generations) is not int or not 2 <= max_live_generations <= 64:
            _reject("live generation limit must be 2..64")
        if type(prove_total) is not bool:
            _reject("prove_total must be an explicit Boolean profile choice")
        self._prove_total = prove_total
        self._profile = PROVED_TOTAL_PROFILE if prove_total else PROFILE
        self._baseline, self._abi, totality = _admit(
            baseline, prove_total=prove_total, timeout_ms=validation_timeout_ms)
        self._clang, self._timeout = clang, validation_timeout_ms
        self._max_live = max_live_generations
        self._lock, self._writer = threading.RLock(), threading.Lock()
        self._states = {}
        self._events = deque(maxlen=128)
        self._cleanup_pending = {}
        self._cleanup_events = deque(maxlen=128)
        self._cleanup_attempts = 0
        self._directory_cleanup = {"status": "not_attempted"}
        self._next, self._epoch, self._current, self._closed = 1, 0, None, False
        self._directory = Path(tempfile.mkdtemp(prefix="hia-multiversion-", dir=directory))
        self._directory_inode = None
        self._directory_pin = PathIdentityPin(self._directory, directory=True)
        try:
            directory_info = self._directory.lstat()
            self._directory_inode = (directory_info.st_dev, directory_info.st_ino)
            self._directory_pin.acquire(self._directory_inode)
            state = self._prepare(self._baseline, 0, 0, baseline=True, totality=totality)
            self._states[0], self._current = state, 0
        except BaseException as exc:
            self._closed = True
            self._remove_directory()
            # Construction did not return an owner through which a caller
            # could inspect cleanup. Preserve the original exception and
            # attach the same bounded diagnostic snapshot when possible.
            try:
                exc.hia_cleanup = self._cleanup_snapshot()
            except Exception:
                pass
            raise

    def _prepare(self, program, generation, proofs, *, baseline=False, totality=()):
        output = self._directory / f"generation-{generation}.so"
        fd, library, functions, inode = None, None, {}, None
        identity_pin = PathIdentityPin(output)
        try:
            receipt = build_program_native(program, output, clang=self._clang, kind="shared", target=TARGET)
            published = output.lstat()
            if stat.S_ISREG(published.st_mode):
                inode = (published.st_dev, published.st_ino)
            identity_pin.acquire(inode)
            data, inode = _read_artifact(output)
            if inode != identity_pin.inode:
                _reject("native artifact differs from its held identity pin")
            ir = emit_program_llvm(program)
            # Recompute identities and inspect actual ELF bytes. Receipt booleans
            # are never admission evidence, including ok/native_execution flags.
            if (receipt.get("core_sha256") != program.sha256
                    or receipt.get("input_sha256") != program.input_sha256
                    or receipt.get("llvm_ir_sha256") != ir.sha256
                    or receipt.get("artifact_sha256") != sha256(data).hexdigest()
                    or receipt.get("artifact_bytes") != len(data)
                    or receipt.get("target") != TARGET or receipt.get("kind") != "shared"):
                _reject("native build receipt does not bind the actual program and artifact")
            inspect_owned_shared_elf(data, tuple(a.function for a in self._abi))
            fd = _sealed_fd(data)
            library = ctypes.CDLL(f"/proc/self/fd/{fd}", mode=os.RTLD_LOCAL | os.RTLD_NOW)
            for signature in self._abi:
                native = getattr(library, signature.function)
                native.argtypes = [_CTYPES[t] for t in signature.parameters]
                native.restype = _CTYPES[signature.result]
                functions[signature.function] = native
            # A fully sealed new fd does not identify dlsym's actual mapping:
            # the loader can retain an old /proc/self/fd/N pathname reference.
            # Bind every export before even the first finite native probe.
            mapping_source = Path(__file__).with_name("native_mapping_identity.py")
            mapping_identity = sha256(mapping_source.read_bytes()).hexdigest()
            try:
                loaded_mapping = verify_loaded_symbols(fd, functions)
            except NativeMappingRejected as error:
                raise MultiversionRejected("E_HIA_MULTIVERSION: loaded native mapping does not bind the sealed artifact") from error
            if sha256(mapping_source.read_bytes()).hexdigest() != mapping_identity:
                _reject("loaded mapping checker changed during admission")
            loaded_mapping["checker_sha256"] = mapping_identity
            calls = 0
            for signature in self._abi:
                native = functions[signature.function]
                for arguments in _probe_vectors(signature):
                    expected = execute_program(program, signature.function, list(arguments),
                                               max_steps=2 * (_MAX_OPS + _MAX_BLOCKS))["result"]
                    actual = native(*arguments)
                    calls += 1
                    if type(actual) is not type(expected) or actual != expected:
                        _reject("actual native result differs from the independent HIA interpreter")
            info = GenerationInfo(generation, program.sha256, program.input_sha256,
                                  sha256(data).hexdigest(), len(data), self._abi, proofs, calls, baseline,
                                  self._profile, len(totality),
                                  json.dumps(loaded_mapping, sort_keys=True, separators=(",", ":")).encode())
            return _Generation(info, fd, library, functions, output, inode, identity_pin, totality=totality)
        except BaseException:
            self._dispose(generation, library, functions, fd, output, inode,
                          identity_pin, cause="preparation_failed")
            raise

    def publish(self, candidate):
        """Freshly prove/build/observe candidate; atomically select on success."""
        with self._writer:
            with self._lock:
                if self._closed:
                    _reject("runtime is closed")
                # Charge both current and candidate while staging. Old leased
                # generations may not be discarded to make space for a new one.
                if len(self._states) + len(self._cleanup_pending) >= self._max_live:
                    _reject("live artifact budget exhausted; existing generations remain selected")
                number = self._next
                self._next += 1
            program, abi, totality = _admit(candidate, prove_total=self._prove_total,
                                           timeout_ms=self._timeout)
            if abi != self._abi:
                _reject("candidate scalar ABI differs from the immutable baseline")
            _prove(self._baseline, program, abi, self._timeout)
            state = self._prepare(program, number, len(abi), totality=totality)
            with self._lock:
                previous = self._states[self._current]
                self._states[number] = state
                self._current = number
                self._epoch += 1
                self._events.append({"event": "publish", "generation": number, "epoch": self._epoch})
                if not previous.info.baseline:
                    previous.retired = True
                    self._collect(previous)
            return state.info

    def publish_if_current(self, candidate, expected_generation, *, expected_epoch,
                           max_prepare_ns, cancellation, preparation_started_ns=None):
        """Conditionally select after a fresh proof/build and an actual cost gate.

        The expected generation AND epoch bind the incumbent snapshot, including
        rollback ABA. The budget measures elapsed time from method entry (or an
        earlier monotonic handoff timestamp) through the final preselection
        check; waiting for a competing writer is included. Prepared but
        unselected artifacts are disposed.
        """
        started = time.perf_counter_ns()
        if (type(expected_generation) is not int or expected_generation < 0
                or type(expected_epoch) is not int or expected_epoch < 0
                or type(max_prepare_ns) is not int or not 0 <= max_prepare_ns < 2**63
                or type(cancellation) is not PublicationCancellation):
            _reject("conditional publication needs exact snapshot, budget and cancellation types")
        if preparation_started_ns is not None:
            if type(preparation_started_ns) is not int or not 0 <= preparation_started_ns <= started:
                _reject("preparation handoff must be an earlier exact monotonic timestamp")
            started = preparation_started_ns

        def check_current():
            if self._closed:
                _reject("runtime is closed")
            if self._current != expected_generation or self._epoch != expected_epoch:
                _reject("stale generation or selection epoch")

        def check_preparation():
            if cancellation.cancelled():
                _reject("publication cancelled before selection")
            if time.perf_counter_ns() - started > max_prepare_ns:
                _reject("actual preparation budget exceeded before selection")

        state, published = None, False
        with self._writer:
            try:
                with self._lock:
                    check_current()
                    check_preparation()
                    if cancellation.committed():
                        _reject("publication cancellation token was already committed")
                    if len(self._states) + len(self._cleanup_pending) >= self._max_live:
                        _reject("live artifact budget exhausted; existing generations remain selected")
                    number = self._next
                    self._next += 1
                program, abi, totality = _admit(candidate, prove_total=self._prove_total,
                                               timeout_ms=self._timeout)
                if abi != self._abi:
                    _reject("candidate scalar ABI differs from the immutable baseline")
                _prove(self._baseline, program, abi, self._timeout)
                check_preparation()
                state = self._prepare(program, number, len(abi), totality=totality)
                # Cancellation and publication have one linearization point.
                # In particular an Event check alone would leave a check/swap
                # race in which Future.cancel could succeed after the check.
                with self._lock, cancellation._lock:
                    check_current()
                    check_preparation()
                    if cancellation._committed:
                        _reject("publication cancellation token was already committed")
                    prepare_ns = time.perf_counter_ns() - started
                    if prepare_ns > max_prepare_ns:
                        _reject("actual preparation budget exceeded before selection")
                    previous = self._states[self._current]
                    cancellation._committed = True
                    self._states[number] = state
                    self._current = number
                    self._epoch += 1
                    published = True
                    epoch = self._epoch
                    self._events.append({"event": "publish_if_current", "generation": number,
                                         "epoch": epoch, "prepare_ns": prepare_ns,
                                         "max_prepare_ns": max_prepare_ns})
                    if not previous.info.baseline:
                        previous.retired = True
                        self._collect(previous)
                return {"generation": state.info.as_dict(), "selection_epoch": epoch,
                        "prepare_ns": prepare_ns, "max_prepare_ns": max_prepare_ns}
            except BaseException:
                if state is not None and not published:
                    self._dispose(state.info.generation, state.library, state.functions, state.fd,
                                  state.artifact, state.inode, state.identity_pin, cause="prepared_but_not_selected")
                raise

    def lease(self):
        with self._lock:
            if self._closed:
                _reject("runtime is closed")
            state = self._states[self._current]
            state.leases += 1
            return GenerationLease(self, state, self._epoch)

    def call(self, function, arguments):
        with self.lease() as lease:
            return lease.call(function, arguments)

    def rollback(self):
        """Select the retained immutable baseline for future calls only."""
        with self._writer, self._lock:
            if self._closed:
                _reject("runtime is closed")
            if self._current != 0:
                previous = self._states[self._current]
                self._current = 0
                self._epoch += 1
                previous.retired = True
                self._events.append({"event": "rollback", "generation": 0, "epoch": self._epoch})
                self._collect(previous)
            return self._states[0].info

    def _release(self, state):
        with self._lock:
            state.leases -= 1
            self._collect(state)

    def _collect(self, state):
        if state.retired and state.leases == 0:
            self._dispose(state.info.generation, state.library, state.functions, state.fd,
                          state.artifact, state.inode, state.identity_pin, cause="retired_generation")
            state.library = None
            del self._states[state.info.generation]
            self._events.append({"event": "retire", "generation": state.info.generation,
                                 "epoch": self._epoch})
            if self._closed and not self._states:
                self._remove_directory()

    def _remove_directory(self):
        self._directory_cleanup = remove_directory(self._directory, self._directory_inode, self._directory_pin)

    def _dispose(self, generation, library, functions, fd, artifact, inode, identity_pin, *, cause):
        with self._lock:
            task = self._cleanup_pending.get(generation)
            if task is None:
                task = NativeRetirement(generation, cause, artifact, inode, library, functions, fd, identity_pin)
                # Retain the record before attempting native release, so even
                # an interrupted attempt cannot acquire a second close owner.
                self._cleanup_pending[generation] = task
            self._attempt_cleanup(task)

    def _attempt_cleanup(self, task):
        result = task.attempt()
        self._cleanup_attempts += 1
        self._cleanup_events.append(result)
        if task.complete:
            self._cleanup_pending.pop(task.generation, None)

    def _cleanup_snapshot(self):
        observation = observe_directory(self._directory, self._directory_inode, self._directory_pin)
        native_complete = (self._closed and not self._states
                           and all(t.native_succeeded for t in self._cleanup_pending.values()))
        identity_complete = (self._closed and not self._states and self._directory_pin.release_succeeded
                             and all(t.identity_pin.release_succeeded for t in self._cleanup_pending.values()))
        pending_identity_closes = [
            {"generation": t.generation, "kind": "artifact", "pin": t.identity_pin.snapshot()}
            for t in self._cleanup_pending.values()
            if not t.identity_pin.release_succeeded]
        directory_pending = self._closed and not self._states and not self._directory_pin.release_succeeded
        if directory_pending:
            pending_identity_closes.append({"generation": None, "kind": "directory",
                                            "pin": self._directory_pin.snapshot()})
        return {"schema": "hepta.hia.native-retirement-observation.v1",
                "attempts": self._cleanup_attempts, "history_limit": 128,
                "pending": [t.snapshot() for _, t in sorted(self._cleanup_pending.items())],
                "pending_identity_releases": pending_identity_closes,
                "pending_resource_count": len(self._cleanup_pending) + int(directory_pending),
                "recent_attempts": json.loads(json.dumps(list(self._cleanup_events))),
                "directory_cleanup": json.loads(json.dumps(self._directory_cleanup)),
                "directory_observation": observation,
                "directory_identity_pin": self._directory_pin.snapshot(),
                "owned_native_release_complete": native_complete,
                "owned_identity_release_complete": identity_complete,
                "observed_closed_and_directory_absent": (native_complete
                    and identity_complete and not self._cleanup_pending and observation["status"] == "absent"),
                "absence_is_a_permanent_filesystem_guarantee": False,
                "native_release_failures_are_retried": False}

    def retry_cleanup(self):
        """Retry bounded owned-file/directory cleanup; never retry fd/dlclose.

        Pending retirements consume the same finite artifact capacity as live
        generations. A failed native release remains explicitly uncertain and
        charged even if its numeric descriptor is later reused by the host.
        """
        with self._writer, self._lock:
            for task in list(self._cleanup_pending.values()):
                # A task never retries native or identity-fd close. It may
                # observe that a caller removed a path and release its still
                # held identity pin, even when native release remains unknown.
                self._attempt_cleanup(task)
            if self._closed and not self._states:
                self._remove_directory()
            return self._cleanup_snapshot()

    def snapshot(self):
        with self._lock:
            return {"schema": self._profile, "closed": self._closed, "selection_epoch": self._epoch,
                    "current_generation": self._current,
                    "generations": [{**state.info.as_dict(), "active_leases": state.leases,
                                     "retired": state.retired,
                                     "artifact_identity_pin": state.identity_pin.snapshot(),
                                     "totality_evidence": [json.loads(p) for p in state.totality]}
                                    for _, state in sorted(self._states.items())],
                    "recent_events": [dict(event) for event in self._events],
                    "cleanup": self._cleanup_snapshot(),
                    "claims": {"sealed_artifact_generations": True, "per_call_generation_snapshot": True,
                               "general_live_code_patch": False, "state_layout_migration": False,
                               "backend_refinement_proved": False, "whole_language_soundness_proved": False}}

    def close(self):
        with self._writer, self._lock:
            if not self._closed:
                self._closed, self._current = True, None
                for state in list(self._states.values()):
                    state.retired = True
                    self._collect(state)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def __copy__(self):
        _reject("native generation runtimes cannot be copied")

    def __deepcopy__(self, memo):
        return self.__copy__()
