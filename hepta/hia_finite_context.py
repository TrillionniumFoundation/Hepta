"""Proof-gated, finite u32 fold traces in one owned native child.

This is a separate execution-context profile, not an extension of the checksum
PreparedArtifactSession.  A factory builds every admitted image from Core,
recomputes both checks, and retains sealed bytes.  Each predeclared trace is
consumed once.  Native versions change only between completed requests.  No
serialized receipt, user-supplied DSO, online feedback, persistent HIA owner,
general state migration, or economic/optimizer claim is admitted by this API.
"""
from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import threading
import time

from .clang_capture import run_bounded
from .hia_adaptive import _NativeRelease
from .hia_guarded_batch import export_code_identity
from .hia_native_differential import _pin_native_artifact, compare_verified_hia_program
from .hia_program import TRAP_CODES, verify_program
from .hia_program_llvm import compile_program_llvm, emit_program_llvm
from .hia_program_runtime import HIAProgramTrap, execute_program
from .hia_scalar_lowering_check import verify_scalar_lowering
from .hia_translation_validation import QUALIFIED_CORE_SCHEMAS, _OutsideProfile, _profile, validate_translation
from .native_tool_identity import digest_executable

PROFILE = "hepta.hia.finite-u32-fold-context.v1"
MAX_IMAGES = 8
MAX_REQUESTS = 256
MAX_CALLS = 65_536
MAX_TRACES = 4096
MAX_PENDING_INPUT_BYTES = 1024 * 1024
MAX_IMAGE_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_EVENT_BYTES = 1024
MAX_ERROR_BYTES = 4096
MAX_BLOCKS = 32
MAX_OPERATIONS = 512
SOLVER_TIMEOUT_MS = 10_000
WALL_SECONDS = 5
CPU_SECONDS = 3
ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
_CONSTRUCTION = object()

# Limits are repeated as literals in this fixed, source-bound native driver.
# Input is parsed completely before any image is loaded.  Flush every event so
# a signal leaves an exact, independently checkable completed-request prefix.
DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
typedef uint32_t (*kernel_t)(uint32_t, uint32_t);
typedef struct { uint32_t id, image, mode, seed, parameter, begin, count; } request_t;
static request_t requests[256];
static uint32_t values[65536];
static const char *trace;
static void limit(int resource, rlim_t n) {
    struct rlimit l = {n, n};
    if (setrlimit(resource, &l)) exit(83);
}
static uint64_t configured(int resource) {
    struct rlimit l;
    if (getrlimit(resource, &l)) exit(83);
    return (uint64_t)l.rlim_cur;
}
static uint32_t number(int delimiter) {
    int c = fgetc(stdin), first = c;
    uint64_t n = 0;
    unsigned digits = 0;
    while (c >= '0' && c <= '9') {
        if (++digits > 10 || (digits > 1 && first == '0')) exit(84);
        n = n * 10 + (unsigned)(c - '0');
        if (n > UINT32_MAX) exit(84);
        c = fgetc(stdin);
    }
    if (!digits || c != delimiter) exit(84);
    return (uint32_t)n;
}
static void flush(void) {
    if (ferror(stdout) || fflush(stdout)) exit(94);
}
static void image_event(uint32_t i, const char *kind) {
    printf("{\"image\":%" PRIu32 ",\"kind\":\"%s\",\"trace\":\"%s\"}\n", i, kind, trace);
    flush();
}
static void fault(uint32_t i, uint32_t code) {
    printf("{\"code\":%" PRIu32 ",\"image\":%" PRIu32 ",\"kind\":\"fault\",\"trace\":\"%s\"}\n", code, i, trace);
    flush();
}
int main(int argc, char **argv) {
    limit(RLIMIT_CORE, 0);
    limit(RLIMIT_CPU, 3);
    limit(RLIMIT_AS, (rlim_t)256 * 1024 * 1024);
    limit(RLIMIT_FSIZE, 128 * 1024);
    if (argc < 3 || argc > 10 || strlen(argv[1]) != 64) return 84;
    trace = argv[1];
    for (unsigned i = 0; i < 64; ++i)
        if (!((trace[i] >= '0' && trace[i] <= '9') || (trace[i] >= 'a' && trace[i] <= 'f'))) return 84;
    uint32_t images = (uint32_t)argc - 2, count = number('\n'), total = 0;
    if (!count || count > 256) return 84;
    for (uint32_t i = 0; i < count; ++i) {
        request_t *r = &requests[i];
        r->id = number(' '); r->image = number(' '); r->mode = number(' ');
        r->seed = number(' '); r->parameter = number(' '); r->count = number(' ');
        if (r->image >= images || r->mode > 1 || (!r->mode && r->parameter)
            || !r->count || r->count > 65536 - total) return 84;
        for (uint32_t j = 0; j < i; ++j) if (requests[j].id == r->id) return 84;
        r->begin = total;
        for (uint32_t j = 0; j < r->count; ++j) {
            uint32_t value = number(j + 1 == r->count ? '\n' : ' ');
            if (r->mode && value > 255) return 84;
            values[total++] = value;
        }
    }
    if (fgetc(stdin) != EOF || ferror(stdin)) return 84;
    printf("{\"as_bytes\":%" PRIu64 ",\"core_bytes\":%" PRIu64 ",\"cpu_seconds\":%" PRIu64
           ",\"fsize_bytes\":%" PRIu64 ",\"kind\":\"limits\",\"trace\":\"%s\"}\n",
           configured(RLIMIT_AS), configured(RLIMIT_CORE), configured(RLIMIT_CPU), configured(RLIMIT_FSIZE), trace);
    flush();
    void *libraries[8] = {0};
    kernel_t kernels[8] = {0};
    uint32_t acquired = 0, closed = 0;
    int status = 0;
    for (uint32_t i = 0; i < images; ++i) {
        libraries[i] = dlopen(argv[i + 2], RTLD_NOW | RTLD_LOCAL);
        if (!libraries[i]) { fault(i, 86); status = 86; goto cleanup; }
        ++acquired;
        image_event(i, "opened");
        (void)dlerror();
        kernels[i] = (kernel_t)dlsym(libraries[i], "calculate");
        if (dlerror() || !kernels[i]) { fault(i, 87); status = 87; goto cleanup; }
        image_event(i, "ready");
    }
    for (uint32_t i = 0; i < count; ++i) {
        request_t *r = &requests[i];
        printf("{\"candidate\":%" PRIu32 ",\"id\":%" PRIu32 ",\"kind\":\"start\",\"seq\":%" PRIu32
               ",\"trace\":\"%s\"}\n", r->image, r->id, i, trace);
        flush();
        uint32_t state = r->seed;
        uint64_t checksum = 0;
        for (uint32_t j = 0; j < r->count; ++j) {
            uint32_t value = values[r->begin + j];
            state = r->mode ? kernels[r->image](state ^ value, r->parameter)
                            : kernels[r->image](state, value);
            checksum = checksum * UINT64_C(1099511628211) + state;
        }
        printf("{\"calls\":%" PRIu32 ",\"candidate\":%" PRIu32 ",\"checksum\":%" PRIu64
               ",\"id\":%" PRIu32 ",\"kind\":\"result\",\"mode\":%" PRIu32 ",\"parameter\":%" PRIu32 ",\"seed\":%" PRIu32 ",\"seq\":%" PRIu32
               ",\"state\":%" PRIu32 ",\"trace\":\"%s\"}\n",
               r->count, r->image, checksum, r->id, r->mode, r->parameter, r->seed, i, state, trace);
        flush();
        /* A later version can be selected only after this request returned. */
    }
cleanup:
    for (uint32_t n = acquired; n > 0; --n) {
        uint32_t i = n - 1;
        void *owned = libraries[i];
        libraries[i] = 0; kernels[i] = 0; /* Consume before a possibly uncertain close. */
        int ok = dlclose(owned) == 0;
        if (ok) ++closed; else status = 88;
        printf("{\"image\":%" PRIu32 ",\"kind\":\"closed\",\"ok\":%s,\"trace\":\"%s\"}\n",
               i, ok ? "true" : "false", trace);
        flush();
    }
    printf("{\"acquired\":%" PRIu32 ",\"closed\":%" PRIu32 ",\"kind\":\"finish\",\"ok\":%s,\"trace\":\"%s\"}\n",
           acquired, closed, status == 0 ? "true" : "false", trace);
    flush();
    return status;
}
'''


class FiniteContextRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise FiniteContextRejected("E_HIA_FINITE_CONTEXT: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _implementation():
    names = ("hia_finite_context.py", "hia_guarded_batch.py", "hia_program.py", "hia_opcodes.py", "hia_semantic_kernel.py", "hia_program_llvm.py",
             "hia_program_runtime.py", "hia_translation_validation.py", "hia_scalar_lowering_check.py",
             "hia_native_differential.py", "hia_adaptive.py", "clang_capture.py", "elf_shared_abi.py")
    return sha256(_wire({name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                         for name in names})).hexdigest()


def checked_profile(document):
    checked = verify_program(document)
    data = checked.as_dict()
    _require(checked.structured_bytes is None and data["schema"] in QUALIFIED_CORE_SCHEMAS
             and len(data["functions"]) == 1, "one explicit primitive v1-v7 function required")
    fn = data["functions"][0]
    _require(fn["name"] == "calculate" and checked.scalar_entrypoints == frozenset({"calculate"})
             and [p["type"] for p in fn["params"]] == ["u32", "u32"] and fn["returns"] == ["u32"]
             and set(fn["effects"]) <= {"trap"}, "only pure calculate(u32,u32)->u32 with optional trap effect")
    try:
        _profile(fn)
    except _OutsideProfile as error:
        raise FiniteContextRejected("E_HIA_FINITE_CONTEXT: " + str(error)) from error
    _require(len(fn["blocks"]) <= MAX_BLOCKS and sum(len(b["ops"]) for b in fn["blocks"]) <= MAX_OPERATIONS,
             "finite context CFG budget exceeded")
    return checked


def _observation(value):
    if type(value) is int:
        _require(0 <= value <= MASK32, "invalid oracle u32 result")
        # This fresh canonical shape needs no JSON round trip for every step.
        return {"status": "returned", "values": [value]}
    _require(type(value) is dict, "oracle must return an exact u32 or a canonical observation")
    if value.get("status") == "returned":
        _require(set(value) == {"status", "values"} and type(value["values"]) is list
                 and len(value["values"]) == 1 and type(value["values"][0]) is int
                 and 0 <= value["values"][0] <= MASK32, "invalid oracle u32 result")
    else:
        _require(set(value) == {"status", "code"} and value.get("status") == "trapped"
                 and type(value["code"]) is str and value["code"] in TRAP_CODES, "invalid oracle first-trap observation")
    return json.loads(_wire(value))


def _vm(checked, x, y):
    try:
        result = execute_program(checked, "calculate", [x, y], max_steps=MAX_OPERATIONS + MAX_BLOCKS)
        return _observation({"status": result["status"], "values": result["values"]})
    except HIAProgramTrap as error:
        return _observation({"status": "trapped", "code": error.code})


def _build_image(root, candidate, output, *, clang, cases, oracle, report):
    started = time.monotonic_ns()
    try:
        checked = checked_profile(candidate)
        report["core_sha256"] = checked.sha256
        proof = validate_translation(root.as_dict(), checked.as_dict(), function="calculate", timeout_ms=SOLVER_TIMEOUT_MS)
        report["translation"] = proof
        _require(proof["status"] == "proved" and proof["before_sha256"] == root.sha256
                 and proof["after_sha256"] == checked.sha256, "fresh all-input first-trap proof did not pass")
        llvm = emit_program_llvm(checked)
        lower = verify_scalar_lowering(checked.as_dict(), function="calculate", llvm_text=llvm.text,
                                      timeout_ms=SOLVER_TIMEOUT_MS)
        report["lowering"] = lower
        _require(lower["status"] == "verified" and lower["core_sha256"] == checked.sha256
                 and lower["llvm_sha256"] == llvm.sha256, "fresh selected LLVM check did not pass")
        output.with_suffix(".ll").write_text(llvm.text, encoding="ascii")
        built = compile_program_llvm(llvm, program=checked, output=output, clang=clang)
        report["compilation"] = built
        _require(built["core_sha256"] == checked.sha256 and built["llvm_ir_sha256"] == llvm.sha256,
                 "compiled image binding differs")
        for args in cases:
            _require(_vm(checked, *args) == _observation(oracle(*args)), "VM differs from independent step oracle")
        differential = compare_verified_hia_program(checked, output, {"calculate": cases},
                                                   max_steps=MAX_OPERATIONS + MAX_BLOCKS)
        report["native_differential"] = differential
        _require(differential["artifact_sha256"] == built["artifact_sha256"]
                 and differential["cases_executed"] == len(cases), "finite native differential is incomplete")
        report["code"] = export_code_identity(output.read_bytes())
        report["status"] = "proved_compiled_and_finitely_compared"
        return built["artifact_sha256"]
    finally:
        report["preparation_wall_ns"] = time.monotonic_ns() - started


def _build_driver(directory, clang):
    source, output = directory / "context_driver.c", directory / "context_driver"
    _require(not source.exists() and not output.exists(), "driver output must be new")
    source.write_text(DRIVER, encoding="ascii")
    compiler = shutil.which(clang)
    _require(compiler is not None, "native compiler unavailable")
    compiler = Path(compiler).resolve()
    before = digest_executable(compiler)
    started = time.monotonic_ns()
    result = run_bounded([str(compiler), "-O3", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                          "-ldl", "-o", str(output)], timeout=30, stdout_limit=16384, stderr_limit=65536)
    _require(result.returncode == 0 and digest_executable(compiler) == before,
             "fixed driver compilation failed or compiler changed: " + result.stderr[:2000])
    return {"path": str(output), "sha256": digest_executable(output), "source_sha256": sha256(DRIVER.encode()).hexdigest(),
            "compiler_sha256": before, "compile_wall_ns": time.monotonic_ns() - started,
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


@dataclass(frozen=True, eq=False)
class _Trace:
    bank: object
    token: object
    images: tuple
    requests: tuple
    expected: tuple
    payload: str
    sha256: str


def _requests(requests, labels):
    _require(type(requests) in {list, tuple} and 1 <= len(requests) <= MAX_REQUESTS,
             "bounded nonempty predeclared request sequence required")
    requests = tuple(requests)
    _require(1 <= len(requests) <= MAX_REQUESTS, "request inventory changed outside the finite bound")
    normalized, ids, total = [], set(), 0
    for value in requests:
        _require(type(value) is dict, "exact request object required")
        value = dict(value)
        _require(type(value.get("mode")) is str and value["mode"] in {"fold", "xor_fold"}, "explicit closed fold mode required")
        fields = {"id", "candidate", "seed", "values", "mode"}
        if value["mode"] == "xor_fold":
            fields.add("parameter")
        _require(set(value) == fields, "exact mode-specific request fields required")
        ident, label, seed, values = (value[key] for key in ("id", "candidate", "seed", "values"))
        mode, parameter = (1, value["parameter"]) if value["mode"] == "xor_fold" else (0, 0)
        _require(type(ident) is int and 0 <= ident <= MASK32 and ident not in ids, "unique exact u32 request IDs required")
        _require(type(label) is str and label in labels, "request names an unadmitted candidate")
        _require(type(parameter) is int and 0 <= parameter <= MASK32, "exact fixed u32 parameter required")
        _require(type(seed) is int and 0 <= seed <= MASK32 and type(values) in {tuple, list}
                 and 1 <= len(values) <= MAX_CALLS - total, "request exceeds exact u32/cumulative call budget")
        values = tuple(values)
        _require(1 <= len(values) <= MAX_CALLS - total
                 and all(type(v) is int and 0 <= v <= (255 if mode else MASK32) for v in values),
                 "request exceeds exact byte/u32/cumulative call budget")
        normalized.append((ident, labels.index(label), mode, seed, parameter, tuple(values)))
        ids.add(ident)
        total += len(values)
    return tuple(normalized), _payload(normalized)


def _payload(normalized):
    payload = str(len(normalized)) + "\n" + "".join(
        " ".join(map(str, (ident, image, mode, seed, parameter, len(values), *values))) + "\n"
        for ident, image, mode, seed, parameter, values in normalized)
    _require(len(payload.encode("ascii")) <= MAX_INPUT_BYTES, "encoded trace exceeds input budget")
    return payload


def _expected(requests, oracle):
    rows = []
    for ident, image, mode, seed, parameter, values in requests:
        state, checksum = seed, 0
        for step, value in enumerate(values):
            observed = _observation(oracle(state ^ value, parameter) if mode else oracle(state, value))
            if observed["status"] == "trapped":
                rows.append(("trapped", observed["code"], step))
                break
            state = observed["values"][0]
            checksum = (checksum * 1099511628211 + state) & MASK64
        else:
            rows.append(("returned", state, checksum))
    return tuple(rows)


def _parse_prefix(raw, trace, images):
    """Validate complete canonical events; never promote an unfinished line.

    A trap/timeout can leave a valid prefix.  Its completed rows are evidence,
    not success, a replay cursor, or proof that the attempted request had no
    effect.  The first malformed line terminates validation without trimming
    the retained raw evidence or accepting later records.
    """
    rows, opened, ready, closed, completed = [], [], [], [], []
    pending, faulted, finished, error, limits = None, False, False, None, False
    for number, raw_line in enumerate(raw.splitlines(keepends=True)):
        try:
            _require(len(raw_line) <= MAX_EVENT_BYTES and raw_line.endswith(b"\n"),
                     "incomplete or oversized output event")
            row = json.loads(raw_line)
            _require(type(row) is dict and raw_line == _wire(row) + b"\n" and row.get("trace") == trace.sha256,
                     "noncanonical or foreign trace event")
            # Reject booleans before changing prefix state: Python otherwise
            # compares True/False equal to 1/0 in exact event dictionaries.
            _require(all(type(v) is int for k, v in row.items() if k not in {"kind", "trace", "ok"})
                     and ("ok" not in row or type(row["ok"]) is bool),
                     "native integer/boolean fields require their exact primitive types")
            _require(not finished, "event after finish")
            kind = row.get("kind")
            if kind == "limits":
                _require(not rows and row == {"as_bytes": ADDRESS_SPACE_BYTES, "core_bytes": 0,
                         "cpu_seconds": CPU_SECONDS, "fsize_bytes": MAX_OUTPUT_BYTES,
                         "kind": kind, "trace": trace.sha256}, "native whole-context limits differ")
                limits = True
            elif kind == "opened":
                wanted = {"image": len(opened), "kind": kind, "trace": trace.sha256}
                _require(limits and pending is None and not completed and not closed and not faulted
                         and len(opened) == len(ready) < images and row == wanted, "unexpected image acquisition")
                opened.append(row["image"])
            elif kind == "ready":
                wanted = {"image": len(ready), "kind": kind, "trace": trace.sha256}
                _require(pending is None and not completed and not closed and not faulted
                         and len(opened) == len(ready) + 1 and row == wanted, "unexpected image readiness")
                ready.append(row["image"])
            elif kind == "start":
                seq = len(completed)
                _require(pending is None and not closed and not faulted and len(ready) == images
                         and seq < len(trace.requests), "unexpected request start")
                ident, image, _mode, _seed, _parameter, _values = trace.requests[seq]
                _require(row == {"candidate": image, "id": ident, "kind": kind, "seq": seq, "trace": trace.sha256},
                         "request start differs from exact plan")
                pending = seq
            elif kind == "result":
                _require(pending is not None and not closed and not faulted, "result without matching start")
                ident, image, mode, seed, parameter, values = trace.requests[pending]
                wanted = trace.expected[pending]
                _require(wanted[0] == "returned" and row == {"calls": len(values), "candidate": image,
                         "checksum": wanted[2], "id": ident, "kind": kind, "mode": mode,
                         "parameter": parameter, "seed": seed, "seq": pending,
                         "state": wanted[1], "trace": trace.sha256}, "native fold/checksum differs from oracle")
                completed.append(row)
                pending = None
            elif kind == "fault":
                _require(limits and not faulted and not completed and pending is None and not closed
                         and set(row) == {"code", "image", "kind", "trace"}, "unexpected loader fault")
                _require((row["code"] == 86 and len(opened) == len(ready) and row["image"] == len(opened) < images)
                         or (row["code"] == 87 and len(opened) == len(ready) + 1 and row["image"] == len(ready)),
                         "loader fault contradicts acquired prefix")
                faulted = True
            elif kind == "closed":
                _require(pending is None and len(closed) < len(opened)
                         and (faulted or len(completed) == len(trace.requests))
                         and set(row) == {"image", "kind", "ok", "trace"}
                         and type(row["ok"]) is bool and row["image"] == opened[-1 - len(closed)],
                         "unexpected or repeated image release")
                closed.append(row)
            elif kind == "finish":
                ok = not faulted and len(completed) == len(trace.requests) and all(r["ok"] for r in closed)
                _require(limits and pending is None and len(closed) == len(opened)
                         and row == {"acquired": len(opened), "closed": sum(r["ok"] for r in closed),
                                     "kind": kind, "ok": ok, "trace": trace.sha256}, "invalid final cleanup record")
                finished = True
            else:
                _require(False, "unknown native event")
            rows.append(row)
        except (FiniteContextRejected, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
            error = {"line": number, "message": str(exc)}
            break
    return {"events": rows, "completed_requests": completed, "pending_request_seq": pending,
            "opened_images": opened, "ready_images": ready, "close_attempts": closed,
            "native_limits_observed": limits,
            "finish_observed": finished, "prefix_error": error,
            "complete": finished and error is None and bool(rows[-1]["ok"]),
            "replay_permitted": False}


class FiniteU32Bank:
    """In-process, nontransferable authority for a locally rebuilt finite bank."""

    def __init__(self, construction, root, labels, oracle, report):
        _require(construction is _CONSTRUCTION, "use build_bank; receipts and external images are not authority")
        self._root, self._labels, self._oracle, self._report = root, labels, oracle, report
        self._lock = threading.RLock()
        self._pins, self._tokens = [], {}
        self._early_releases = []
        self._pending_input_bytes = 0
        self._child_cleanup_uncertain = False
        self._closed = self._poisoned = False
        self._implementation = _implementation()

    def __copy__(self):
        raise FiniteContextRejected("finite native bank ownership cannot be copied")

    def __deepcopy__(self, memo):
        return self.__copy__()

    def __reduce__(self):
        raise FiniteContextRejected("finite native bank authority cannot be serialized")

    def _pin(self, path, expected):
        def early_close(fd):
            release = _NativeRelease(library=None, fd=fd)
            self._early_releases.append(release)
            record = release.attempt()
            _require(record["native_release_succeeded"], "unpublished descriptor release uncertain")
        data, _source, fd = _pin_native_artifact(Path(path), maximum_bytes=MAX_IMAGE_BYTES, close_owner=early_close)
        pin = {"fd": fd, "path": f"/proc/{os.getpid()}/fd/{fd}", "sha256": expected,
               "bytes": len(data), "release": _NativeRelease(library=None, fd=fd)}
        self._pins.append(pin)  # Acquire ownership before any later check can fail.
        stat = os.fstat(fd)
        pin["identity"] = (stat.st_dev, stat.st_ino, stat.st_size)
        _require(sha256(data).hexdigest() == expected, "internally built image changed before sealing")
        return pin

    def _open(self):
        _require(not self._closed and not self._poisoned, "bank is closed or poisoned; replay forbidden")
        _require(_implementation() == self._implementation, "context/checker implementation changed")
        import fcntl
        for pin in self._pins:
            _require(not pin["release"].attempted, "image already released")
            stat = os.fstat(pin["fd"])
            _require((stat.st_dev, stat.st_ino, stat.st_size) == pin["identity"]
                     and fcntl.fcntl(pin["fd"], getattr(fcntl, "F_GET_SEALS", 1034)) & 15 == 15
                     and sha256(os.pread(pin["fd"], pin["bytes"] + 1, 0)).hexdigest() == pin["sha256"],
                     "held sealed native identity changed")

    @property
    def labels(self):
        return self._labels

    def prepare_trace(self, requests):
        """Bind a finite plan and oracle before execution; no native observation."""
        with self._lock:
            self._open()
            _require(len(self._tokens) < MAX_TRACES, "prepared trace budget exhausted")
            requested, _initial_payload = _requests(requests, self._labels)
            images = tuple(sorted({r[1] for r in requested}))
            normalized = tuple((ident, images.index(image), mode, seed, parameter, values)
                               for ident, image, mode, seed, parameter, values in requested)
            payload = _payload(normalized)
            payload_bytes = len(payload.encode("ascii"))
            _require(self._pending_input_bytes + payload_bytes <= MAX_PENDING_INPUT_BYTES,
                     "pending trace input-byte budget exhausted")
            expected = _expected(normalized, self._oracle)
            digest = sha256(_wire({"profile": PROFILE, "bank": self._bank_sha256,
                                   "images": images, "requests": normalized, "expected": expected})).hexdigest()
            token = object()
            trace = _Trace(self, token, images, normalized, expected, payload, digest)
            self._tokens[token] = (trace, digest, sha256(payload.encode("ascii")).hexdigest(), payload_bytes)
            self._pending_input_bytes += payload_bytes
            return trace

    def _enrolled(self, trace):
        _require(type(trace) is _Trace and trace.bank is self, "foreign trace; replay forbidden")
        enrolled = self._tokens.get(trace.token)
        _require(enrolled is not None and enrolled[0] is trace and trace.sha256 == enrolled[1]
                 and sha256(trace.payload.encode("ascii")).hexdigest() == enrolled[2]
                 and sha256(_wire({"profile": PROFILE, "bank": self._bank_sha256,
                                   "images": trace.images, "requests": trace.requests,
                                   "expected": trace.expected})).hexdigest() == trace.sha256,
                 "foreign, altered or consumed trace; replay forbidden")
        return enrolled

    def _consume(self, trace):
        enrolled = self._enrolled(trace)
        self._tokens[trace.token] = None
        self._pending_input_bytes -= enrolled[3]

    def cancel(self, trace):
        """Discard an unstarted plan without a child or a replay permission."""
        with self._lock:
            _require(not self._closed, "bank is closed")
            self._consume(trace)
            return {"status": "cancelled-before-execution", "trace_sha256": trace.sha256,
                    "execution_attempted": False, "replay_permitted": False,
                    "pending_input_bytes": self._pending_input_bytes}

    def _discard_pending(self):
        count = sum(value is not None for value in self._tokens.values())
        for token in self._tokens:
            self._tokens[token] = None
        self._pending_input_bytes = 0
        return count

    def state(self):
        """Diagnostic accounting only; this snapshot is never admission authority."""
        with self._lock:
            return {"closed": self._closed, "poisoned": self._poisoned, "registered_traces": len(self._tokens),
                    "pending_traces": sum(value is not None for value in self._tokens.values()),
                    "pending_input_bytes": self._pending_input_bytes, "max_traces": MAX_TRACES,
                    "max_pending_input_bytes": MAX_PENDING_INPUT_BYTES}

    def run(self, trace, *, report=None):
        """Consume once, keep exact failed prefixes, and never retry a child."""
        row = {} if report is None else report
        _require(type(row) is dict, "report must be an ordinary dictionary")
        started = time.monotonic_ns()
        with self._lock:
            self._open()
            self._consume(trace)  # Consume before launch or any uncertain effect.
            child_environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
            row.update(profile=PROFILE, trace_sha256=trace.sha256, bank_sha256=self._bank_sha256,
                       execution_attempted=False, replay_permitted=False, online_feedback=False,
                       persistent_hia_owners=[], persistent_hia_loans=[],
                       status="consumed-before-launch", requested=len(trace.requests),
                       planned_load_inventory=[{"slot": slot, "bank_index": index, "candidate": self._labels[index],
                                                "artifact_sha256": self._images[index]["sha256"]}
                                               for slot, index in enumerate(trace.images)],
                       loaded_inventory=[], ready_inventory=[],
                       child_environment=dict(child_environment),
                       limits={"wall_seconds": WALL_SECONDS, "cpu_seconds": CPU_SECONDS,
                               "address_space_bytes": ADDRESS_SPACE_BYTES, "stdin_bytes": MAX_INPUT_BYTES,
                               "stdout_bytes": MAX_OUTPUT_BYTES, "stderr_bytes": MAX_ERROR_BYTES})
            try:
                self._open()
                command = [self._driver["path"], trace.sha256, *(self._images[i]["path"] for i in trace.images)]
                row["execution_attempted"] = True
                result = run_bounded(command, input_text=trace.payload, timeout=WALL_SECONDS,
                                     stdin_limit=MAX_INPUT_BYTES, stdout_limit=MAX_OUTPUT_BYTES,
                                     stderr_limit=MAX_ERROR_BYTES, env=child_environment)
                raw_out = result.raw_stdout if result.raw_stdout is not None else result.stdout.encode()
                raw_err = result.raw_stderr if result.raw_stderr is not None else result.stderr.encode()
                row.update(returncode=result.returncode, raw_stdout_base64=b64encode(raw_out).decode("ascii"),
                           raw_stderr_base64=b64encode(raw_err).decode("ascii"),
                           owned_child_cleanup="confirmed_by_bounded_capture")
                self._record_prefix(row, raw_out, trace)
                _require(result.returncode == 0 and raw_err == b"" and row["prefix"]["complete"],
                         "native context failed, incomplete, or not exactly bound to its trace")
                self._open()
                row["status"] = "completed"
            except BaseException as error:
                # Consume the cleanup uncertainty before any diagnostic decode,
                # allocation or user-facing report operation can itself fail.
                # A malformed/deep prefix must never make a live child's parent
                # proc-fd identities eligible for close/reuse.
                self._poisoned = True
                uncertain = (getattr(error, "code", None) in {"E_CAPTURE_CLEANUP", "E_CAPTURE_OWNERSHIP"}
                             or bool(getattr(error, "capture_error", None))
                             or any(note.startswith("Cleanup refused:") for note in getattr(error, "__notes__", ())))
                if uncertain:
                    self._child_cleanup_uncertain = True
                    error.finite_context_owner = self
                try:
                    row["owned_child_cleanup"] = "uncertain" if uncertain else row.get(
                        "owned_child_cleanup", "bounded_capture_failure_no_success_claim")
                    row["pins_retained_for_uncertain_child"] = bool(uncertain)
                    row["pending_traces_cancelled"] = self._discard_pending()
                    row.update(status="failed-no-replay", error={"type": type(error).__name__, "message": str(error),
                               "code": getattr(error, "code", None)})
                    capture = getattr(error, "capture", None)
                    if capture is not None:
                        row.update(returncode=capture.returncode,
                                   raw_stdout_base64=b64encode(capture.stdout).decode("ascii"),
                                   raw_stderr_base64=b64encode(capture.stderr).decode("ascii"))
                        row["capture_failure"] = {"stdout_total_bytes": capture.stdout_total_bytes,
                            "stderr_total_bytes": capture.stderr_total_bytes, "capture_error": getattr(error, "capture_error", None)}
                        self._record_prefix(row, capture.stdout, trace)
                except BaseException as diagnostic:
                    # Keep the original owned-process failure and its owner.
                    # Diagnostic failure is not evidence that cleanup succeeded.
                    try:
                        row["diagnostic_error"] = type(diagnostic).__name__
                        error.add_note("Finite context failure evidence could not be decoded: " + type(diagnostic).__name__)
                    except BaseException:
                        pass
                raise
            finally:
                row["outer_wall_ns"] = time.monotonic_ns() - started
        return row

    @staticmethod
    def _record_prefix(row, raw, trace):
        prefix = _parse_prefix(raw, trace, len(trace.images))
        row["prefix"] = prefix
        row["loaded_inventory"] = [row["planned_load_inventory"][i] for i in prefix["opened_images"]]
        row["ready_inventory"] = [row["planned_load_inventory"][i] for i in prefix["ready_images"]]

    def close(self):
        """One release attempt per held descriptor; uncertain debt stays visible."""
        with self._lock:
            if self._closed:
                return json.loads(_wire(self._release_snapshot))
            self._closed = True
            cancelled = self._discard_pending()
            self._tokens.clear()
            started = time.monotonic_ns()
            # A possibly live child can still resolve the held parent proc-fd
            # names.  Revoking/reusing those numbers before its confirmed reap
            # would invalidate the byte-identity guarantee.  Keep bounded debt;
            # this profile has no numeric-PID retry or cleanup recovery API.
            rows = [pin["release"].snapshot() if self._child_cleanup_uncertain else pin["release"].attempt()
                    for pin in reversed(self._pins)]
            early = [release.snapshot() for release in self._early_releases]
            result = {"descriptors": rows, "complete": all(r["native_release_succeeded"] for r in rows),
                      "unpublished_descriptors": early,
                      "pending_traces_cancelled": cancelled, "pending_input_bytes": self._pending_input_bytes,
                      "pins_retained_for_uncertain_child": self._child_cleanup_uncertain,
                      "retry_permitted": False, "wall_ns": time.monotonic_ns() - started}
            result["complete"] = (result["complete"] and not self._child_cleanup_uncertain
                                  and all(r["native_release_succeeded"] for r in early))
            self._release_snapshot = result
            self._report["release"] = json.loads(_wire(result))
            return json.loads(_wire(result))

    def __enter__(self):
        self._open()
        return self

    def __exit__(self, exc_type, exc, traceback):
        result = self.close()
        if not result["complete"]:
            if exc is not None:
                exc.add_note("finite context descriptor release uncertain; no retry or success")
            else:
                _require(False, "descriptor release uncertain; no retry or success")


def build_bank(baseline, candidates, directory, *, clang, cases, oracle, report=None):
    """Build the exact closed bank locally; all imported receipts are excluded.

    ``oracle`` is trusted host code independently implementing one step.  It is
    checked against every admitted Core on the finite ``cases`` corpus; that
    finite check is not an all-input proof of the oracle or the native backend.
    Each candidate's equivalence to baseline and selected LLVM are separately
    recomputed before compilation.  All setup, oracle and final close work must
    be included by any future economic experiment, equally for every policy.
    """
    started = time.monotonic_ns()
    row = {} if report is None else report
    _require(type(row) is dict, "report must be an ordinary dictionary")
    _require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
             "finite context currently requires actual Linux x86-64")
    root = checked_profile(baseline)
    _require(type(candidates) is dict and 1 <= len(candidates) <= MAX_IMAGES and "baseline" in candidates
             and all(type(k) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", k) for k in candidates),
             "bounded named bank with an explicit baseline required")
    _require(checked_profile(candidates["baseline"]).sha256 == root.sha256, "baseline candidate differs from root")
    _require(callable(oracle) and type(cases) is list and 1 <= len(cases) <= 64
             and all(type(args) is list and len(args) == 2
                     and all(type(v) is int and 0 <= v <= MASK32 for v in args) for args in cases),
             "bounded exact u32 native corpus and trusted step oracle required")
    directory = Path(directory)
    _require(directory.is_dir() and not any(directory.iterdir()), "new empty build directory required")
    labels = tuple(candidates)
    row.update(profile=PROFILE, baseline_sha256=root.sha256, labels=list(labels), candidates={},
               serialized_receipts_authorize_execution=False, machine_code_semantics_proved=False,
               global_optimality_proved=False, economic_benefit_proved=False,
               abi={"function": "calculate", "params": ["u32", "u32"], "returns": ["u32"],
                    "calling_convention": "C-Linux-x86_64", "persistent_state": []})
    bank = FiniteU32Bank(_CONSTRUCTION, root, labels, oracle, row)
    try:
        images = []
        for label in labels:
            output = directory / (label + ".so")
            child_report = row["candidates"][label] = {}
            digest = _build_image(root, candidates[label], output, clang=clang, cases=cases, oracle=oracle,
                                  report=child_report)
            images.append(bank._pin(output, digest))
        driver = _build_driver(directory, clang)
        row["driver"] = driver
        bank._driver = bank._pin(driver["path"], driver["sha256"])
        bank._images = tuple(images)
        row["bank_sha256"] = sha256(_wire({"profile": PROFILE, "root": root.sha256,
            "images": [[name, pin["sha256"]] for name, pin in zip(labels, images)],
            "driver": driver["sha256"], "implementation": bank._implementation})).hexdigest()
        bank._bank_sha256 = row["bank_sha256"]
        bank._open()
        row["status"] = "prepared"
        return bank
    except BaseException as error:
        row.update(status="preparation-failed", error={"type": type(error).__name__, "message": str(error)})
        release = bank.close()
        if not release["complete"]:
            error.add_note("finite context preparation release uncertain; no retry")
            # Retain the actual owner with the exception; a receipt cannot
            # discharge uncertain ownership or authorize a numeric close retry.
            error.finite_context_owner = bank
        raise
    finally:
        row["preparation_wall_ns"] = time.monotonic_ns() - started
