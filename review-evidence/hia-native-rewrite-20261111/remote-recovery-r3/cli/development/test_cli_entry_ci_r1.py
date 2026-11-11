"""Independent CI actual ELF tests for the seven-image CLI entry slice.

This is a new, initially unexecuted harness. CPython is an independent oracle,
never a subprocess used by the native ELF. Valid-file business requests remain
explicitly OPEN (exit 126); they are not counted as CLI business equivalence.
"""
from pathlib import Path
from hashlib import sha256
import argparse, ctypes, fcntl, importlib, json, os, pty, resource, select
import signal, stat, struct, subprocess, sys, tempfile, time, traceback, zlib

def digest(value):
    return sha256(value).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert sys.version_info[:3] == (3, 12, 14), sys.version
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "cas").mkdir()
    pins = {}
    def read(path):
        path = Path(path).resolve()
        raw = path.read_bytes()
        if str(path) in pins:
            assert pins[str(path)] == digest(raw)
        pins[str(path)] = digest(raw)
        return raw
    def cas(raw):
        raw = bytes(raw)
        h = digest(raw)
        path = out / "cas" / (h + ".zlib")
        if not path.exists():
            path.write_bytes(zlib.compress(raw, 6))
        assert zlib.decompress(path.read_bytes()) == raw
        return dict(sha256=h, bytes=len(raw), compression="zlib", path="cas/" + path.name)
    braw = read(args.bundle)
    bundle = json.loads(braw)
    assert bundle["scope"] == "DEVELOPMENT_COMPONENT_SLICE_NOT_INSTALLED_NOT_COLD"
    executable = Path(bundle["executable_path"]).resolve()
    elf = read(executable)
    assert (len(elf), digest(elf)) == (bundle["executable_bytes"], bundle["executable_sha256"])
    assert elf[:4] == b"\x7fELF" and struct.unpack_from("<Q", elf, 32)[0] == 64
    phnum = struct.unpack_from("<H", elf, 56)[0]
    assert not any(struct.unpack_from("<I", elf, 64 + i * 56)[0] == 3 for i in range(phnum)), "PT_INTERP is not allowed"
    for role in range(1, 8):
        component = bundle["components"][str(role)]
        source = component["source"]
        sraw = read(source["copy"])
        assert len(sraw) == source["bytes"] and digest(sraw) == source["sha256"]
        if role == 7:
            path = component["image_path"]
            expected = component["manifest"]["image_sha256"]
        else:
            image = component["image"]
            path, expected = image["copy"], image["sha256"]
            raw = read(component["manifest"]["copy"])
            original = json.loads(raw)
            assert original["source_sha256"] == digest(sraw) and original["image_sha256"] == expected
        assert digest(read(path)) == expected
    read(__file__)
    source = args.source.resolve()
    for p in sorted((source / "hepta").glob("*.py")):
        read(p)
    sys.path.insert(0, str(source))
    from hepta.hia_schema import PRIMITIVE_PROFILES
    save(out / "source-before.json", pins)
    oracle = out / "oracle.py"
    oracle_source = (
        "import sys\n"
        "sys.dont_write_bytecode=True\n"
        "sys.path.insert(0," + repr(str(source)) + ")\n"
        "from hepta.cli import hia_main\n"
        "raise SystemExit(hia_main(sys.argv[1:]))\n"
    )
    oracle.write_text(oracle_source)
    read(oracle)
    save(out / "source-before.json", pins)
    rows = []
    result = dict(status="INCOMPLETE", scope="NEW_CI_ACTUAL_SEVEN_IMAGE_ELF_PREFIX_ONLY",
                  ordinary_business_owner_closed=False, publication_closed=False,
                  installed_entry_activated=False, native_interpreter_or_runtime_fallback=False)
    ledger = (out / "cases.jsonl").open("w")

    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int

    def child_limits(close_stdin, expected_parent):
        # The outer CI supervisor kills this harness's process group. Each child
        # starts a separate session, so also bind its lifetime to this parent.
        if prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))
        if os.getppid() != expected_parent:
            os.kill(os.getpid(), signal.SIGKILL)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if close_stdin:
            os.close(0)

    def invoke(label, kind, argv, directory, columns="80", tty_columns=None, close_stdin=False):
        target = out / "cases" / label / kind
        target.mkdir(parents=True, exist_ok=False)
        env = dict(PATH="", HOME="", LC_ALL="C.UTF-8", LANG="C.UTF-8",
                   PYTHONINTMAXSTRDIGITS="4300", PYTHONDONTWRITEBYTECODE="1",
                   PYTHONNOUSERSITE="1")
        if columns is not None:
            env["COLUMNS"] = columns
        command = [str(executable), *argv] if kind == "native" else [sys.executable, "-I", str(oracle), *argv]
        master = slave = None
        captured = bytearray()
        tty_eof = False
        process = None
        status = usage = None
        started = time.monotonic_ns()
        timed_out = False
        expected_parent = os.getpid()
        with (target / "stdout.bin").open("wb") as so, (target / "stderr.bin").open("wb") as se:
            try:
                if tty_columns is not None:
                    master, slave = pty.openpty()
                    fcntl.ioctl(slave, 0x5414, struct.pack("HHHH", 17, tty_columns, 0, 0))
                    os.set_blocking(master, False)
                process = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                    stdout=slave if slave is not None else so, stderr=se,
                    start_new_session=True, preexec_fn=lambda: child_limits(close_stdin, expected_parent))
                if slave is not None:
                    os.close(slave)
                    slave = None
                while status is None or (master is not None and not tty_eof):
                    if master is not None and not tty_eof:
                        ready, _, _ = select.select([master], [], [], 0.02)
                        if ready:
                            try:
                                part = os.read(master, 65536)
                                if part:
                                    captured.extend(part)
                                else:
                                    tty_eof = True
                            except BlockingIOError:
                                pass
                            except OSError as error:
                                if error.errno != 5:
                                    raise
                                tty_eof = True
                    else:
                        time.sleep(0.01)
                    if status is None:
                        pid, state, measured = os.wait4(process.pid, os.WNOHANG)
                        if pid:
                            status, usage = state, measured
                            process.returncode = os.waitstatus_to_exitcode(state)
                    if time.monotonic_ns() - started > 30_000_000_000:
                        timed_out = True
                        break
            finally:
                original_error = sys.exception()
                cleanup_errors = []
                if process is not None and process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except BaseException as error:
                        cleanup_errors.append(error)
                    try:
                        _, status, usage = os.wait4(process.pid, 0)
                        process.returncode = os.waitstatus_to_exitcode(status)
                    except BaseException as error:
                        cleanup_errors.append(error)
                for descriptor in (slave, master):
                    if descriptor is not None:
                        try:
                            os.close(descriptor)
                        except BaseException as error:
                            cleanup_errors.append(error)
                slave = master = None
                if tty_columns is not None:
                    try:
                        so.write(captured)
                    except BaseException as error:
                        cleanup_errors.append(error)
                if cleanup_errors:
                    if original_error is not None:
                        for error in cleanup_errors:
                            original_error.add_note("CLI child cleanup: " + repr(error))
                    else:
                        raise cleanup_errors[0]
        stdout, stderr = (target / "stdout.bin").read_bytes(), (target / "stderr.bin").read_bytes()
        record = dict(argv=argv, env=env, tty_columns=tty_columns, close_stdin=close_stdin,
                      pid=process.pid, returncode=process.returncode, wait_status=status,
                      timed_out=timed_out, elapsed_ns=time.monotonic_ns() - started,
                      usage=dict(user=usage.ru_utime, system=usage.ru_stime, maxrss_kib=usage.ru_maxrss),
                      stdout=cas(stdout), stderr=cas(stderr))
        save(target / "process.json", record)
        assert not timed_out, (label, kind, "timeout")
        return (process.returncode, stdout, stderr), record

    def compare(label, argv, directory, **kw):
        expected, rr = invoke(label, "reference", argv, directory, **kw)
        actual, nr = invoke(label, "native", argv, directory, **kw)
        row = dict(label=label, scope="ACTUAL_ELF_FULL_STDOUT_STDERR_EXIT_EQUIVALENCE",
                   argv=argv, reference=rr, native=nr, equal=actual == expected)
        rows.append(row)
        ledger.write(json.dumps(row, sort_keys=True) + "\n"); ledger.flush()
        assert actual == expected, (label, expected[0], actual[0], digest(expected[1]), digest(actual[1]),
                                    digest(expected[2]), digest(actual[2]))

    def pending(label, argv, directory, **kw):
        actual, nr = invoke(label, "native", argv, directory, **kw)
        row = dict(label=label, scope="EXPLICIT_OPEN_BUSINESS_HANDOFF_NOT_EQUIVALENCE",
                   argv=argv, native=nr, expected_exit=126,
                   not_a_successful_business_result=True)
        rows.append(row)
        ledger.write(json.dumps(row, sort_keys=True) + "\n"); ledger.flush()
        assert actual == (126, b"", b""), (label, actual[0], actual[1], actual[2])

    try:
        with tempfile.TemporaryDirectory(prefix="hia-cli-entry-fixtures-") as fixture_dir:
            fx = Path(fixture_dir)
            (fx / "ordinary").write_bytes(b"native CLI business is intentionally not connected\n")
            (fx / "empty").write_bytes(b"")
            (fx / "maximum").write_bytes(b"x" * 8388608)
            (fx / "oversized").write_bytes(b"x" * 8388609)
            (fx / "directory").mkdir()
            (fx / "symlink").symlink_to("ordinary")
            (fx / "dangling").symlink_to("absent")
            (fx / "parent-link").symlink_to(".", target_is_directory=True)
            os.mkfifo(fx / "fifo")
            fixture_rows = []
            for p in sorted(fx.iterdir()):
                info = p.lstat()
                row = dict(name=p.name, mode=stat.S_IMODE(info.st_mode),
                           file_type=stat.S_IFMT(info.st_mode), links=info.st_nlink)
                if p.is_symlink():
                    row["symlink_target"] = os.readlink(p)
                elif stat.S_ISREG(info.st_mode):
                    row["data"] = cas(p.read_bytes())
                fixture_rows.append(row)
            save(out / "fixtures.json", fixture_rows)

            smoke = [("smoke-version", ["--version"]), ("smoke-help", ["--help"]),
                     ("smoke-capabilities", ["capabilities"]), ("smoke-catalog", ["catalog"]),
                     ("smoke-file-refusal", ["verify", str(fx / "absent")])]
            for label, argv in smoke:
                compare(label, argv, fx)
            core_args = [
                [], ["-h"], ["--ver"], ["--"], ["bogus"], ["--unknown"],
                ["capabilities", "--schema=x"], ["catalog", "--schema"],
                ["catalog", "--schema", "bad"], ["catalog", "--schema="],
                ["--version", "bogus"], ["--help", "--unknown"],
                ["catalog", "--", "--schema"], ["verify", "--output", "x"],
                ["build", "absent", "-o", "out", "--kind", "elf"],
                ["build", "absent", "-o", "out", "--backend", "python"],
                ["build", "absent", "-o", "out", "--target", "bad"],
                ["edit-query", "absent", "--function", "f"],
                ["edit-apply", "absent", "--query", "q"],
                ["edit-batch-query", "absent"], ["catalog", "\udcff"],
            ]
            for i, argv in enumerate(core_args):
                compare("args-" + str(i).zfill(3), argv, fx)
            names = ["capabilities", "catalog", "import-assembly", "render-assembly", "check-assembly",
                     "verify", "inspect", "normalize", "build", "patch", "impact",
                     "edit-query", "edit-apply", "edit-batch-query", "edit-batch-apply"]
            for action in names:
                for width in ("20", "79", "120"):
                    compare("help-" + action + "-" + width, [action, "--help"], fx, columns=width)
                if action not in ("capabilities", "catalog"):
                    compare("missing-" + action, [action], fx)
            for i, schema in enumerate(PRIMITIVE_PROFILES):
                compare("catalog-" + str(i), ["catalog", "--schema", schema], fx)
            for label, argv, width in [("tty-top", ["--help"], 53), ("tty-build", ["build", "--help"], 36),
                                      ("tty-error", ["edit-apply"], 71)]:
                compare(label, argv, fx, columns=None, tty_columns=width)
            required = {
                "build": ["--output", "unused-output"],
                "patch": ["--request", "unused-request"],
                "impact": ["--request", "unused-request"],
                "edit-query": ["--function", "f", "--block", "b", "--value", "v", "--fields", "x"],
                "edit-apply": ["--query", "unused-query", "--response", "unused-response"],
                "edit-batch-query": ["--selections", "unused-selections"],
                "edit-batch-apply": ["--query", "unused-query", "--response", "unused-response"],
            }
            for action in names[2:]:
                for fixture in ("absent", "directory", "symlink", "dangling", "fifo", "oversized"):
                    compare("file-" + action + "-" + fixture,
                            [action, str(fx / fixture), *required.get(action, ())], fx)
            compare("file-empty-path", ["verify", ""], fx)
            compare("file-surrogateescape-name", ["verify", str(fx / "missing-\udcff")], fx)
            compare("file-repeated-slash", ["verify", str(fx) + "///directory/./"], fx)
            for action in names[2:]:
                pending("pending-" + action, [action, str(fx / "ordinary"), *required.get(action, ())], fx)
            for label, path, close_stdin in [
                ("pending-empty", fx / "empty", False),
                ("pending-max", fx / "maximum", False),
                ("pending-parent-symlink", fx / "parent-link/ordinary", False),
                ("pending-osfd-zero", fx / "ordinary", True),
            ]:
                pending(label, ["verify", str(path)], fx, close_stdin=close_stdin)
        result.update(status="PASS", cases=len(rows),
                      exact_equivalence_cases=sum(r["scope"].startswith("ACTUAL_ELF") for r in rows),
                      explicit_open_handoff_cases=sum(r["scope"].startswith("EXPLICIT_OPEN") for r in rows),
                      native_processes=len(rows),
                      reference_processes=sum(r["scope"].startswith("ACTUAL_ELF") for r in rows),
                      private_runtime_interpreter=False, utf8_linux_startup_profile=True,
                      raw_buffers_preserved="all process stdout/stderr and filesystem input content")
    except BaseException:
        result.update(status="FAIL", completed_cases=len(rows), failure=traceback.format_exc())
        (out / "failure.txt").write_text(result["failure"])
        raise
    finally:
        ledger.close()
        save(out / "cases-completed.json", rows)
        after = {p: digest(Path(p).read_bytes()) for p in pins}
        save(out / "source-after.json", after)
        result["source_pins_unchanged"] = after == pins
        save(out / "result.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
        assert after == pins

if __name__ == "__main__":
    main()
