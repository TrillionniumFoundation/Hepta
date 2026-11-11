"""Build the NEW fixed FS carrier using the actually compiled FS-r4 image.

This script is a development builder, not an installed runtime. Its output is a
static ELF containing the fixed syscall template and real HIA filesystem image.
No native execution claim exists until this script and the separate ELF harness
actually run. All prior failed/source-only attempts remain separate evidence.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import argparse, ctypes, hashlib, importlib.util, json, os
from pathlib import Path
import shutil, stat, struct, subprocess, time, traceback

ASSEMBLY_SHA = "b2389a0528c5a22960d978c95aaf97c32bc1f829fe49ac80e70f8a31fa6228cb"
PACKER_SOURCE_SHA = "32d433607cb544f00113a5de1a36add37934667b49f3ee012a733d4470f46a8a"
B3_SHA = "35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
CANARY = bytes(range(160, 176))

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--executor", type=Path, required=True)
    parser.add_argument("--packer", type=Path, required=True)
    args = parser.parse_args()
    assert sys.version_info[:3] == (3, 12, 14)
    pins = {}
    def pin(path, expected=None):
        path = Path(path).resolve()
        assert path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        row = dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE(path.stat().st_mode))
        if expected is not None:
            assert row["sha256"] == expected, (str(path), row["sha256"], expected)
        if str(path) in pins:
            assert pins[str(path)] == row
        pins[str(path)] = row
        return raw
    def load(name, path, expected=None):
        raw = pin(path, expected)
        specification = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(specification)
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module
    context_raw = pin(args.context)
    context = json.loads(context_raw)
    ref = Path(context["reference"]).resolve()
    tree = Path(context["namespace_working"]).resolve()
    evidence = Path(context["namespace_evidence"]).resolve()
    out = evidence / "carrier-build-r1"
    out.mkdir(parents=False, exist_ok=False)
    (out / "source").mkdir()
    report = dict(status="INCOMPLETE", scope="NEW_PRIVATE_FS_CARRIER_BUILD_NOT_ORDINARY_STORE",
                  actual_carrier_processes=0, packer_entries=0,
                  physical_store_closed=False, sqlite_migration_closed=False)
    packer_image = None
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int

    class Buffer:
        def __init__(self, size, initial=b"", readonly=False):
            assert 0 <= len(initial) <= size
            self.size = size
            self.middle = (size + 32 + 4095) & ~4095
            self.total = self.middle + 8192
            self.raw = None
            address = libc.mmap(None, self.total, 0, 0x22, -1, 0)
            if address == ctypes.c_void_p(-1).value:
                raise OSError(ctypes.get_errno(), "mmap")
            self.raw = address
            self.address = address + 4112
            try:
                if libc.mprotect(address + 4096, self.middle, 3):
                    raise OSError(ctypes.get_errno(), "mprotect RW")
                ctypes.memmove(self.address - 16, CANARY, 16)
                ctypes.memmove(self.address + size, CANARY, 16)
                if initial:
                    ctypes.memmove(self.address, initial, len(initial))
                if readonly and libc.mprotect(address + 4096, self.middle, 1):
                    raise OSError(ctypes.get_errno(), "mprotect RO")
            except BaseException:
                self.close()
                raise
        def read(self):
            return ctypes.string_at(self.address, self.size)
        def check(self):
            assert ctypes.string_at(self.address - 16, 16) == CANARY
            assert ctypes.string_at(self.address + self.size, 16) == CANARY
        def close(self):
            if self.raw is not None:
                original = self.raw
                self.raw = None
                if libc.munmap(original, self.total):
                    raise OSError(ctypes.get_errno(), "munmap")

    def command(label, argv, timeout=30):
        start = time.monotonic_ns()
        done = subprocess.run(argv, capture_output=True, timeout=timeout,
                              env=dict(os.environ, LC_ALL="C", PYTHONDONTWRITEBYTECODE="1"))
        (out / (label + ".stdout")).write_bytes(done.stdout)
        (out / (label + ".stderr")).write_bytes(done.stderr)
        save(out / (label + ".json"), dict(args=[str(x) for x in argv],
             returncode=done.returncode, elapsed_ns=time.monotonic_ns() - start,
             stdout_bytes=len(done.stdout), stdout_sha256=sha(done.stdout),
             stderr_bytes=len(done.stderr), stderr_sha256=sha(done.stderr)))
        assert done.returncode == 0, (label, done.returncode, done.stderr)
        return done.stdout

    try:
        # This r4 builder consumes the freshly executed r4 VM/native result.
        # The sealed r3 provider is retained only as historical provenance.
        assert context.get("namespace_predecessor") is None
        prior_path = evidence / "validation-r1/result.json"
        prior_raw = pin(prior_path)
        prior = json.loads(prior_raw)
        assert prior["status"] == "PASS" and prior["source_unchanged"]
        assert prior["produced_image_before_after_equal"] is True
        assert prior["native_entries"] > 0
        assert set(prior["tests"]) == {"vm", "paired"}
        for row in prior["tests"].values():
            assert row["passed"] and 0 < row["tests_loaded"] == row["tests_run"] == len(row["test_ids"]) == 18
            assert not any(row[k] for k in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
        kernel_row = prior["image"]
        kernel = pin(kernel_row["path"], kernel_row["sha256"])
        assert len(kernel) == kernel_row["bytes"] and 0 < len(kernel) <= 1 << 20
        kernel_source = pin(tree / "examples/hia_bootstrap/agent_namespace_filesystem_r4.hiaasm",
                            prior["source_sha256"])
        compiler = evidence / "compiler/B3.image.bin"
        compiler_raw = pin(compiler, B3_SHA)
        assert len(compiler_raw) == 669556
        fixed_source = pin(args.executor, ASSEMBLY_SHA)
        pin(__file__)
        sys.path.insert(0, str(ref))
        for name in ("generate_hia_agent_namespace_store", "generate_hia_agent_namespace_objects"):
            load("tools." + name, tree / "tools" / (name + ".py"))
        packer = load("namespace_filesystem_packer", args.packer, PACKER_SOURCE_SHA)
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve() == ref / "tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve() == ref / "tools/hia_selfhost_child.py"
        for module in tuple(sys.modules.values()):
            filename = getattr(module, "__file__", None)
            if filename:
                path = Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix == ".py":
                    pin(path)
        pin(qualifier.CHILD)
        for number, (path, row) in enumerate(pins.items()):
            original = pin(path)
            target = out / "source" / str(number) / Path(path).name
            target.parent.mkdir(parents=True)
            target.write_bytes(original); target.chmod(row["mode"])
        save(out / "source-before.json", pins)
        for name in ("as", "readelf", "nm", "objcopy"):
            tool = shutil.which(name)
            assert tool is not None, ("missing installed build tool", name)
            command("tool-" + name, [tool, "--version"])
        assembler = shutil.which("as"); readelf = shutil.which("readelf")
        nm = shutil.which("nm"); objcopy = shutil.which("objcopy")
        obj = out / "executor.o"
        binary_path = out / "executor.bin"
        command("assemble", [assembler, "--64", "-o", obj, args.executor])
        relocation_output = command("relocations", [readelf, "-rW", obj])
        assert b"There are no relocations in this file." in relocation_output
        symbol_output = command("symbols", [nm, "-n", obj])
        symbols = {}
        for line in symbol_output.decode().splitlines():
            fields = line.split()
            if len(fields) == 3:
                symbols[fields[2]] = int(fields[0], 16)
        command("binary", [objcopy, "-O", "binary", "-j", ".text", obj, binary_path])
        binary = binary_path.read_bytes()
        layout = dict(entry=symbols["executor_start"], image_table=symbols["image_table"],
                      end=symbols["executor_end"], template_bytes=len(binary),
                      template_sha256=sha(binary), source_sha256=sha(fixed_source),
                      relocation_count=0)
        save(out / "layout.json", layout)
        prefix, table = packer.prefix_and_table(fixed_source, binary, layout)
        document = packer.document(prefix, table)
        source = render_assembly(document).encode()
        (out / "packer.hiaasm").write_bytes(source)
        assemble_program(source)
        profile = dict(functions=len(document["functions"]),
            blocks=sum(len(f["blocks"]) for f in document["functions"]),
            max_blocks=max(len(f["blocks"]) for f in document["functions"]),
            ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
            max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
        assert profile["functions"] <= 128 and profile["blocks"] <= 1536
        assert profile["max_blocks"] <= 256 and profile["ops"] <= 8192
        assert profile["max_block_params"] <= 16
        compile_dir = out / "compile"
        compile_dir.mkdir()
        image_path, receipt = qualifier.compile_stage(compile_dir, "namespace-native-packer", compiler, source)
        image = image_path.read_bytes()
        assert receipt["source_sha256"] == receipt["input_sha256"] == sha(source)
        assert receipt["artifact_sha256"] == receipt["image_sha256"] == B3_SHA
        assert receipt["produced_sha256"] == sha(image) and receipt["produced_bytes"] == len(image)
        assert receipt["limits"]["cpu_seconds"] == 10
        assert receipt["limits"]["address_bytes"] == 256 << 20
        assert receipt["runner_sha256"] == sha(pin(qualifier.CHILD))
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        request = json.loads((compile_dir / "namespace-native-packer.request.json").read_bytes())
        assert request["capacity"] == request["workspace_size"] == 1 << 20
        packer_image = NativeHiaJsonImage(image, sha(image))
        assert packer_image.image_sha256 == sha(image)
        payload = struct.pack("<8Q", packer.MAGIC, 3, len(kernel), 64 + len(kernel), 0, 0, 0, 0) + kernel
        (out / "packer-input.bin").write_bytes(payload)
        start = (len(prefix) + 15) & ~15
        size = start + len(kernel)
        expected = bytearray(prefix + bytes(start - len(prefix)) + kernel)
        struct.pack_into("<Q", expected, table + 8, 0x400000 + start)
        struct.pack_into("<2Q", expected, 96, size, size)
        cases = [("normal", payload, size, size, bytes(expected))]
        def changed(word, value):
            raw = bytearray(payload); struct.pack_into("<Q", raw, word * 8, value); return bytes(raw)
        for label, word, value in (("magic", 0, 0), ("version", 1, 4), ("empty-image", 2, 0),
                                    ("large-image", 2, (1 << 20) + 1), ("total-length", 3, 64),
                                    ("reserved", 7, 1)):
            cases.append((label, changed(word, value), size, 0xffffffff, bytes(size)))
        cases.append(("short-output", payload, size - 1, 0xfffffffe, bytes(size - 1)))
        outcomes = []
        for label, raw, capacity, expected_return, expected_bytes in cases:
            a = o = w = None
            case = out / "packer-controls" / label
            case.mkdir(parents=True)
            try:
                a = Buffer(len(raw), raw, readonly=True); o = Buffer(capacity); w = Buffer(64)
                before_work = w.read()
                result = int(packer_image._entry(a.address, a.size, o.address, o.size, w.address, w.size))
                report["packer_entries"] += 1
                output = o.read(); after_work = w.read()
                for buffer in (a, o, w): buffer.check()
                assert a.read() == raw and after_work == before_work
                (case / "input.bin").write_bytes(raw)
                (case / "output.bin").write_bytes(output)
                (case / "workspace.bin").write_bytes(after_work)
                row = dict(label=label, actual_return=result, expected_return=expected_return,
                           input_sha256=sha(raw), output_sha256=sha(output), output_bytes=len(output),
                           source_unchanged=True, workspace_unchanged=True, guards=True,
                           exact_output_equal=output == expected_bytes)
                save(case / "result.json", row); outcomes.append(row)
                assert result == expected_return and output == expected_bytes
            finally:
                for buffer in (w, o, a):
                    if buffer is not None: buffer.close()
        executable = out / "hia-namespace-filesystem"
        actual = (out / "packer-controls/normal/output.bin").read_bytes()
        executable.write_bytes(actual); executable.chmod(0o755)
        assert executable.read_bytes() == bytes(expected)
        assert actual[:4] == b"\x7fELF"
        assert struct.unpack_from("<H", actual, 56)[0] == 2
        assert struct.unpack_from("<I", actual, 64)[0] == 1
        assert struct.unpack_from("<I", actual, 120)[0] == 0x6474e551
        assert struct.unpack_from("<2Q", actual, 96) == (len(actual), len(actual))
        assert actual[start:] == kernel
        report.update(status="PASS_BUILD_ONLY", profile=profile, compile_receipt=receipt,
                      packer_controls=outcomes, kernel_source_sha256=sha(kernel_source),
                      kernel_image_sha256=sha(kernel), packer_image_sha256=sha(image),
                      executable=dict(path=str(executable), bytes=len(actual), sha256=sha(actual), mode=0o755,
                                      image_offset=start, kernel_bytes=len(kernel),
                                      template_bytes=len(binary), layout=layout))
    except BaseException as error:
        report.update(status="FAIL", error_class=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if packer_image is not None:
            packer_image._mapping.close()
        after = {}
        for path in pins:
            p = Path(path)
            raw = p.read_bytes()
            after[path] = dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE(p.stat().st_mode))
        report.update(source_before=pins, source_after=after, source_pins_unchanged=after == pins)
        if after != pins:
            report["status"] = "FAIL"
        save(out / "summary.json", report)
        print(json.dumps({k: report[k] for k in ("status", "scope", "packer_entries",
                                               "actual_carrier_processes", "source_pins_unchanged")}), flush=True)
    raise SystemExit(0 if report["status"] == "PASS_BUILD_ONLY" else 1)

if __name__ == "__main__":
    main()
