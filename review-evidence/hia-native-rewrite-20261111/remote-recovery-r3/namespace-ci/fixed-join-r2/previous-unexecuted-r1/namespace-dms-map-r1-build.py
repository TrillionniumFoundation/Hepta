"""Fresh four-role DMS7 / Map3 / memory1 / FS5 build and actual HIA publication.

Every role is generated and compiled anew under the unchanged original B3 gate.
This is a new component build, not a new cold qualification or ordinary Store.
No image or native count is inherited from the separate predecessor components.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import argparse, ctypes, hashlib, importlib.util, json, os
from pathlib import Path
import shutil, stat, struct, subprocess, time, traceback

ASSEMBLY_SHA = "308b3b0f9d785e71493def82a43ceb4d8aa2891e79ef73e63a4d620657900406"
PACKER_SOURCE_SHA = "0bb8c8f223947256f3dba5b69ff2508c656def2a28dc5c272a840e456c5eb1a3"
B3_SHA = "35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
CANARY = bytes(range(160, 176))
ROLE_SOURCES = {
    1: ("generate_hia_agent_namespace_filesystem_r5.py",
        "d1bc8721c3cd5f3276024c239a11060a005161b8d9f23114495cec04d68c48a6"),
    2: ("generate_hia_agent_namespace_shm_map_r3.py",
        "1ac940af6b31b8e7cc02ada063a46fc5a28ee04f524bb60d5bfeb5fde109fcde"),
    3: ("generate_hia_agent_namespace_memory_leases.py",
        "353f2ec8e9e95ce4186ea404893ea2f599e6963a29d541894e0613740ebef2c7"),
    4: ("generate_hia_agent_namespace_dms_map_join_r7.py",
        "ccbcaca8c9e4f4054419fee69efd55db81c48367fee410317a0cb04284f4f8fa"),
}
BUILDER_SOURCES = {
    "generate_hia_agent_namespace_store":
        "7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50",
    "generate_hia_agent_namespace_objects":
        "2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de",
}
ROLES = (1, 2, 3, 4)
EXPECTED_PACKER_CONTROLS = 25

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
        path = Path(path).absolute()
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        path = path.resolve()
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
    out = evidence / "join-build-r1"
    out.mkdir(parents=False, exist_ok=False)
    (out / "source").mkdir()
    report = dict(status="INCOMPLETE", scope="NEW_FIXED_FOUR_IMAGE_DMS_MAP_MEMORY_BUILD_NOT_ORDINARY_STORE",
                  actual_carrier_processes=0, packer_entries=0, fresh_role_compiles=0,
                  inherited_test_counts=False, generated_roles={}, compiled_roles={},
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
        try:
            done = subprocess.run(argv, capture_output=True, timeout=timeout,
                                  env=dict(os.environ, LC_ALL="C", PYTHONDONTWRITEBYTECODE="1"))
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b"", error.stderr or b""
            (out / (label + ".stdout")).write_bytes(stdout)
            (out / (label + ".stderr")).write_bytes(stderr)
            save(out / (label + ".json"), dict(args=[str(x) for x in argv],
                 status="TIMEOUT", timeout_seconds=timeout, elapsed_ns=time.monotonic_ns() - start,
                 stdout_bytes=len(stdout), stdout_sha256=sha(stdout),
                 stderr_bytes=len(stderr), stderr_sha256=sha(stderr)))
            raise
        (out / (label + ".stdout")).write_bytes(done.stdout)
        (out / (label + ".stderr")).write_bytes(done.stderr)
        save(out / (label + ".json"), dict(args=[str(x) for x in argv],
             returncode=done.returncode, elapsed_ns=time.monotonic_ns() - start,
             stdout_bytes=len(done.stdout), stdout_sha256=sha(done.stdout),
             stderr_bytes=len(done.stderr), stderr_sha256=sha(done.stderr)))
        assert done.returncode == 0, (label, done.returncode, done.stderr)
        return done.stdout

    try:
        assert context.get("namespace_predecessor") is None
        roles = {}
        kernels = {}
        compiler = evidence / "compiler/B3.image.bin"
        compiler_raw = pin(compiler, B3_SHA)
        assert len(compiler_raw) == 669556
        fixed_source = pin(args.executor, ASSEMBLY_SHA)
        pin(__file__)
        sys.path.insert(0, str(ref))
        for name, expected in BUILDER_SOURCES.items():
            load("tools." + name, tree / "tools" / (name + ".py"), expected)
        packer = load("namespace_dms_join_packer", args.packer, PACKER_SOURCE_SHA)
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve() == ref / "tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve() == ref / "tools/hia_selfhost_child.py"
        def profile_of(document):
            assert document["functions"]
            value = dict(functions=len(document["functions"]),
                blocks=sum(len(f["blocks"]) for f in document["functions"]),
                max_blocks=max(len(f["blocks"]) for f in document["functions"]),
                ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
                max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
            assert value["functions"] <= 128 and value["blocks"] <= 1536
            assert value["max_blocks"] <= 256 and value["ops"] <= 8192
            assert value["max_block_params"] <= 16
            return value

        def compile_bound(label, source):
            directory = out / "compile" / label
            directory.mkdir(parents=True, exist_ok=False)
            path, receipt = qualifier.compile_stage(directory, label, compiler, source)
            raw = pin(path)
            assert receipt["source_sha256"] == receipt["input_sha256"] == sha(source)
            assert receipt["artifact_sha256"] == receipt["image_sha256"] == B3_SHA
            assert receipt["produced_sha256"] == sha(raw) and receipt["produced_bytes"] == len(raw)
            assert 0 < len(raw) <= 1 << 20
            assert receipt["limits"]["cpu_seconds"] == 10
            assert receipt["limits"]["address_bytes"] == 256 << 20
            assert receipt["runner_sha256"] == sha(pin(qualifier.CHILD))
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            request = json.loads((directory / (label + ".request.json")).read_bytes())
            assert request["capacity"] == request["workspace_size"] == 1 << 20
            return path, raw, receipt

        generated = {}
        for role in ROLES:
            filename, expected = ROLE_SOURCES[role]
            author = load("namespace_join_author_" + str(role), tree / "tools" / filename, expected)
            document = author.document()
            profile = profile_of(document)
            source = render_assembly(document).encode()
            assemble_program(source)
            path = out / ("role-" + str(role) + ".hiaasm")
            path.write_bytes(source)
            pin(path, sha(source))
            generated[role] = (path, source, profile)
            report["generated_roles"][str(role)] = dict(path=str(path), bytes=len(source),
                sha256=sha(source), profile=profile, author_source_sha256=expected)
            save(out / "summary.json", report)

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
        for role in ROLES:
            path, source, profile = generated[role]
            image_path, raw, receipt = compile_bound("role-" + str(role), source)
            kernels[role] = raw
            report["fresh_role_compiles"] += 1
            roles[str(role)] = dict(source=dict(path=str(path), bytes=len(source), sha256=sha(source)),
                image=dict(path=str(image_path), bytes=len(raw), sha256=sha(raw)),
                author_source_sha256=ROLE_SOURCES[role][1], profile=profile,
                compile_receipt=receipt)
            report["compiled_roles"][str(role)] = roles[str(role)]
            save(out / "summary.json", report)
        assert report["fresh_role_compiles"] == 4
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
        pin(out / "packer.hiaasm", sha(source))
        image_path, image, receipt = compile_bound("namespace-join-packer", source)
        packer_image = NativeHiaJsonImage(image, sha(image))
        assert packer_image.image_sha256 == sha(image)
        records = bytearray()
        record_offsets = {}
        for role in ROLES:
            record_offsets[role] = 64 + len(records)
            records += struct.pack("<3Q", role, len(kernels[role]), 0) + kernels[role]
        payload = struct.pack("<8Q", packer.MAGIC, 1, 4, 64 + len(records), 0, 0, 0, 0) + records
        payload = bytes(payload)
        (out / "packer-input.bin").write_bytes(payload)
        expected = bytearray(prefix)
        positions = {}
        for role in ROLES:
            position = (len(expected) + 15) & ~15
            expected.extend(bytes(position - len(expected)))
            positions[role] = position
            expected.extend(kernels[role])
            struct.pack_into("<Q", expected, table + role * 8, 0x400000 + position)
        size = len(expected)
        struct.pack_into("<2Q", expected, 96, size, size)
        cases = [("normal", payload, size, size, bytes(expected))]
        def changed(offset, value):
            raw = bytearray(payload); struct.pack_into("<Q", raw, offset, value); return bytes(raw)
        controls = [("magic", 0, 0), ("version", 8, 0), ("role-count", 16, 3),
            ("total-length", 24, 64), ("reserved", 56, 1)]
        for role in ROLES:
            offset = record_offsets[role]
            controls.extend([
                ("role-" + str(role) + "-wrong", offset, 5),
                ("role-" + str(role) + "-empty", offset + 8, 0),
                ("role-" + str(role) + "-large", offset + 8, (1 << 20) + 1),
                ("role-" + str(role) + "-reserved", offset + 16, 1),
            ])
        for label, offset, value in controls:
            cases.append((label, changed(offset, value), size, 0xffffffff, bytes(size)))
        cases.append(("truncated-source", payload[:-1], size, 0xffffffff, bytes(size)))
        cases.append(("short-output", payload, size - 1, 0xfffffffe, bytes(size - 1)))
        cases.append(("trailing-source", payload + b"\0", size, 0xffffffff, bytes(size)))
        assert len(cases) == EXPECTED_PACKER_CONTROLS
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
        executable = out / "hia-namespace-dms-map"
        actual = (out / "packer-controls/normal/output.bin").read_bytes()
        executable.write_bytes(actual); executable.chmod(0o755)
        assert executable.read_bytes() == bytes(expected)
        assert actual[:4] == b"\x7fELF"
        assert struct.unpack_from("<H", actual, 56)[0] == 2
        assert struct.unpack_from("<I", actual, 64)[0] == 1
        assert struct.unpack_from("<I", actual, 120)[0] == 0x6474e551
        assert struct.unpack_from("<2Q", actual, 96) == (len(actual), len(actual))
        for role in ROLES:
            position = positions[role]
            assert actual[position:position + len(kernels[role])] == kernels[role]
            assert struct.unpack_from("<Q", actual, table + role * 8)[0] == 0x400000 + position
        assert report["packer_entries"] == len(outcomes) == EXPECTED_PACKER_CONTROLS
        report.update(status="PASS_BUILD_ONLY", profile=profile, compile_receipt=receipt,
            packer_controls=outcomes, coordinator_source_sha256=sha(generated[4][1]),
            coordinator_image_sha256=sha(kernels[4]), packer_image_sha256=sha(image),
            exact_roles=roles,
            executable=dict(path=str(executable), bytes=len(actual), sha256=sha(actual), mode=0o755,
                image_offsets={str(k):v for k,v in positions.items()},
                image_bytes={str(k):len(v) for k,v in kernels.items()},template_bytes=len(binary),layout=layout))
    except BaseException as error:
        report.update(status="FAIL", error_class=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if packer_image is not None:
            try:
                packer_image._mapping.close()
            except BaseException as cleanup:
                report["status"] = "FAIL"
                report["mapping_cleanup_error"] = repr(cleanup)
        after = {}
        for path in pins:
            p = Path(path)
            try:
                info = p.lstat()
                assert stat.S_ISREG(info.st_mode) and not p.is_symlink()
                raw = p.read_bytes()
                after[path] = dict(bytes=len(raw), sha256=sha(raw), mode=stat.S_IMODE(info.st_mode))
            except BaseException as error:
                after[path] = dict(error_class=type(error).__name__, error=str(error))
        report.update(source_before=pins, source_after=after, source_pins_unchanged=after == pins)
        if after != pins:
            report["status"] = "FAIL"
        save(out / "summary.json", report)
        print(json.dumps({k: report[k] for k in ("status", "scope", "packer_entries",
                                               "actual_carrier_processes", "source_pins_unchanged")}), flush=True)
    raise SystemExit(0 if report["status"] == "PASS_BUILD_ONLY" else 1)

if __name__ == "__main__":
    main()
