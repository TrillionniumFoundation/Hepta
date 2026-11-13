"""Explicit HIA argv, presentation and fifteen-action CLI continuation.

The two immutable images own argument decisions, help/error bytes, action
sequencing, read budgets, report updates and exit selection. This foreign
adapter transports strings/handles and performs requested effects. Existing
semantic bodies, read_bounded policy, publication and successful pretty JSON
remain named foreign owners; this is not a whole-native CLI delivery claim.

The presentation profiles are ordinary English CPython 3.12.14, 3.14.4 and 3.14.10,
with the default 3.14 color theme. Arbitrary Python argument objects, custom
argparse subclasses/themes, and concurrent mutation of environment or streams
during parser construction are outside this explicit selected profile.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import struct
import subprocess
import sys
from types import SimpleNamespace

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _load_manifest, _source_resource_path, _unique_manifest_pairs,
)

SELECTOR = "HEPTA_HIA_CLI_MANIFEST"
SCHEMA = "hepta.hia.cli-native-bundle.v1"
CONTROL_SCHEMA = "hepta.hia.cli-control-native.v1"
FORMAT_SCHEMA = "hepta.hia.cli-format-native.v1"
SOURCES = {
    "control": _source_resource_path("examples/hia_bootstrap/cli_control.hepta"),
    "format": _source_resource_path("examples/hia_bootstrap/cli_format.hepta"),
}
ARGV_MAGIC = int.from_bytes(b"HCLIARG4", "little")
RESULT_MAGIC = int.from_bytes(b"HCLIRES4", "little")
STEP_MAGIC = int.from_bytes(b"HCLISTP4", "little")
COMMAND_MAGIC = int.from_bytes(b"HCLICMD4", "little")
ERROR_MAGIC = int.from_bytes(b"HCLIERR4", "little")
OBSERVE_MAGIC = int.from_bytes(b"HCLIOBS4", "little")
HIGH = 1 << 63
DOMAIN_ERRORS = (OSError, ValueError, UnicodeError, subprocess.SubprocessError)


def _utf32(value):
    if type(value) is not str:
        raise TypeError("selected native CLI requires ordinary string observations")
    return value.encode("utf-32-le", "surrogatepass")


def _text(raw):
    if len(raw) % 4:
        raise RuntimeError("misaligned native CLI text extent")
    try:
        return raw.decode("utf-32-le", "surrogatepass")
    except UnicodeError as error:
        raise RuntimeError("invalid native CLI Unicode observation") from error


def _q(buffer, offset):
    return struct.unpack_from("<Q", buffer, offset)[0]


def _frame(arguments, version, environment, profile, columns, color_terminal, ignore_environment, digit_limit):
    """Transport already observed strings and scalar runtime facts."""
    if type(arguments) is not list or any(type(arg) is not str for arg in arguments):
        raise TypeError("selected native CLI argv must contain ordinary strings")
    values = [version]
    presence = 1
    for index, name in enumerate(("PYTHON_COLORS", "NO_COLOR", "FORCE_COLOR", "TERM", "COLUMNS"), 1):
        value = environment.get(name)
        if value is not None:
            presence |= 1 << index
            values.append(value)
        else:
            values.append("")
    values += arguments
    payloads = [_utf32(value) for value in values]
    header_size = 192 + len(arguments) * 16
    raw = bytearray(header_size)
    struct.pack_into("<12Q", raw, 0, ARGV_MAGIC, 4, len(arguments), profile,
                     columns, int(ignore_environment), int(color_terminal), digit_limit,
                     0, presence, 0, 0)
    cursor = header_size
    for index, payload in enumerate(payloads):
        struct.pack_into("<2Q", raw, 96 + index * 16, cursor, len(payload) // 4)
        raw.extend(payload)
        cursor += len(payload)
    return bytes(raw)


def _runtime_profile():
    observed = tuple(sys.version_info[:3])
    profiles = {(3, 12, 14): 312, (3, 14, 4): 314, (3, 14, 10): 31410}
    if sys.implementation.name != "cpython" or observed not in profiles:
        raise RuntimeError("selected native CLI requires its pinned CPython 3.12.14, 3.14.4 or 3.14.10 profile")
    return profiles[observed]


def _terminal_columns():
    # Raw OS observation only. Native code parses COLUMNS and chooses fallback.
    try:
        value = os.get_terminal_size(sys.__stdout__.fileno()).columns
        return value
    except (AttributeError, OSError, ValueError):
        return 0


def _color_terminal():
    # Called only when the HIA color policy requests this observation.
    stream = sys.stdout
    if not hasattr(stream, "fileno"):
        return False
    try:
        return bool(os.isatty(stream.fileno()))
    except OSError:
        return bool(hasattr(stream, "isatty") and stream.isatty())


def _print_parser_message(message, stream):
    # Exact ordinary argparse._print_message write/refusal behavior.
    if message:
        stream = stream or sys.stderr
        try:
            stream.write(message)
        except (AttributeError, OSError):
            pass


def _publish_assembly(program, text, destination):
    """Explicit retained publication body, with the original effect order."""
    from .artifact_publication import publish_verified
    import tempfile
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise ValueError("Assembly output must be a new file")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.resolve() != target.parent:
        raise ValueError("Assembly output parent must not traverse a symlink")
    with tempfile.TemporaryDirectory(prefix=".hepta-assembly-", dir=target.parent) as temporary:
        stage = Path(temporary) / "program.hepta"
        payload = text.encode("utf-8")
        with stage.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        receipt = publish_verified(stage, target, payload)
    return {"schema": "hepta.hia.assembly-output.v1", "ok": True,
            "output": str(target), "core_sha256": program.sha256,
            "publication": receipt, "deployment_authority": False}


class NativeCli:
    def __init__(self, control, formatter):
        self.control = control
        self.formatter = formatter

    def _format_call(self, raw, workspace):
        # This allocation scales with complete input and worst-case escapes;
        # it introduces no new independent CLI output-byte ceiling.
        capacity = (len(raw) // 4 * 12 + 32768) * 4
        output = ctypes.create_string_buffer(capacity)
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        code = self.formatter._entry(source, len(raw), output, len(output),
                                     workspace, len(workspace))
        if code not in (0, 3):
            raise RuntimeError("native CLI formatter protocol or profile refused")
        count, split = struct.unpack_from("<2Q", workspace, 1024)
        if count > len(output) // 4 or split > count:
            raise RuntimeError("invalid native CLI formatter output extent")
        return code, ctypes.string_at(output, count * 4), split

    def _needs_color_terminal(self, raw):
        workspace = ctypes.create_string_buffer(131072)
        struct.pack_into("<Q", workspace, 0, OBSERVE_MAGIC)
        code, text, split = self._format_call(raw, workspace)
        request = _q(workspace, 1064)
        if code != 3 or text or split or request not in (0, 1):
            raise RuntimeError("invalid native CLI environment observation request")
        return request

    def prepare(self, argv, cli):
        # Iteration is performed once, as argparse.parse_known_args does.
        arguments = sys.argv[1:] if argv is None else list(argv)
        profile = _runtime_profile()
        environment = {name: os.environ.get(name) for name in
                       ("PYTHON_COLORS", "NO_COLOR", "FORCE_COLOR", "TERM", "COLUMNS")}
        version = "hia " + cli.__version__
        facts = dict(profile=profile, columns=80, color_terminal=False,
                     ignore_environment=bool(sys.flags.ignore_environment),
                     digit_limit=sys.get_int_max_str_digits())
        raw = _frame(arguments, version, environment, **facts)
        if self._needs_color_terminal(raw):
            facts["color_terminal"] = _color_terminal()
        facts["columns"] = _terminal_columns()
        return CliSession(self, _frame(arguments, version, environment, **facts), cli)

    def format_result(self, session):
        workspace = ctypes.create_string_buffer(131072 + session.argc * 24)
        ctypes.memmove(workspace, session.workspace, 1024)
        extras = _q(session.workspace, 80)
        if extras > session.argc:
            raise RuntimeError("invalid native CLI extra-argument extent")
        if extras:
            ctypes.memmove(ctypes.addressof(workspace) + 131072,
                           ctypes.addressof(session.workspace) + 32768 + session.argc * 48,
                           extras * 24)
        code, raw, split = self._format_call(session.raw, workspace)
        if code != 0:
            raise RuntimeError("unexpected native CLI formatter continuation")
        return _text(raw[:split * 4]), _text(raw[split * 4:])

    def driver_error(self, message):
        payload = _utf32(message)
        raw = struct.pack("<4Q", ERROR_MAGIC, 4, len(payload) // 4, 0) + payload
        workspace = ctypes.create_string_buffer(131072)
        code, text, split = self._format_call(raw, workspace)
        if code != 0 or split:
            raise RuntimeError("invalid native CLI E_DRIVER output")
        return _text(text)

    def run(self, argv, cli):
        session = self.prepare(argv, cli)
        if session.kind:
            first, second = self.format_result(session)
            session.finished = True
            if session.kind == 3:
                _print_parser_message(first, sys.stderr)
                _print_parser_message(second, sys.stderr)
            else:
                _print_parser_message(first + second, sys.stdout)
            raise SystemExit(session.exit_code)
        return session.run()


class CliSession:
    """A single native continuation; every foreign-effect permission is spent once."""
    def __init__(self, owner, raw, cli):
        self.owner, self.raw, self.cli = owner, raw, cli
        self.argc = struct.unpack_from("<Q", raw, 16)[0]
        self.workspace = ctypes.create_string_buffer(65536 + self.argc * 80 + len(raw))
        self.output = ctypes.create_string_buffer(128)
        self.finished = False
        self.pending = False
        self.domain_failure = False
        self.handles = [None]
        self.common = {}
        try:
            source = ctypes.create_string_buffer(raw, max(1, len(raw)))
            code = owner.control._entry(source, len(raw), self.output, len(self.output),
                                        self.workspace, len(self.workspace))
            if code != 0 or _q(self.workspace, 0) != RESULT_MAGIC:
                raise RuntimeError("native CLI argument frame or profile refused")
            self.kind = _q(self.workspace, 8)
            self.exit_code = _q(self.workspace, 112)
            if self.kind not in (0, 1, 2, 3) or self.exit_code not in (0, 2):
                raise RuntimeError("invalid native CLI argument result")
            self.namespace = self._namespace() if self.kind == 0 else None
            self.packet = self._packet(0, 0, 0, self.register(self.namespace), 0, 0)
        except BaseException:
            self.finished = True
            self.pending = False
            raise

    @staticmethod
    def _packet(sequence, operation, failed, a, b, c):
        return struct.pack("<12Q", STEP_MAGIC, 4, sequence, operation, failed, a, b, c, 0, 0, 0, 0)

    def register(self, value):
        handle = len(self.handles)
        if handle >= HIGH:
            raise RuntimeError("native CLI foreign handle namespace exhausted")
        self.handles.append(value)
        return handle

    def _literal(self, index):
        if index >= 512:
            raise RuntimeError("native CLI literal handle outside its arena")
        begin, size = struct.unpack_from("<2Q", self.workspace, 8192 + index * 16)
        if begin < 16384 or begin > 32768 or size > 32768 - begin:
            raise RuntimeError("native CLI literal extent outside its arena")
        return ctypes.string_at(ctypes.addressof(self.workspace) + begin, size).decode("ascii")

    def _input_text(self, begin, size):
        if begin % 4 or begin > len(self.raw) or size > (len(self.raw) - begin) // 4:
            raise RuntimeError("native CLI input-string extent outside its frame")
        return _text(self.raw[begin:begin + size * 4])

    def _namespace(self):
        values = {}
        for index in range(19):
            kind, begin, size, key = struct.unpack_from("<4Q", self.workspace, 256 + index * 32)
            if kind == 0:
                continue
            name = self._literal(key)
            if name in values:
                raise RuntimeError("duplicate native CLI namespace field")
            if kind == 1:
                if begin or size:
                    raise RuntimeError("invalid native CLI None namespace record")
                value = None
            elif kind == 2:
                value = self._input_text(begin, size)
            elif kind == 3:
                if begin < 16384 or begin > 32768 or size > 32768 - begin:
                    raise RuntimeError("native CLI default-string extent outside its arena")
                value = ctypes.string_at(ctypes.addressof(self.workspace) + begin, size).decode("ascii")
            else:
                raise RuntimeError("unknown native CLI namespace record")
            values[name] = value
        return SimpleNamespace(**values)

    def value(self, handle):
        if 0 < handle < len(self.handles):
            return self.handles[handle]
        if HIGH <= handle < HIGH + 14:
            kind, a, size = struct.unpack_from("<3Q", self.workspace, 4096 + (handle - HIGH) * 32)
            if kind == 1 and a in (0, 1) and size == 0:
                return bool(a)
            if kind == 2 and 6144 <= a <= 8192 and size <= 8192 - a:
                return ctypes.string_at(ctypes.addressof(self.workspace) + a, size).decode("ascii")
        raise RuntimeError("unknown native CLI foreign or literal handle")

    def field(self, namespace, index):
        if index >= 19:
            raise RuntimeError("native CLI field index outside namespace")
        name = self._literal(_q(self.workspace, 256 + index * 32 + 24))
        return getattr(self.value(namespace), name)

    def step(self, packet=None):
        if self.finished or self.pending or self.domain_failure:
            self.finished = True
            self.pending = False
            raise RuntimeError("native CLI continuation is closed or awaiting its effect")
        try:
            raw = self.packet if packet is None else packet
            source = ctypes.create_string_buffer(raw, max(1, len(raw)))
            code = self.owner.control._entry(source, len(raw), self.output, len(self.output),
                                             self.workspace, len(self.workspace))
            command = struct.unpack_from("<16Q", self.output)
            if command[0] != COMMAND_MAGIC or any(command[8:]):
                raise RuntimeError("invalid native CLI command envelope")
            if code == 1:
                operation, sequence, catching, a, b, c, d = command[1:8]
                if not 1 <= operation <= 42 or sequence == 0 or catching not in (0, 1):
                    raise RuntimeError("invalid native CLI effect instruction")
                self.command = (operation, sequence, catching, a, b, c, d)
                self.pending = True
            elif code == 2:
                if command[1] or command[3] or command[4] not in (0, 1, 2) or any(command[5:8]):
                    raise RuntimeError("invalid native CLI terminal instruction")
                self.finished = True
                self.exit_code = command[4]
            else:
                raise RuntimeError("native CLI continuation protocol or profile refused")
            return code
        except BaseException:
            self.finished = True
            self.pending = False
            raise

    def _effect(self, operation, a, b, c, d):
        value, register, field = self.value, self.register, self.field
        zero = (0, 0, 0)
        if operation == 1:
            result = self.cli.agent_capabilities()
        elif operation == 2:
            from .hia_opcodes import opcode_catalog
            result = opcode_catalog(field(a, b))
        elif operation == 3:
            result = self.common["read_bounded"](field(a, b), limit=c)
        elif operation == 4:
            result = self.common["verify_program"](value(a))
        elif operation == 5:
            result = self.common["assemble_program"](value(a))
        elif operation == 6:
            result = self.common["diagnose_assembly"](value(a))
        elif operation == 7:
            result = self.common["render_assembly"](value(a))
        elif operation == 8:
            result = value(a).as_dict()
        elif operation == 9:
            result = value(a).report()
        elif operation == 10:
            result = self.common["inspect_program"](value(a))
        elif operation == 11:
            from .hia_program_native import build_program_machine
            result = build_program_machine(value(a), field(b, c), kind="object", linker="cc")
        elif operation == 42:
            from .hia_program_selfhost import build_program_selfhost
            arguments = value(b)
            result = build_program_selfhost(value(a), arguments.output,
                manifest=arguments.selfhost_manifest,
                manifest_sha256=arguments.selfhost_manifest_sha256,
                kind=arguments.kind, target=arguments.target)
        elif operation == 12:
            result = self.common["decode_json"](value(a))
        elif operation == 13:
            revised, receipt = self.common["apply_program_patch"](value(a), value(b))
            return register(revised), register(receipt), 0
        elif operation == 14:
            revised, receipt, impact = self.common["analyze_patch_impact"](value(a), value(b))
            return register(revised), register(receipt), register(impact)
        elif operation == 15:
            result = self.common["prepare_edit"](
                value(a), function=field(b, 8), block=field(b, 9),
                output=field(b, 10), fields=value(c))
        elif operation == 16:
            revised, receipt = self.common["apply_edit"](value(a), value(b), value(c))
            return register(revised), register(receipt), 0
        elif operation == 17:
            result = self.common["prepare_batch"](value(a), value(b))
        elif operation == 18:
            revised, receipt = self.common["apply_batch"](value(a), value(b), value(c))
            return register(revised), register(receipt), 0
        elif operation == 19:
            result = self.common["publish_program"](value(a), field(b, c))
        elif operation == 20:
            result = self.cli.publish_json_view(value(a), field(b, c))
        elif operation == 21:
            result = _publish_assembly(value(a), value(b), field(c, d))
        elif operation == 22:
            self.cli.output_json(value(a))
            return zero
        elif operation == 23:
            print(value(a), end="")
            return zero
        elif operation == 24:
            result = {**value(a)}
        elif operation == 25:
            value(a)[value(b)] = value(c)
            return zero
        elif operation == 26:
            result = {}
        elif operation == 27:
            result = []
        elif operation == 28:
            value(a).append(value(b))
            return zero
        elif operation == 29:
            result = field(a, b)[c:c + d]
        elif operation == 30:
            return int(bool(value(a)["accepted"])), 0, 0
        elif operation == 31:
            return int(value(a).get("ok") is True), 0, 0
        elif operation == 32:
            result = str(value(a))
        elif operation == 33:
            result = self.owner.driver_error(value(a))
        elif operation == 34:
            print(value(a))
            return zero
        elif operation == 35:
            from .hia_program import verify_program
            from .hia_program_tools import (
                read_bounded, decode_json, inspect_program, apply_program_patch, publish_program,
            )
            self.common.update(verify_program=verify_program, read_bounded=read_bounded,
                               decode_json=decode_json, inspect_program=inspect_program,
                               apply_program_patch=apply_program_patch, publish_program=publish_program)
            return zero
        elif operation == 36:
            from .hia_agent_assembly import assemble_program, render_assembly, diagnose_assembly
            self.common.update(assemble_program=assemble_program, render_assembly=render_assembly,
                               diagnose_assembly=diagnose_assembly)
            return zero
        elif operation == 37:
            from .hia_edit_query import prepare_edit
            self.common["prepare_edit"] = prepare_edit
            return zero
        elif operation == 38:
            from .hia_edit_query import apply_edit, MAX_RESPONSE_BYTES
            self.common["apply_edit"] = apply_edit
            return zero
        elif operation == 39:
            from .hia_edit_batch import prepare_batch
            self.common["prepare_batch"] = prepare_batch
            return zero
        elif operation == 40:
            from .hia_edit_batch import apply_batch, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES
            self.common["apply_batch"] = apply_batch
            return zero
        elif operation == 41:
            from .hia_patch_impact import analyze_patch_impact
            self.common["analyze_patch_impact"] = analyze_patch_impact
            return zero
        else:
            raise RuntimeError("unknown native CLI effect")
        return register(result), 0, 0

    def observe(self):
        if self.finished or not self.pending:
            self.finished = True
            self.pending = False
            raise RuntimeError("native CLI effect permission already consumed or closed")
        operation, sequence, catching, a, b, c, d = self.command
        self.pending = False  # Before any foreign effect or callback.
        self.domain_failure = False
        try:
            try:
                result = self._effect(operation, a, b, c, d)
            except DOMAIN_ERRORS:
                if catching:
                    self.domain_failure = True
                else:
                    self.finished = True
                raise
            self.packet = self._packet(sequence, operation, 0, *result)
            return self.packet
        except BaseException:
            if not self.domain_failure:
                self.finished = True
                self.pending = False
            raise

    def _drive(self):
        while self.step() == 1:
            try:
                self.observe()
            except DOMAIN_ERRORS as error:
                if not self.domain_failure or self.finished:
                    raise
                self.domain_failure = False
                operation, sequence, catching, a, b, c, d = self.command
                self.packet = self._packet(sequence, operation, 1, self.register(error), 0, 0)
                # The entire native-requested handler runs inside this except.
                # str(error) and stdout effects retain the real active exception;
                # no synthetic raise alters its traceback or context.
                return self._drive()
        return self.exit_code

    def run(self):
        try:
            return self._drive()
        except BaseException:
            self.finished = True
            self.pending = False
            self.domain_failure = False
            raise


def _relative_path(value):
    return (type(value) is str and bool(value) and "\0" not in value and "\\" not in value
            and not value.startswith("/") and str(PurePosixPath(value)) == value
            and all(part not in ("", ".", "..") for part in value.split("/")))


def installed_cli(manifest_path):
    """Bind both sources and exact child manifests; selected failures never fall back.

    Warm cache entries retain their original immutable image mapping. They
    do not reread a previously admitted disk image on every command. Source
    and manifest bytes are rebound on every explicit selection.
    """
    path = Path(manifest_path).resolve(strict=True)
    with path.open("rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("native CLI bundle exceeds manifest extent")
    bundle = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode("utf-8"))
    keys = {"schema", "control_manifest", "control_manifest_sha256",
            "format_manifest", "format_manifest_sha256"}
    if type(bundle) is not dict or set(bundle) != keys or bundle["schema"] != SCHEMA:
        raise ValueError("invalid native CLI bundle")
    children = {}
    compilers = []
    for name in ("control", "format"):
        relative, expected = bundle[name + "_manifest"], bundle[name + "_manifest_sha256"]
        if (not _relative_path(relative) or type(expected) is not str or len(expected) != 64
                or any(char not in "0123456789abcdef" for char in expected)):
            raise ValueError("invalid native CLI child identity")
        child = (path.parent / relative).resolve(strict=True)
        if not child.is_relative_to(path.parent):
            raise ValueError("native CLI child leaves its bundle")
        with child.open("rb") as stream:
            child_raw = stream.read(16385)
        if len(child_raw) > 16384 or sha256(child_raw).hexdigest() != expected:
            raise ValueError("native CLI child manifest identity mismatch")
        metadata = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(child_raw.decode("utf-8"))
        if type(metadata) is not dict or not _relative_path(metadata.get("image_path")):
            raise ValueError("invalid native CLI child image path")
        compilers.append(metadata.get("compiler_sha256"))
        children[name] = (child, child_raw)
    if compilers[0] != compilers[1]:
        raise ValueError("native CLI companion compilers differ")
    source_hashes = {name: sha256(source.read_bytes()).hexdigest() for name, source in SOURCES.items()}
    control = _load_manifest(str(children["control"][0]), children["control"][1],
                             source_hashes["control"], CONTROL_SCHEMA, NativeHiaJsonImage)
    formatter = _load_manifest(str(children["format"][0]), children["format"][1],
                               source_hashes["format"], FORMAT_SCHEMA, NativeHiaJsonImage)
    if (path.read_bytes() != raw
            or any(child.read_bytes() != child_raw for child, child_raw in children.values())
            or any(sha256(source.read_bytes()).hexdigest() != source_hashes[name]
                   for name, source in SOURCES.items())):
        raise ValueError("native CLI selection changed while loading")
    return NativeCli(control, formatter)
