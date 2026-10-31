"""Compact, deterministic spelling of checked primitive HIA Core.

This frontend supplies syntax only. Types, effects, ownership, calls, CFG edges,
integer modes and attributes stay explicit, and the existing whole-program
verifier remains the sole semantic authority. No expression synthesis, repair,
automatic cast, inferred cleanup, optimizer, or second evaluator lives here.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
import unicodedata

from .hia_json_preflight import preflight_hia_json
from .hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from .hia_program_tools import HIAEditRejected, decode_json
from .hia_schema import SCHEMA_V6, SCHEMA_V7, SCHEMA_V8

ASSEMBLY_SCHEMA = "hepta.hia.agent-assembly.v1"
WIRE_HEADER = "hia-asm.v1"
CORE_SCHEMAS = frozenset({SCHEMA_V6, SCHEMA_V7, SCHEMA_V8})
MAX_SOURCE_BYTES = 1024 * 1024
MAX_LINES = 16384
MAX_LINE_BYTES = 16384
MAX_FUNCTIONS = 256
MAX_BLOCKS = 4096
MAX_OPERATIONS = 16384
MAX_LIST_ITEMS = 256
MAX_ATTRIBUTE_NODES = 2048
MAX_ATTRIBUTE_DEPTH = 16

_NAME = r"[A-Za-z_][A-Za-z_0-9]{0,127}"
_OPCODE = r"[A-Za-z_][A-Za-z_0-9.]{0,127}"
_HEADER = re.compile(rf"{re.escape(WIRE_HEADER)}\s+(\S+)\s+({_NAME})")
_FUNCTION = re.compile(
    rf"fn\s+({_NAME})\(([^()]*)\)\s*->\s*\(([^()]*)\)"
    rf"\s+effects\(([^()]*)\)\s+entry\(({_NAME})\)"
    rf"(?:\s+return_loans\(([^()]*)\))?")
_BLOCK = re.compile(rf"block\s+({_NAME})\(([^()]*)\)")
_INSTRUCTION = re.compile(rf"([^=]+)\s*=\s*({_OPCODE})\(([^()]*)\)(?:\s+(.*))?")
_RETURN = re.compile(r"ret\(([^()]*)\)")
_JUMP = re.compile(rf"jump\s+({_NAME})\(([^()]*)\)")
_BRANCH = re.compile(rf"branch\s+({_NAME})\s+({_NAME})\(([^()]*)\)\s+({_NAME})\(([^()]*)\)")
_TRAP = re.compile(rf"trap\s+({_NAME})")


class HIAAssemblyRejected(HIAProgramRejected):
    """A bounded syntax/representation refusal or the original Core refusal."""

    def __init__(self, message, code="E_HIA_ASSEMBLY", *, line=None, phase="syntax"):
        self.line = line
        self.phase = phase
        super().__init__((f"line {line}: " if line is not None else "") + message, code)


def _reject(message, *, line=None, limit=False):
    raise HIAAssemblyRejected(message, "E_HIA_ASSEMBLY_LIMIT" if limit else "E_HIA_ASSEMBLY",
                              line=line)


def _source(value):
    if type(value) not in (str, bytes):
        _reject("source must be UTF-8 text or bytes")
    if len(value) > MAX_SOURCE_BYTES:
        _reject("source exceeds byte budget", limit=True)
    try:
        raw = value.encode("utf-8") if type(value) is str else value
        if len(raw) > MAX_SOURCE_BYTES:
            _reject("source exceeds byte budget", limit=True)
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise HIAAssemblyRejected("source is not valid UTF-8") from exc
    # LF and optional CRLF are the only line separators. Do not let Unicode
    # splitlines(), NUL, BOM or terminal controls change visible tokenization.
    # The assembly grammar uses ASCII separators and LF/CRLF only. Python's
    # regex \s also matches Unicode whitespace (e.g. NBSP or U+2028), which
    # would otherwise admit visually misleading spellings of the same Core.
    # Reject invisible format controls before tokenization, not just C0 bytes.
    if any((ord(c) < 32 and c not in "\n\r\t") or c == "\ufeff"
           or (ord(c) > 127 and (c.isspace()
                                  or unicodedata.category(c) in {"Cc", "Cf"}))
           for c in text):
        _reject("unsupported control, Unicode separator/format character or byte-order mark")
    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        _reject("source exceeds line budget", limit=True)
    for number, line in enumerate(lines, 1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            _reject("line exceeds byte budget", line=number, limit=True)
        # A terminal CR has no following LF and is not a CRLF separator.
        # Never silently normalize it into the same canonical Core as LF.
        if "\r" in line.removesuffix("\r") or (number == len(lines) and line.endswith("\r")):
            _reject("carriage return must be part of CRLF", line=number)
    return raw, lines


def _items(value, line):
    if not value.strip():
        return []
    parts = [part.strip() for part in value.split(",")]
    if len(parts) > MAX_LIST_ITEMS:
        _reject("list exceeds item budget", line=line, limit=True)
    if any(not part for part in parts):
        _reject("empty list item", line=line)
    return parts


def _names(value, line):
    parts = _items(value, line)
    if any(re.fullmatch(_NAME, part) is None for part in parts):
        _reject("expected explicit ASCII names", line=line)
    return parts


def _parameters(value, line):
    result = []
    for part in _items(value, line):
        match = re.fullmatch(rf"({_NAME})\s*:\s*({_NAME})", part)
        if match is None:
            _reject("expected name:type for every value", line=line)
        result.append({"name": match[1], "type": match[2]})
    return result


def _attrs(value, line):
    if value is None:
        return {}
    try:
        preflight_hia_json(value, max_nodes=MAX_ATTRIBUTE_NODES,
                          max_depth=MAX_ATTRIBUTE_DEPTH)
        attrs = decode_json(value)
    except (ValueError, OverflowError, HIAEditRejected) as exc:
        raise HIAAssemblyRejected("attributes require bounded strict JSON", line=line) from exc
    if type(attrs) is not dict:
        _reject("attributes must be one JSON object", line=line)
    return attrs


def assemble_program(source: str | bytes) -> VerifiedProgram:
    """Translate explicit assembly to Core and reverify the entire program.

    v6/v7/v8 are the text targets. Historical schemas require their existing
    explicit adapters, and nominal layouts require their existing elaborator.
    """
    _, lines = _source(source)
    document = None
    function = block = None
    blocks = operations = 0
    for number, raw in enumerate(lines, 1):
        line = raw.removesuffix("\r").strip(" \t")
        if not line:
            continue
        if document is None:
            match = _HEADER.fullmatch(line)
            if match is None or match[1] not in CORE_SCHEMAS:
                _reject("expected hia-asm.v1, explicit primitive v6/v7/v8 schema, and module", line=number)
            document = {"schema": match[1], "module": match[2], "functions": []}
            continue
        if function is None:
            exports = re.fullmatch(r"exports\(([^()]*)\)", line)
            if exports is not None:
                if "exports" in document or document["functions"]:
                    _reject("exports may occur once, before all functions", line=number)
                document["exports"] = _names(exports[1], number)
                continue
            match = _FUNCTION.fullmatch(line)
            if match is None:
                _reject("expected explicit function header", line=number)
            if len(document["functions"]) >= MAX_FUNCTIONS:
                _reject("function inventory exceeds budget", line=number, limit=True)
            function = {"name": match[1], "params": _parameters(match[2], number),
                        "returns": _names(match[3], number), "effects": _names(match[4], number),
                        "entry": match[5], "blocks": []}
            if match[6] is not None:
                if document["schema"] != SCHEMA_V8:
                    _reject("return_loans requires explicit Core v8", line=number)
                try:
                    preflight_hia_json(match[6], max_nodes=MAX_LIST_ITEMS + 1, max_depth=2)
                    origins = decode_json(match[6])
                except (ValueError, OverflowError, HIAEditRejected) as exc:
                    raise HIAAssemblyRejected("return_loans requires bounded strict JSON", line=number) from exc
                if (type(origins) is not list or len(origins) > MAX_LIST_ITEMS
                        or any(x is not None and (type(x) is not str or re.fullmatch(_NAME, x) is None)
                               for x in origins)):
                    _reject("return_loans requires a list of formal names or null", line=number)
                function["return_loans"] = origins
            document["functions"].append(function)
            block = None
            continue
        if line == "end":
            if block is None or "term" not in block:
                _reject("function must end after a block terminator", line=number)
            function = block = None
            continue
        match = _BLOCK.fullmatch(line)
        if match is not None:
            if block is not None and "term" not in block:
                _reject("previous block has no terminator", line=number)
            blocks += 1
            if blocks > MAX_BLOCKS:
                _reject("block inventory exceeds budget", line=number, limit=True)
            block = {"id": match[1], "params": _parameters(match[2], number), "ops": []}
            function["blocks"].append(block)
            continue
        if block is None or "term" in block:
            _reject("expected block header or function end", line=number)
        if match := _RETURN.fullmatch(line):
            block["term"] = {"op": "ret", "values": _names(match[1], number)}
        elif match := _JUMP.fullmatch(line):
            block["term"] = {"op": "jump", "target": match[1], "args": _names(match[2], number)}
        elif match := _BRANCH.fullmatch(line):
            block["term"] = {"op": "branch", "cond": match[1],
                             "then": {"target": match[2], "args": _names(match[3], number)},
                             "else": {"target": match[4], "args": _names(match[5], number)}}
        elif match := _TRAP.fullmatch(line):
            block["term"] = {"op": "trap", "code": match[1]}
        elif match := _INSTRUCTION.fullmatch(line):
            operations += 1
            if operations > MAX_OPERATIONS:
                _reject("operation inventory exceeds budget", line=number, limit=True)
            block["ops"].append({"op": match[2], "args": _names(match[3], number),
                                 "out": [] if match[1].strip() == "_" else _parameters(match[1], number),
                                 "attrs": _attrs(match[4], number)})
        else:
            _reject("expected typed instruction or explicit terminator", line=number)
    if document is None:
        _reject("missing assembly header")
    if function is not None:
        _reject("unterminated function; explicit end required", line=len(lines))
    try:
        return verify_program(document)
    except HIAProgramRejected as exc:
        # Core errors are kept as Core errors. An absent location is honest:
        # assigning a guessed syntax line would misidentify cross-block errors.
        raise HIAAssemblyRejected(str(exc).removeprefix(exc.code + ": "), exc.code,
                                  phase="core_verification") from exc


def _render_parameters(parameters):
    return ",".join(p["name"] + ":" + p["type"] for p in parameters)


def render_assembly(document) -> str:
    """Canonical compact text whose exact primitive Core round trip is checked."""
    checked = verify_program(document)
    data = checked.as_dict()
    if checked.structured_bytes is not None or data["schema"] not in CORE_SCHEMAS:
        raise HIAAssemblyRejected("render requires explicit primitive v6/v7/v8 Core; use the existing adapter first",
                                  "E_HIA_ASSEMBLY_PROFILE", phase="representation")
    lines = [f'{WIRE_HEADER} {data["schema"]} {data["module"]}']
    if "exports" in data:
        lines.append("exports(" + ",".join(data["exports"]) + ")")
    for function in data["functions"]:
        lines.append(f'fn {function["name"]}({_render_parameters(function["params"])}) -> '
                     f'({",".join(function["returns"])}) effects({",".join(function["effects"])}) '
                     f'entry({function["entry"]})')
        if "return_loans" in function:
            lines[-1] += " return_loans(" + json.dumps(function["return_loans"], separators=(",", ":")) + ")"
        for block in function["blocks"]:
            lines.append(f'block {block["id"]}({_render_parameters(block["params"])})')
            for instruction in block["ops"]:
                outputs = _render_parameters(instruction["out"]) or "_"
                text = f'  {outputs} = {instruction["op"]}({",".join(instruction["args"])})'
                if instruction["attrs"]:
                    text += " " + json.dumps(instruction["attrs"], sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=False, allow_nan=False)
                lines.append(text)
            term = block["term"]
            if term["op"] == "ret":
                text = "ret(" + ",".join(term["values"]) + ")"
            elif term["op"] == "jump":
                text = f'jump {term["target"]}({",".join(term["args"])})'
            elif term["op"] == "branch":
                left, right = term["then"], term["else"]
                text = (f'branch {term["cond"]} {left["target"]}({",".join(left["args"])}) '
                        f'{right["target"]}({",".join(right["args"])})')
            else:
                text = "trap " + term["code"]
            lines.append("  " + text)
        lines.append("end")
    rendered = "\n".join(lines) + "\n"
    if assemble_program(rendered).canonical_bytes != checked.canonical_bytes:
        raise HIAAssemblyRejected("renderer changed canonical Core", "E_HIA_ASSEMBLY_ROUNDTRIP",
                                  phase="representation")
    return rendered


def diagnose_assembly(source: str | bytes) -> dict:
    """Stable Agent diagnostic; accepted syntax/Core grants no native authority."""
    result = {"schema": "hepta.hia.assembly-diagnostic.v1", "accepted": False,
              "deployment_authority": False, "safety_certificate": False,
              "native_artifact_created": False}
    try:
        raw, _ = _source(source)
        result.update(source_sha256=sha256(raw).hexdigest(), source_bytes=len(raw))
        checked = assemble_program(raw)
    except HIAProgramRejected as exc:
        result["diagnostic"] = {"code": exc.code, "message": str(exc),
                                "phase": getattr(exc, "phase", "core_verification"),
                                "line": getattr(exc, "line", None)}
        return result
    result.update(accepted=True, core_sha256=checked.sha256,
                  core_schema=checked.as_dict()["schema"], diagnostic=None)
    return result
