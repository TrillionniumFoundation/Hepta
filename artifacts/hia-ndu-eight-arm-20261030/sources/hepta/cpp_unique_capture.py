"""Bounded, complete streaming census of a real Clang C++ AST.

The JSON object grammar remains checked by the standard parser. Streaming only
separates the complete top-level objects; it never filters source text or skips
the remainder of a translation unit. A reader must exhaust the iterator before
using its receipt. These are process budgets, not a Clang/OS sandbox.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
import os
import re
import selectors
import subprocess
import tempfile
import time

from .clang_capture import _terminate
from .c_migrate import MigrationRejected

MAX_AST_BYTES = 384_000_000
MAX_AST_VALUES = 6_000_000
MAX_OBJECT_BYTES = 96_000_000
MAX_AST_SECONDS = 120
_TOKENS = re.compile(rb'["\\{}\[\]]')


def _reject(reason):
    raise MigrationRejected("E_CPP_UNIQUE_CAPTURE", reason)


def _fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("Duplicate Clang JSON field: " + key)
        result[key] = value
    return result


class _Objects:
    """Fail-closed framing of Clang's complete TranslationUnitDecl JSON."""
    def __init__(self):
        self.header = bytearray()
        self.parts = []
        self.object_bytes = 0
        self.mode = "header"
        self.need = "value_or_end"
        self.depth = 0
        self.string = False
        self.escaped = False
        self.tail = bytearray()
        self.values = 0
        self.objects = 0

    def _node(self):
        data = b"".join(self.parts)
        self.parts = []
        self.object_bytes = 0
        try:
            def bad(value):
                raise ValueError("Nonfinite JSON constant " + value)
            node = json.loads(data, parse_constant=bad, object_pairs_hook=_fields)
        except (ValueError, RecursionError, UnicodeError) as error:
            _reject("Malformed Clang object: " + str(error))
        if not isinstance(node, dict) or not isinstance(node.get("kind"), str):
            _reject("Clang top-level value is not an AST object")
        pending = [(node, 2)]
        while pending:
            value, depth = pending.pop()
            self.values += 1
            if self.values > MAX_AST_VALUES or depth > 128:
                _reject("Complete AST value/depth budget exceeded")
            if isinstance(value, dict):
                pending.extend((part, depth + 1) for part in value.values())
            elif isinstance(value, list):
                pending.extend((part, depth + 1) for part in value)
            elif (isinstance(value, float) and not math.isfinite(value)
                  or value is not None and not isinstance(value, (str, int, bool, float))):
                _reject("Unexpected AST scalar")
        self.objects += 1
        return node

    def feed(self, raw):
        if self.mode == "header":
            self.header.extend(raw)
            match = re.search(rb'"inner"\s*:\s*\[', self.header)
            if match is None:
                if len(self.header) > 65536:
                    _reject("Missing bounded translation-unit header")
                return
            if match.end() > 65536:
                _reject("Translation-unit header exceeds budget")
            try:
                root = json.loads(bytes(self.header[:match.end()]) + b"]}", object_pairs_hook=_fields,
                                  parse_constant=lambda value: _reject("Nonfinite header constant " + value))
            except (ValueError, UnicodeError, RecursionError) as error:
                _reject("Malformed translation-unit header: " + str(error))
            if (not isinstance(root, dict) or root.get("kind") != "TranslationUnitDecl"
                    or not {"id", "kind", "inner"} <= set(root)
                    or set(root) - {"id", "kind", "loc", "range", "inner"}):
                _reject("Unexpected translation-unit header fields")
            pending = [(root, 0)]
            while pending:
                value, depth = pending.pop()
                self.values += 1
                if depth > 128 or isinstance(value, float) and not math.isfinite(value):
                    _reject("Invalid translation-unit header value/depth")
                if isinstance(value, dict):
                    pending.extend((child, depth + 1) for child in value.values())
                elif isinstance(value, list):
                    pending.extend((child, depth + 1) for child in value)
            raw = bytes(self.header[match.end():])
            self.header.clear()
            self.mode = "between"
        cursor = 0
        while cursor < len(raw):
            if self.mode == "tail":
                self.tail.extend(raw[cursor:])
                if len(self.tail) > 65536:
                    _reject("Trailing AST content exceeds budget")
                return
            if self.mode == "between":
                match = re.search(rb"\S", raw[cursor:])
                if match is None:
                    return
                cursor += match.start()
                byte = raw[cursor]
                if byte == ord("]") and self.need in {"value_or_end", "comma_or_end"}:
                    self.mode = "tail"; cursor += 1
                    continue
                if byte == ord(",") and self.need == "comma_or_end":
                    self.need = "value"; cursor += 1
                    continue
                if byte != ord("{") or self.need not in {"value", "value_or_end"}:
                    _reject("Malformed complete AST object sequence")
                self.mode = "object"
                self.depth = 0
                self.string = False
                self.escaped = False
            start = cursor
            finished = False
            for token in _TOKENS.finditer(raw, cursor):
                position, byte = token.start(), token[0][0]
                # An escaped ordinary character consumes the escape even if
                # the next structural token is later in the chunk.
                if self.escaped and position > cursor:
                    self.escaped = False
                cursor = position + 1
                if self.string:
                    if self.escaped:
                        self.escaped = False
                    elif byte == ord("\\"):
                        self.escaped = True
                    elif byte == ord('"'):
                        self.string = False
                    continue
                if byte == ord('"'):
                    self.string = True
                elif byte in {ord("{"), ord("[")}:
                    self.depth += 1
                elif byte in {ord("}"), ord("]")}:
                    self.depth -= 1
                    if self.depth < 0:
                        _reject("Unbalanced AST object framing")
                    if self.depth == 0:
                        self.parts.append(raw[start:cursor])
                        self.object_bytes += cursor - start
                        if self.object_bytes > MAX_OBJECT_BYTES:
                            _reject("One AST subtree exceeds the memory budget")
                        yield self._node()
                        self.mode = "between"
                        self.need = "comma_or_end"
                        finished = True
                        break
            if not finished:
                if self.escaped and cursor < len(raw):
                    self.escaped = False
                self.parts.append(raw[start:])
                self.object_bytes += len(raw) - start
                if self.object_bytes > MAX_OBJECT_BYTES:
                    _reject("One AST subtree exceeds the memory budget")
                return

    def close(self):
        if self.mode != "tail" or re.fullmatch(rb"\s*}\s*", self.tail) is None:
            _reject("Truncated or trailing complete AST")


def stream_ast(arguments, *, cwd, source, receipt):
    """Yield every top-level AST node; populate receipt only after full closure."""
    if receipt:
        _reject("Capture receipt must start empty")
    digest, total = sha256(), 0
    framed = _Objects()
    start = time.perf_counter_ns()
    with tempfile.TemporaryFile() as input_file, tempfile.TemporaryFile() as errors:
        if source is not None:
            encoded = source.encode()
            if len(encoded) > 1_000_000:
                _reject("Reference source exceeds budget")
            input_file.write(encoded)
        input_file.seek(0)
        process = subprocess.Popen(arguments, cwd=cwd, stdin=input_file,
                                   stdout=subprocess.PIPE, stderr=errors,
                                   start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                complete = False
                while not complete:
                    if (time.perf_counter_ns() - start) / 1e9 > MAX_AST_SECONDS:
                        _reject("Complete AST capture timeout")
                    if os.fstat(errors.fileno()).st_size > 1_000_000:
                        _reject("Clang error output exceeds budget")
                    for _, _ in selector.select(0.1):
                        raw = os.read(process.stdout.fileno(), 65536)
                        if not raw:
                            complete = True
                            break
                        total += len(raw)
                        if total > MAX_AST_BYTES:
                            _reject("Complete AST byte budget exceeded")
                        digest.update(raw)
                        yield from framed.feed(raw)
            code = process.wait(timeout=5)
            errors.seek(0)
            error_text = errors.read(1_000_001)
            if len(error_text) > 1_000_000:
                _reject("Clang error output exceeds budget")
            if code:
                _reject("Clang returned " + str(code) + ": " + error_text.decode(errors="replace")[-6000:])
            framed.close()
            receipt.update(sha256=digest.hexdigest(), bytes=total,
                           top_level_objects=framed.objects, json_values=framed.values,
                           byte_limit=MAX_AST_BYTES, value_limit=MAX_AST_VALUES,
                           largest_subtree_limit=MAX_OBJECT_BYTES,
                           timeout_seconds=MAX_AST_SECONDS,
                           capture_and_census_wall_ns=time.perf_counter_ns() - start,
                           complete_stream=True, raw_ast_retained=False,
                           stderr_sha256=sha256(error_text).hexdigest())
        finally:
            process.stdout.close()
            # The parent may have exited while a descendant retains the pipe.
            # Match the existing bounded capture's whole-group cleanup.
            _terminate(process)
