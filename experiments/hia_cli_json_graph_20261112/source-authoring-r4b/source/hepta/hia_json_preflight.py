"""Bounded JSON syntax preflight for the existing HIA decoder.

This small scanner never materializes a JSON *value* tree. It rejects over-budget
node counts, excessive depth, and duplicate object keys BEFORE json.loads
allocates the value graph. The stdlib decoder remains the only producer of
actual JSON values and the unchanged HIA checker remains the semantic authority.
The scanner accepts only the existing HIA integer/string/bool/null subset;
fractional and nonfinite numbers were already rejected by HIA's _structure.
"""
from __future__ import annotations

import json
import os
import re


# Skip only spans which the reference grammar treats identically. Escapes,
# quote boundaries, controls and surrogate code points still reach the same
# ordered checks below; no parsed value or previous admission is reused.
_STRING_BOUNDARY = re.compile(r'["\\\x00-\x1f\ud800-\udfff]')
_WHITESPACE_SPAN = re.compile(r'[ \t\n\r]+')
_DIGIT_SPAN = re.compile(r'[0-9]+')


def preflight_hia_json(text: str, *, max_nodes: int, max_depth: int) -> None:
    """Use an explicitly installed HIA candidate inside its declared profile.

    Without the operator-selected manifest, retain the independent Python path.
    Inputs outside the native profile retain the old API; a broken selected
    artifact fails closed, never silently falls back after a native error.
    No JSON payload can select executable code or change the manifest.
    """
    if (type(text) is not str or type(max_nodes) is not int or max_nodes < 1
            or type(max_depth) is not int or max_depth < 0):
        raise ValueError("invalid HIA JSON preflight input/budgets")
    manifest = os.environ.get('HEPTA_HIA_JSON_PREFLIGHT_MANIFEST')
    if manifest and max_nodes <= 1048576 and max_depth <= 128:
        try:
            wire = text.encode('utf-8')
        except UnicodeEncodeError:
            # Python str may contain isolated surrogates. Those are not UTF-8
            # wire inputs; keep the reference's grammar/budget error ordering.
            pass
        else:
            if len(wire) <= 8388608:
                from .hia_json_preflight_native import installed_preflight
                installed_preflight(manifest).admit(wire, max_nodes=max_nodes, max_depth=max_depth)
                return
    _preflight_hia_json_reference(text, max_nodes=max_nodes, max_depth=max_depth)


def _preflight_hia_json_reference(text: str, *, max_nodes: int, max_depth: int) -> None:
    """Enforce the same root-at-depth-zero value budget as HIA _structure.

    Keys are not structural nodes; array elements and object *values* are.
    Duplicate object keys compare their decoded spellings, including \\u escapes.
    Does not emit any parsed values or trust a claimed schema or proof flag.
    """
    if (type(text) is not str or type(max_nodes) is not int or max_nodes < 1
            or type(max_depth) is not int or max_depth < 0):
        raise ValueError("invalid HIA JSON preflight input/budgets")
    size, index, nodes = len(text), 0, 0
    stack: list[dict] = []
    want_value, done = True, False

    def fail(reason: str) -> None:
        raise ValueError("HIA JSON preflight: " + reason)

    def whitespace() -> None:
        nonlocal index
        if index < size and text[index] in " \t\n\r":
            index = _WHITESPACE_SPAN.match(text, index).end()

    def string_token() -> str:
        nonlocal index
        if index >= size or text[index] != '"':
            fail("expected JSON string")
        first = index
        index += 1
        while index < size:
            boundary = _STRING_BOUNDARY.search(text, index)
            if boundary is None:
                # All remaining characters were ordinary string contents;
                # the original scanner would reach the same missing quote.
                index = size
                break
            index = boundary.start()
            ch = text[index]
            index += 1
            if ch == '"':
                return text[first:index]
            if ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF:
                fail("unescaped control or isolated Unicode surrogate")
            if ch != "\\":
                continue
            if index >= size:
                fail("unterminated JSON escape")
            esc = text[index]
            index += 1
            if esc in '"\\/bfnrt':
                continue
            if esc != "u" or index + 4 > size:
                fail("invalid JSON escape")
            if any(c not in "0123456789abcdefABCDEF" for c in text[index:index + 4]):
                fail("invalid Unicode escape")
            code_unit = int(text[index:index + 4], 16)
            index += 4
            # HIA's UTF-8 canonical wire format cannot contain isolated
            # UTF-16 surrogate code units. Reject them before json.loads
            # materializes Agent values. A high unit must be immediately
            # followed by the exact escaped low unit in the same token.
            if 0xD800 <= code_unit <= 0xDBFF:
                if (index + 6 > size or text[index:index + 2] != "\\u"
                        or any(c not in "0123456789abcdefABCDEF"
                               for c in text[index + 2:index + 6])
                        or not 0xDC00 <= int(text[index + 2:index + 6], 16) <= 0xDFFF):
                    fail("unpaired high Unicode surrogate")
                index += 6
            elif 0xDC00 <= code_unit <= 0xDFFF:
                fail("unpaired low Unicode surrogate")
        fail("unterminated JSON string")

    def atom() -> None:
        nonlocal index
        if index >= size:
            fail("missing JSON value")
        for keyword in ("true", "false", "null"):
            if text.startswith(keyword, index):
                index += len(keyword)
                return
        if text[index] == '"':
            string_token()
            return
        if text[index] == "-":
            index += 1
        if index >= size or not text[index].isascii() or not text[index].isdigit():
            fail("expected JSON integer or literal")
        if text[index] == "0":
            index += 1
        else:
            index = _DIGIT_SPAN.match(text, index).end()
        # We intentionally decline fractions/exponents: HIA never admits a
        # floating-point JSON node, and stdlib JSON decoding still follows.

    def complete_value() -> None:
        nonlocal done
        if not stack:
            done = True
        elif stack[-1]["state"] != "waiting":
            fail("unexpected value completion")
        else:
            stack[-1]["state"] = "after"

    while True:
        whitespace()
        if done:
            if index != size:
                fail("extra JSON data")
            return
        if want_value:
            if index >= size:
                fail("missing JSON value")
            nodes += 1
            if nodes > max_nodes or len(stack) > max_depth:
                raise OverflowError("HIA JSON exceeds node/depth budget before decoding")
            if text[index] == "[":
                index += 1
                stack.append({"kind": "array", "state": "first"})
            elif text[index] == "{":
                index += 1
                stack.append({"kind": "object", "state": "first", "keys": set()})
            else:
                atom()
                complete_value()
            want_value = False
            continue
        if not stack:
            fail("incomplete JSON value")
        frame = stack[-1]
        state, kind = frame["state"], frame["kind"]
        ch = text[index] if index < size else None
        if kind == "array":
            if state in {"first", "element"}:
                if state == "first" and ch == "]":
                    index += 1
                    stack.pop()
                    complete_value()
                else:
                    frame["state"] = "waiting"
                    want_value = True
            elif state == "after":
                if ch == ",":
                    index += 1
                    frame["state"] = "element"
                elif ch == "]":
                    index += 1
                    stack.pop()
                    complete_value()
                else:
                    fail("expected array separator/end")
            else:
                fail("invalid array preflight state")
        else:
            if state in {"first", "key"}:
                if state == "first" and ch == "}":
                    index += 1
                    stack.pop()
                    complete_value()
                elif ch == '"':
                    token = string_token()
                    key = json.loads(token)
                    if key in frame["keys"]:
                        fail("duplicate decoded object key")
                    frame["keys"].add(key)
                    frame["state"] = "colon"
                else:
                    fail("expected object field name")
            elif state == "colon":
                if ch != ":":
                    fail("expected object colon")
                index += 1
                frame["state"] = "value"
            elif state == "value":
                frame["state"] = "waiting"
                want_value = True
            elif state == "after":
                if ch == ",":
                    index += 1
                    frame["state"] = "key"
                elif ch == "}":
                    index += 1
                    stack.pop()
                    complete_value()
                else:
                    fail("expected object separator/end")
            else:
                fail("invalid object preflight state")
