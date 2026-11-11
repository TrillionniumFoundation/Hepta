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


def _legacy_whitespace(text, index):
    while index < len(text) and text[index] in " \t\n\r":
        index += 1
    return index


def _legacy_atom_kind(text, index):
    size = len(text)
    if index >= size:
        raise ValueError("HIA JSON preflight: missing JSON value")
    for keyword in ("true", "false", "null"):
        if text.startswith(keyword, index):
            return "value", index + len(keyword)
    if text[index] == '"':
        return "string", index
    if text[index] == "-":
        index += 1
    if index >= size or not text[index].isascii() or not text[index].isdigit():
        raise ValueError("HIA JSON preflight: expected JSON integer or literal")
    if text[index] == "0":
        index += 1
    else:
        while index < size and '0' <= text[index] <= '9':
            index += 1
    return "value", index


def _string_fail(reason):
    raise ValueError("HIA JSON preflight: " + reason)


def _legacy_string_token(text, index):
    size = len(text)
    if index >= size or text[index] != '"':
        _string_fail("expected JSON string")
    first = index
    index += 1
    while index < size:
        ch = text[index]
        index += 1
        if ch == '"':
            return text[first:index],index
        if ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF:
            _string_fail("unescaped control or isolated Unicode surrogate")
        if ch != "\\":
            continue
        if index >= size:
            _string_fail("unterminated JSON escape")
        esc = text[index]
        index += 1
        if esc in '"\\/bfnrt':
            continue
        if esc != "u" or index + 4 > size:
            _string_fail("invalid JSON escape")
        if any(c not in "0123456789abcdefABCDEF" for c in text[index:index + 4]):
            _string_fail("invalid Unicode escape")
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
                _string_fail("unpaired high Unicode surrogate")
            index += 6
        elif 0xDC00 <= code_unit <= 0xDFFF:
            _string_fail("unpaired low Unicode surrogate")
    _string_fail("unterminated JSON string")



def _legacy_key_decode(token):
    return json.loads(token)


def _legacy_key_insert(token, keyset):
    key=_legacy_key_decode(token)
    if key in keyset:
        raise ValueError('HIA JSON preflight: duplicate decoded object key')
    keyset.add(key)


def _legacy_grammar_preflight(text: str, *, max_nodes: int, max_depth: int) -> None:
    """Enforce the same root-at-depth-zero value budget as HIA _structure.

    Keys are not structural nodes; array elements and object *values* are.
    Duplicate object keys compare their decoded spellings, including \\u escapes.
    Does not emit any parsed values or trust a claimed schema or proof flag.
    """
    if (type(text) is not str or type(max_nodes) is not int or max_nodes < 1
            or type(max_depth) is not int or max_depth < 0):
        raise ValueError("invalid HIA JSON preflight input/budgets")
    from .hia_native_json_scan import legacy_enabled, scanner
    native = None if legacy_enabled() else scanner()
    size, index, nodes = len(text), 0, 0
    stack: list[dict] = []
    want_value, done = True, False

    def fail(reason: str) -> None:
        raise ValueError("HIA JSON preflight: " + reason)

    def whitespace() -> None:
        nonlocal index
        index = (_legacy_whitespace(text, index) if native is None
                 else native.whitespace(text, index))

    def string_token() -> str:
        nonlocal index
        token, index = (_legacy_string_token(text,index) if native is None
                        else native.string_token(text,index))
        return token

    def atom() -> None:
        nonlocal index
        kind, following = (_legacy_atom_kind(text, index) if native is None
                           else native.atom(text, index))
        if kind == "string":
            string_token()
        else:
            index = following


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
                    _legacy_key_insert(token,frame["keys"])
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


def preflight_hia_json(text: str, *, max_nodes: int, max_depth: int) -> None:
    if (type(text) is not str or type(max_nodes) is not int or max_nodes < 1
            or type(max_depth) is not int or max_depth < 0):
        raise ValueError("invalid HIA JSON preflight input/budgets")
    from .hia_native_json_scan import legacy_enabled,scanner
    if legacy_enabled():
        return _legacy_grammar_preflight(text,max_nodes=max_nodes,max_depth=max_depth)
    return scanner().preflight(text,max_nodes,max_depth)
