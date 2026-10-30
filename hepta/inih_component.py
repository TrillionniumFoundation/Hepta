"""Source-pinned, partial INIReader implementation migration and callback contract.

This is a closed extractor for two *real* upstream revisions, not a general C++
frontend. Boolean recognition, error dispatch, and callback branch decisions
are lowered to checked Hepta. STL storage, case folding, parser, and rendering
remain explicit C/C++ boundaries. The generated adapter additionally protects
synchronous callback lifetimes and cleans the C parser before rethrowing a C++
callback exception. That last behavior is an explicit resource repair, not an
equivalence claim about the original leak.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha1, sha256
import json
from pathlib import Path
import re

PROFILE = "inih-two-pinned-revisions-synchronous-callback-partial-v1"
LATEST = "2d5ec7b59abbb8e1797e48060965001aaac6996a"
PREVIOUS = "de720a6f4066587618edfba3960ea9ed4132c665"
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/inih_component"
PIN_SHA256 = "c14abee683d2e6a3542b97a860f9c4f1d9274f71cbe3d37c96aedbdc3216010d"
MEMBERS = Counter({"INIReader": 2, "ParseError": 1, "ParseErrorMessage": 1,
    "Get": 1, "GetString": 1, "GetInteger": 1, "GetInteger64": 1,
    "GetUnsigned": 1, "GetUnsigned64": 1, "GetReal": 1, "GetBoolean": 1,
    "Sections": 1, "Keys": 1, "HasSection": 1, "HasValue": 1,
    "MakeKey": 1, "ValueHandler": 1})


class InihMigrationRejected(ValueError):
    pass


def _reject(message):
    raise InihMigrationRejected(message)


def _digest(data):
    return sha256(data).hexdigest()


def _capture_sources(version: str, *, fixture_root: Path = FIXTURES) -> tuple[dict, dict]:
    """Bind all component inputs, including the retained foreign implementation."""
    if version not in {LATEST, PREVIOUS}:
        _reject("Only the two explicitly captured upstream revisions are admitted")
    pin_bytes = (fixture_root / "UPSTREAM.json").read_bytes()
    if _digest(pin_bytes) != PIN_SHA256:
        _reject("The checked upstream source pin changed")
    pin = json.loads(pin_bytes)
    if pin.get("repository") != "https://github.com/benhoyt/inih":
        _reject("Unexpected upstream identity")
    records = [v for v in pin["versions"] if v["commit"] == version]
    if len(records) != 1:
        _reject("Missing or ambiguous source pin")
    expected = {"LICENSE.txt", "cpp/INIReader.cpp", "cpp/INIReader.h", "ini.c", "ini.h"}
    if {r["path"] for r in records[0]["files"]} != expected:
        _reject("Component source inventory is incomplete")
    result, contents = [], {}
    for entry in records[0]["files"]:
        path = fixture_root / version / entry["path"]
        if path.is_symlink() or not path.is_file():
            _reject("Source must be an ordinary captured file")
        data = path.read_bytes()
        oid = sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if len(data) != entry["bytes"] or oid != entry["git_blob_sha1"]:
            _reject("Upstream source identity mismatch: " + entry["path"])
        contents[entry["path"]] = data
        result.append({**entry, "sha256": _digest(data),
            "url": f"https://github.com/benhoyt/inih/blob/{version}/{entry['path']}"})
    return ({"repository": pin["repository"], "commit": version, "files": result,
            "whole_upstream_repository_captured": False}, contents)


def verify_sources(version: str, *, fixture_root: Path = FIXTURES) -> dict:
    return _capture_sources(version, fixture_root=fixture_root)[0]


def _mask_comments_and_literals(text: str, *, literals: bool = False) -> str:
    """Mask comments (and optionally literals), preserving offsets/newlines."""
    result = list(text)
    index = 0
    while index < len(text):
        start = index
        if text.startswith("//", index):
            index = text.find("\n", index)
            if index < 0:
                index = len(text)
            mask = True
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                _reject("Unterminated source comment")
            index, mask = end + 2, True
        elif text[index] in {'"', "'"}:
            quote = text[index]
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            else:
                _reject("Unterminated source literal")
            mask = literals
        else:
            index += 1
            continue
        if mask:
            for offset in range(start, index):
                if result[offset] != "\n":
                    result[offset] = " "
    return "".join(result)


def _definitions(source: str) -> list[dict]:
    masked = _mask_comments_and_literals(source, literals=True)
    pattern = re.compile(r"(?m)^[^\n;{}]*\bINIReader::([A-Za-z_]\w*)\s*\([^{};]*?\)(?:\s+const)?\s*\{")
    rows = []
    end_previous = 0
    for match in pattern.finditer(masked):
        if match.start() < end_previous:
            continue
        open_brace = match.end() - 1
        depth, end = 1, open_brace + 1
        while end < len(masked) and depth:
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        if depth:
            _reject("Unbalanced member definition")
        rows.append({"name": match[1], "start": match.start(), "end": end,
            "body_start": open_brace + 1, "body_end": end - 1,
            "signature": source[match.start():open_brace].strip(),
            "body": source[open_brace + 1:end - 1]})
        end_previous = end
    if Counter(r["name"] for r in rows) != MEMBERS:
        _reject("Every active INIReader member definition must have a disposition")
    remainder = list(masked)
    for row in rows:
        remainder[row["start"]:row["end"]] = " " * (row["end"] - row["start"])
    rest = re.sub(r"(?m)^\s*#include[^\n]*", "", "".join(remainder))
    rest = rest.replace("using std::string;", "")
    if rest.strip():
        _reject("Unaccounted active top-level implementation text")
    return rows


def _boolean_literals(body: str) -> tuple[list[str], list[str], str]:
    clean = _mask_comments_and_literals(body)
    marker = clean.find("if (valstr ==")
    if marker < 0:
        _reject("Missing source Boolean predicate")
    suffix = clean[marker:]
    match = re.fullmatch(r'if\s*\((.*?)\)\s*return\s+true\s*;\s*else\s+if\s*\((.*?)\)\s*return\s+false\s*;\s*else\s*return\s+default_value\s*;\s*', suffix, re.S)
    if match is None:
        _reject("Unsupported Boolean decision grammar")
    groups = []
    for expression in match.groups():
        pieces = expression.split("||")
        words = []
        for piece in pieces:
            word = re.fullmatch(r'\s*valstr\s*==\s*"([a-z0-9]+)"\s*', piece)
            if word is None:
                _reject("Boolean recognition requires exact ASCII literals")
            words.append(word[1])
        groups.append(words)
    if len(set(groups[0] + groups[1])) != sum(map(len, groups)):
        _reject("Ambiguous Boolean literal classes")
    # This exact source-bound prefix retains upstream locale-sensitive folding.
    prefix = body[:marker]
    if "std::transform" not in prefix or "::tolower(ch)" not in prefix:
        _reject("Missing retained upstream case-folding boundary")
    return groups[0], groups[1], prefix


def _error_cases(body: str) -> list[tuple[int, str]]:
    clean = _mask_comments_and_literals(body)
    matches = list(re.finditer(r'case\s+(-?\d+)\s*:\s*return\s+"([^"\\]*)"\s*;', clean))
    cases = [(int(m[1]), m[2]) for m in matches]
    expected_codes = {-2, -1, 0} | ({-3} if "case -3:" in clean else set())
    if {x[0] for x in cases} != expected_codes or len(cases) != len(expected_codes):
        _reject("Unsupported error classification")
    expected = ('if (_error > 0) { return "parse error on line " + std::to_string(_error) + "; missing \']\' or \'=\'?"; }'
                ' switch (_error) { CASES } return "unknown error " + std::to_string(_error);')
    remainder = clean
    for match in reversed(matches):
        remainder = remainder[:match.start()] + remainder[match.end():]
    normalized = re.sub(r"\s+", "", remainder)
    if normalized != re.sub(r"\s+", "", expected.replace("CASES", "")):
        _reject("Error method contains unmodeled statements")
    return cases


def _callback_shape(body: str):
    actual = re.sub(r"\s+", "", _mask_comments_and_literals(body))
    expected = '''if (!name) return 1;
        INIReader* reader = static_cast<INIReader*>(user);
        string key = MakeKey(section, name);
        if (reader->_values[key].size() > 0) reader->_values[key] += "\\n";
        reader->_values[key] += value ? value : "";
        return 1;'''
    if actual != re.sub(r"\s+", "", expected):
        _reject("Callback has statements outside the closed branch/storage contract")


def _function(name, parameters, returns, lines):
    effects = "panic" if name == "hia_ini_error_kind" else ""
    return f'export "C" fn {name}({parameters}) -> {returns} effects {{{effects}}} {{\n' + "\n".join("    " + line for line in lines) + "\n}\n"


def _hepta(true_words, false_words, cases):
    states = {"": 0}
    transitions = {}
    for word in true_words + false_words:
        for length in range(1, len(word) + 1):
            prefix = word[:length]
            if prefix not in states:
                states[prefix] = len(states)
            transitions[states[prefix[:-1]], ord(prefix[-1])] = states[prefix]
    step = [f"if state == {s} && byte == {byte} {{ return {target}; }}"
            for (s, byte), target in sorted(transitions.items())]
    step += ["return 4294967295;"]
    finish = [f"if state == {states[word]} {{ return {1 if word in true_words else 0}; }}"
              for word in true_words + false_words]
    finish += ["if fallback != 0 { return 1; }", "return 0;"]
    errors = ["if error > 0 { return 1; }"]
    errors += [f"if error == {code} {{ return {i + 2}; }}" for i, (code, _) in enumerate(cases)]
    errors += ["return 255;"]
    callback = ["if has_name == 0 { return 0; }",
        "if nonempty != 0 {", "    if has_value != 0 { return 4; }", "    return 3;", "}",
        "if has_value != 0 { return 2; }", "return 1;"]
    lease = ["if phase == 0 && event == 0 { return 1; }",
        "if phase == 1 && event == 1 { return 2; }",
        "if phase == 2 && event == 2 { return 1; }",
        "if phase == 1 && event == 3 { return 3; }", "return 255;"]
    text = "module inih_component;\n\n// Extracted decisions plus an explicitly authored callback lease contract.\n\n"
    text += _function("hia_ini_bool_step", "state: u32, byte: u32", "u32", step) + "\n"
    text += _function("hia_ini_bool_finish", "state: u32, fallback: u32", "u32", finish) + "\n"
    text += _function("hia_ini_error_kind", "error: i32", "u32", errors) + "\n"
    text += _function("hia_ini_callback_action", "has_name: u32, has_value: u32, nonempty: u32", "u32", callback) + "\n"
    text += _function("hia_ini_lease_step", "phase: u32, event: u32", "u32", lease)
    return text, {"states": states, "transitions": [{"from": s, "byte": b, "to": t}
        for (s, b), t in sorted(transitions.items())], "dead_state": 4294967295,
        "true_literals": true_words, "false_literals": false_words}


def generate(version: str, *, fixture_root: Path = FIXTURES) -> dict:
    source_identity, source_bytes = _capture_sources(version, fixture_root=fixture_root)
    source = source_bytes["cpp/INIReader.cpp"].decode("utf-8")
    header = source_bytes["cpp/INIReader.h"].decode("utf-8")
    rows = _definitions(source)
    # Account for every public/protected declared callable as well as definitions.
    clean_header = _mask_comments_and_literals(header)
    declared = Counter(re.findall(r"\b(INIReader|ParseError|ParseErrorMessage|Get|GetString|GetInteger|GetInteger64|GetUnsigned|GetUnsigned64|GetReal|GetBoolean|Sections|Keys|HasSection|HasValue|MakeKey|ValueHandler)\s*\([^;{}]*\)\s*(?:const\s*)?;", clean_header))
    if declared != MEMBERS:
        _reject("Header declarations do not match the complete member inventory")
    by_name = {r["name"]: r for r in rows if r["name"] != "INIReader"}
    true_words, false_words, prefix = _boolean_literals(by_name["GetBoolean"]["body"])
    cases = _error_cases(by_name["ParseErrorMessage"]["body"])
    _callback_shape(by_name["ValueHandler"]["body"])
    hepta, automaton = _hepta(true_words, false_words, cases)
    replacements = {}
    replacements["GetBoolean"] = prefix + '''    uint32_t state = 0;
    for (unsigned char ch : valstr) {
        state = hia_ini_bool_step(state, static_cast<uint32_t>(ch));
    }
    return hia_ini_bool_finish(state, default_value ? 1U : 0U) != 0;
'''
    rendered_cases = "\n".join(f"    case {index + 2}: return {json.dumps(message)};"
                               for index, (_, message) in enumerate(cases))
    replacements["ParseErrorMessage"] = '''
    switch (hia_ini_error_kind(_error)) {
    case 1: return "parse error on line " + std::to_string(_error) + "; missing ']' or '='?";
''' + rendered_cases + '''
    default: return "unknown error " + std::to_string(_error);
    }
'''
    replacements["ValueHandler"] = '''
    hepta_ini::CallbackInvocation callback(user);
    if (!callback) { return 0; }
    try {
        if (hia_ini_callback_action(name ? 1U : 0U, 0, 0) == 0) { return 1; }
        INIReader* reader = static_cast<INIReader*>(callback.owner());
        string key = MakeKey(section, name);
        uint32_t action = hia_ini_callback_action(1, value ? 1U : 0U,
                                                 reader->_values[key].size() > 0 ? 1U : 0U);
        if (action == 3 || action == 4) { reader->_values[key] += "\\n"; }
        reader->_values[key] += (action == 2 || action == 4) ? value : "";
        return 1;
    } catch (...) {
        callback.capture_failure();
        return 0;
    }
'''
    inventory = []
    transformed = source
    for row in reversed(rows):
        name, body = row["name"], row["body"]
        disposition = "retained_foreign_cpp_implementation"
        if name in replacements:
            body = replacements[name]
            disposition = "hepta_decisions_with_explicit_foreign_data_operations"
        elif name == "INIReader":
            # Do not absorb a new caller into this closed contract silently.
            normalized = re.sub(r"\s+", "", body)
            filename = "_error=ini_parse(filename.c_str(),ValueHandler,this);"
            buffer = "_error=ini_parse_string_length(buffer,buffer_size,ValueHandler,this);"
            if normalized not in {filename, buffer}:
                _reject("Constructor has unsupported work around the parser call")
            body = "\n    hepta_ini::ScopedBorrow borrow(this);\n" + body.replace("ValueHandler, this", "ValueHandler, borrow.user()")
            body += "    borrow.rethrow_pending();\n"
            disposition = "retained_parser_call_with_authored_callback_lease_adapter"
        transformed = transformed[:row["body_start"]] + body + transformed[row["body_end"]:]
        inventory.append({"name": name, "signature": row["signature"],
            "source_line": source.count("\n", 0, row["start"]) + 1,
            "body_sha256": _digest(row["body"].encode()), "disposition": disposition})
    transformed = transformed.replace('#include "INIReader.h"', '#include "INIReader.h"\n#include "inih_hepta_callback.hpp"', 1)
    report = {"schema": "hepta.cpp.inih.partial-migration.v1", "profile": PROFILE,
        "upstream": source_identity, "member_definitions": list(reversed(inventory)),
        "member_definition_count": len(inventory), "header_callable_inventory_complete": True,
        "retained_state": ["INIReader::_error", "INIReader::_values (std::map<std::string,std::string>)"],
        "hepta_automaton": automaton, "error_cases": [{"code": c, "text": s} for c, s in cases],
        "generated_hepta_sha256": _digest(hepta.encode()),
        "generated_cpp_sha256": _digest(transformed.encode()),
        "actual_cpp_body_decision_fragments": ["GetBoolean", "ParseErrorMessage", "ValueHandler"],
        "authored_safety_increment": "same-thread scoped non-reentrant callback lease; catch callback exception, let C parser free its buffer, then rethrow",
        "exception_cleanup_is_explicit_behavioral_repair": True,
        "required_parser_options": {"INI_HANDLER_LINENO": 0, "INI_STOP_ON_FIRST_ERROR": 1},
        "whole_component_translated": False, "general_cpp_translator": False,
        "general_cpp_memory_safety_proved": False, "compiler_refinement_proved": False,
        "unmeasured": ["human migration hours", "performance superiority", "arbitrary asynchronous cancellation"],
        "boundary": ["upstream C parser", "STL map/string allocation and mutation", "locale-sensitive tolower",
            "string formatting", "native callback registry implementation", "upstream borrowed char pointer validity"],
        "qualified_domain": "bounded synchronous same-thread callbacks; at most 32 simultaneously active parser leases per thread; LP64 native host"}
    return {"hepta": hepta, "cpp": transformed, "report": report, "captured_sources": source_bytes}


def materialize(version: str, output: Path, *, fixture_root: Path = FIXTURES) -> dict:
    """Stage fresh source output; upstream bytes and generated bindings are retained."""
    generated = generate(version, fixture_root=fixture_root)
    if output.exists() or output.is_symlink():
        _reject("Output must be a fresh directory")
    output.mkdir(parents=True)
    for relative in ("ini.c", "ini.h", "LICENSE.txt", "cpp/INIReader.h"):
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(generated["captured_sources"][relative])
    (output / "cpp/INIReader.cpp").write_text(generated["cpp"])
    (output / "inih.hepta").write_text(generated["hepta"])
    (output / "MIGRATION.json").write_text(json.dumps(generated["report"], indent=2) + "\n")
    return generated["report"]
