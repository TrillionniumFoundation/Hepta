"""Author exact Candidate refusal responses over pinned HIA child observations."""
import json
from pathlib import Path
import re

from hepta.hia_core_patch_native import ERROR_MESSAGES
from hepta.hia_json_preflight_native import SYNTAX_REASONS
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_agent_read_page import SOURCE as PAGE
from tools.generate_hia_json_decode import source_program as decoder
from tools.generate_hia_discovery_effect import source_program as discovery_policy
from tools.generate_hia_mcp_request import WIRE_HELPERS, comparison_table
from tools.generate_hia_worker_context_request import literal_match
from tools.generate_hia_worker_inspection_effect import function, literal

SOURCE = Path("examples/hia_bootstrap/worker_candidate_admission_diagnostic.hepta")
KEYS = ("accepted", "schema", "diagnostic", "ok", "status", "diagnostics", "code", "message", "phase", "line")
POLICY = r"""
def diagnose_candidate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 2 or length(s) > 16384 or length(o) < 32768 or length(w) < 262144:
        return INVALID
    if length(s) == 16:
        source = input_word(s, 0)
        status = input_word(s, 8)
        if source == INGRESS:
            return frame(o, explain_ingress(o, status))
        if source == PATCH:
            return frame(o, explain_patch(o, status))
    put(o, 48, 4096)
    put(o, 56, 32)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 2:
        return INVALID
    kind = 64 + get(w, 88) * 72
    diagnostic = 64 + get(w, kind + 16) * 72
    if get(w, diagnostic) != 6:
        return INVALID
    if json_mode(w, kind):
        return frame(o, json_refusal(o, w, diagnostic))
    if assembly_mode(w, kind):
        return frame(o, assembly_refusal(o, w, diagnostic))
    return INVALID

def json_refusal(o:mutbuf, w:mutbuf, report:u64) -> u64:
    if is_false(w, lookup(w, report, K_ok)) == False or error_status(w, lookup(w, report, K_status)) == False:
        return 0
    rows = lookup(w, report, K_diagnostics)
    if rows == NONE or get(w, rows) != 5 or get(w, rows + 32) != 1:
        return 0
    row = 64 + get(w, rows + 24) * 72
    if get(w, row) != 6 or driver(w, lookup(w, row, K_phase)) == False:
        return 0
    if driver_code(w, lookup(w, row, K_code)) == False:
        return 0
    message = lookup(w, row, K_message)
    if combined_json(w, message):
        return 0
    return render_message(o, w, message, 0, False)

def assembly_refusal(o:mutbuf, w:mutbuf, report:u64) -> u64:
    if is_false(w, lookup(w, report, K_accepted)) == False or assembly_schema(w, lookup(w, report, K_schema)) == False:
        return 0
    row = lookup(w, report, K_diagnostic)
    if row == NONE or get(w, row) != 6:
        return 0
    code = lookup(w, row, K_code)
    phase = lookup(w, row, K_phase)
    stated_line = lookup(w, row, K_line)
    message = lookup(w, row, K_message)
    if code == NONE or get(w, code) != 4 or stated_line == NONE:
        return 0
    if syntax(w, phase):
        if assembly_error(w, code) == False and assembly_limit(w, code) == False:
            return 0
        if get(w, stated_line) != 0 and get(w, stated_line) != 3:
            return 0
        return render_message(o, w, message, code, True)
    if core_verification(w, phase) and get(w, stated_line) == 0:
        return render_message(o, w, message, code, False)
    return 0

def is_false(w:mutbuf, node:u64) -> bool:
    return node != NONE and get(w, node) == 1

def render_message(o:mutbuf, w:mutbuf, node:u64, stated:u64, syntax_phase:bool) -> u64:
    if node == NONE or get(w, node) != 4 or get(w, node + 32) < 9:
        return 0
    start = get(w, node + 24)
    maximum = get(w, node + 32)
    width = code_width(w, start, maximum)
    if width == 0:
        return 0
    if stated != 0:
        if get(w, stated + 32) != width:
            return 0
        index = 0
        other = get(w, stated + 24)
        while index < width:
            if byte(w, start + index) != byte(w, other + index):
                return 0
            index = index + 1
    at = error_open(o, 16)
    index = 0
    while index < width:
        store(o, at + index, byte(w, start + index))
        index = index + 1
    at = message_open(o, at + width)
    # Preserve the public truncation in Unicode scalar count, not raw bytes.
    count = 0
    index = 0
    while index < maximum:
        if byte(w, start + index) & 192 != 128:
            if count == 4096:
                maximum = index
            else:
                count = count + 1
        index = index + 1
    at = emit_escaped(w, o, start, maximum, at)
    if syntax_phase:
        return syntax_close(o, at)
    return admission_close(o, at)

def code_width(w:mutbuf, start:u64, maximum:u64) -> u64:
    if match_word(w, start, 6) != PREFIX:
        return 0
    index = 6
    while index + 2 < maximum and index <= 128:
        unit = byte(w, start + index)
        if unit == 58 and byte(w, start + index + 1) == 32 and index > 6:
            return index
        if (unit < 65 or unit > 90) and (unit < 48 or unit > 57) and unit != 95:
            return 0
        index = index + 1
    return 0

def frame(o:mutbuf, end:u64) -> u64:
    if end < 18 or end > 7900:
        return INVALID
    state_put(o, 0, DIAGNOSTIC)
    state_put(o, 8, end - 16)
    return end
"""
TEXT = {
    "json_mode": "json", "assembly_mode": "assembly", "error_status": "error",
    "driver": "driver", "driver_code": "E_DRIVER",
    "combined_json": "E_HIA_FORMAT: invalid/deep UTF-8 JSON",
    "assembly_schema": "hepta.hia.assembly-diagnostic.v1",
    "assembly_error": "E_HIA_ASSEMBLY", "assembly_limit": "E_HIA_ASSEMBLY_LIMIT",
    "syntax": "syntax", "core_verification": "core_verification",
}
LITERALS = {
    "error_open": b'{"code":"',
    "message_open": b'","details_artifact":null,"message":"',
    "syntax_close": b'","phase":"syntax","retry_action":"correct_input"}',
    "admission_close": b'","phase":"admission","retry_action":"correct_input"}',
}


def rendered(code, message):
    return json.dumps({"code": code, "details_artifact": None, "message": message, "phase": "admission",
                       "retry_action": "correct_input"}, sort_keys=True, separators=(",", ":")).encode("ascii")


def source_program():
    constants = {key: int.from_bytes(value, "little") for key, value in {
        "INGRESS": b"HIACIR01", "PATCH": b"HIAPRF01", "DIAGNOSTIC": b"HIACDJ01", "PREFIX": b"E_HIA_",
    }.items()}
    constants.update(NONE=(1 << 64) - 1, INVALID=4294967293)
    constants.update({"K_" + key: index for index, key in enumerate(KEYS, 1)})
    lex = {1: "invalid JSON", 2: "JSON input exceeds byte limit",
           3: "JSON node/depth budget exceeded before decoding",
           4: "invalid JSON: HIA JSON preflight: duplicate decoded object key"}
    lex.update({32 + key: "invalid JSON: HIA JSON preflight: " + message
                for key, message in SYNTAX_REASONS.items() if key < 20})
    patch = {key: rendered("E_HIA_REJECTED", "E_HIA_EDIT: " + message)
             for key, message in ERROR_MESSAGES.items() if key != 0xfffffffd}
    patch[0xfffffff1] = rendered("E_HIA_PATCH_SCHEMA", "patch artifact differs from declared patch schema")
    static = []
    for name, cases in (("ingress", {key: rendered("E_HIA_REJECTED", "E_HIA_EDIT: " + message)
                                     for key, message in lex.items()}),
                        ("patch", patch)):
        dispatch = [f"def explain_{name}(o:mutbuf, code:u64) -> u64:"]
        for key, raw in cases.items():
            label = f"{name}_{key}"
            dispatch.extend((f"    if code == {key}:", f"        return {label}(o)"))
            static.append(literal(label, raw, fixed=16))
        dispatch.append("    return 0")
        static.append("\n".join(dispatch))
    policy = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda match: str(constants[match[0]]), POLICY)
    helper = """
def state_put(w:mutbuf, at:u64, value:u64) -> u64:
    put(w, at, value)
    return at + 8
"""
    return "\n".join((policy, helper, function(discovery_policy(), "input_word"),
        function(WIRE_HELPERS.replace("NONE", str(constants["NONE"])), "lookup"),
        function(WIRE_HELPERS, "match_word"), comparison_table("key_id", KEYS),
        *(function(PAGE, name) for name in ("short_escape", "hex_digit")),
        function(PAGE, "emit_escaped").replace("s:readbuf", "s:mutbuf"),
        *(literal_match(name, text) for name, text in TEXT.items()),
        *(literal(name, raw) for name, raw in LITERALS.items()), *static, decoder(wire_spans=True)))


if __name__ == "__main__":
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding="utf-8")
