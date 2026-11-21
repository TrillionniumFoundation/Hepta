"""Author the native Candidate continuation for retained inputs and outputs."""
import json
import re
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_discovery_effect import source_program as discovery_policy
from tools.generate_hia_worker_artifact_authority import source_program as authority_policy
from tools.generate_hia_worker_inspection_effect import (
    ERRORS as INSPECTION_ERRORS, POLICY as INSPECTION_POLICY, function, literal,
)

SOURCE = Path("examples/hia_bootstrap/worker_candidate_effect.hepta")

POLICY = r'''
# From the admitted request: authenticate Context; consume an attempt;
# resolve source or ordered base and patch; admit/transform; publish Core
# and diagnostics; emit one terminal outcome with the exact accounting ID.
def candidate_effect(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 40 or length(w) != 32768 or length(o) < 2048:
        return INVALID
    body = input_word(s, 32)
    if input_word(s, 0) != EVENT or input_word(s, 16) != state_word(w, 8) + 1 or body != length(s) - 40:
        return INVALID
    event = input_word(s, 8)
    status = input_word(s, 24)
    phase = state_word(w, 0)
    if phase == 0:
        if event != 1 or status != 0:
            return INVALID
        return begin(s, o, w, body)
    if event != phase:
        return INVALID
    if event == 2:
        return after_context(o, w, status, body)
    if event == 3:
        return after_attempt(o, w, status, body)
    if event == 4 or event == 5:
        return after_input(o, w, event, status, body)
    if event == 6:
        return after_transform(s, o, w, status, body)
    if event == 7:
        return after_core(s, o, w, status, body)
    if event == 8:
        if status != 9 or receipt(s, w, 112, body) == False:
            return INVALID
        return result(s, o, w)
    return INVALID

def begin(s:readbuf, o:mutbuf, w:mutbuf, body:u64) -> u64:
    if body < 42 or body > 1536 or input_word(s, 40) != REQUEST:
        return INVALID
    mode = input_word(s, 48)
    if mode < 1 or mode > 4:
        return INVALID
    context = input_word(s, 56)
    if context < 2 or context > 320 or 24 + context + 8 > body:
        return INVALID
    source_at = 64 + context
    source = input_word(s, source_at)
    if source < 2 or source > 512 or source > length(s) - source_at - 8:
        return INVALID
    patch_at = source_at + 8 + source
    if mode < 3:
        if patch_at != length(s):
            return INVALID
    else:
        if length(s) - patch_at < 8:
            return INVALID
        patch = input_word(s, patch_at)
        if patch < 2 or patch > 512 or patch != length(s) - patch_at - 8:
            return INVALID
        state_put(w, 40, patch)
        copy_input(s, w, patch_at + 8, 1024, patch)
    state_put(w, 16, mode)
    state_put(w, 24, context)
    state_put(w, 32, source)
    copy_input(s, w, 64, 3072, context)
    copy_input(s, w, source_at + 8, 512, source)
    return context_action(o, w, 1, 2)

def context_action(o:mutbuf, w:mutbuf, role:u64, phase:u64) -> u64:
    count = state_word(w, 24)
    action(o, w, role, phase, 0, count)
    return copy_state(w, o, 3072, 48, count)

def after_context(o:mutbuf, w:mutbuf, status:u64, body:u64) -> u64:
    if body != 0 or status > 6:
        return INVALID
    if status != 0:
        return refuse(o, w, status)
    # Successful Context lookup is the only authority for cost accounting.
    if state_word(w, 24) != 121 or state_word(w, 3079) & 4294967295 != CONTEXT_PREFIX:
        return INVALID
    index = 4
    while index < 36:
        digit = byte(w, 3079 + index)
        if (digit < 48 or digit > 57) and (digit < 97 or digit > 102):
            return INVALID
        index = index + 1
    state_put(w, 312, 36)
    return context_action(o, w, 2, 3)

def after_attempt(o:mutbuf, w:mutbuf, status:u64, body:u64) -> u64:
    if body != 0 or status > 3:
        return INVALID
    if status == 1 or status == 2:
        return refuse(o, w, 7 + status)
    if status == 3:
        return context_action(o, w, 2, 3)
    count = state_word(w, 32)
    kind = choose(state_word(w, 16) < 3, 1, 2)
    action(o, w, 3, 4, kind, count)
    return copy_state(w, o, 512, 48, count)

def after_input(o:mutbuf, w:mutbuf, event:u64, status:u64, body:u64) -> u64:
    if body != 0 or status > 2:
        return INVALID
    if status == 1:
        return refuse(o, w, 5)
    if status == 2:
        return refuse(o, w, 7)
    mode = state_word(w, 16)
    if event == 4 and mode >= 3:
        count = state_word(w, 40)
        action(o, w, 3, 5, 3, count)
        return copy_state(w, o, 1024, 48, count)
    action(o, w, 4, 6, mode, 0)
    return 48

def after_transform(s:readbuf, o:mutbuf, w:mutbuf, status:u64, body:u64) -> u64:
    if status == 1 and body == 0 and state_word(w, 16) >= 3:
        return refuse(o, w, 10)
    if status == 2:
        if body < 18 or body > length(o) - 116 or input_word(s, 40) != DIAGNOSTIC:
            return INVALID
        if input_word(s, 48) != body - 16 or byte(s, 56) != 123 or byte(s, length(s) - 1) != 125:
            return INVALID
        end = copy_input(s, o, 56, 116, body - 16)
        return outcome(o, w, 7, 0, end)
    if status != 0 or body != 128 or valid_hex(s, 40, 128) == False:
        return INVALID
    copy_input(s, w, 40, 48, 128)
    # Core publication carries both its authorized receipt hash and the
    # canonical Context reference to be included as immutable metadata.
    count = state_word(w, 24)
    action(o, w, 5, 7, 8, 64 + count)
    copy_state(w, o, 48, 48, 64)
    return copy_state(w, o, 3072, 112, count)

def receipt(s:readbuf, w:mutbuf, digest:u64, body:u64) -> bool:
    if body != 200 or input_word(s, 40) != DOCUMENT or input_word(s, 48) != 176 or input_word(s, 56) != 0:
        return False
    if artifact_reference(s, 64) == False:
        return False
    index = 0
    while index < 64:
        if byte(s, 117 + index) != byte(w, digest + index):
            return False
        index = index + 1
    return True

def after_core(s:readbuf, o:mutbuf, w:mutbuf, status:u64, body:u64) -> u64:
    if status != 8 or receipt(s, w, 48, body) == False:
        return INVALID
    copy_input(s, w, 64, 2048, 176)
    action(o, w, 5, 8, 9, 64)
    return copy_state(w, o, 112, 48, 64)

def result(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = result_open(o, 116)
    if state_word(w, 16) < 3:
        at = result_null(o, at)
    else:
        if state_word(w, 32) != 176:
            return INVALID
        at = copy_state(w, o, 512, at, 176)
    at = result_candidate(o, at)
    at = copy_state(w, o, 2048, at, 176)
    at = result_diagnostic(o, at)
    at = copy_input(s, o, 64, at, 176)
    store(o, at, 125)
    return outcome(o, w, 6, 0, at + 1)

def refuse(o:mutbuf, w:mutbuf, code:u64) -> u64:
    end = rejection(o, code)
    if end == 0:
        return INVALID
    return outcome(o, w, 7, code, end)
'''

ERRORS = (*INSPECTION_ERRORS[:7],
          ("E_HIA_BUDGET", "context total wall budget has expired", "context"),
          ("E_HIA_BUDGET", "candidate attempt budget exhausted", "context"),
          ("E_HIA_PATCH_SCHEMA", "patch artifact differs from declared patch schema", "admission"))


def source_program():
    tags = {
        "EVENT": b"HIAFDE01", "ACTION": b"HIACNA01", "REQUEST": b"HIACAN01",
        "DOCUMENT": b"HIADOC01", "OUTCOME": b"HIACND01", "CONTEXT_PREFIX": b"ctx-",
        "DIAGNOSTIC": b"HIACDJ01",
    }
    constants = {name: int.from_bytes(value, "little") for name, value in tags.items()}
    constants["INVALID"] = 4294967295
    shared = discovery_policy()
    authority = authority_policy()
    # Both flows have the same Context, sideband and action layouts. Replace
    # only the output tag and the private terminal phase, not the accounting.
    outcome = function(INSPECTION_POLICY, "outcome").replace("role, 8, kind", "role, 9, kind")
    policy = POLICY + outcome + function(INSPECTION_POLICY, "action")
    policy = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda match: str(constants[match[0]]), policy)
    dispatch = ["def rejection(o:mutbuf, code:u64) -> u64:"]
    diagnostics = []
    for index, (code, message, phase) in enumerate(ERRORS, 1):
        dispatch.extend((f"    if code == {index}:", f"        return error_{index}(o)"))
        raw = json.dumps({"code": code, "details_artifact": None, "message": message, "phase": phase,
                          "retry_action": "correct_input"}, sort_keys=True, separators=(",", ":")).encode("ascii")
        diagnostics.append(literal(f"error_{index}", raw, fixed=116))
    dispatch.append("    return 0")
    parts = {
        "result_open": b'{"adopted":false,"base_program":',
        "result_candidate": b',"behavior_equivalence_proved":false,"candidate":',
        "result_diagnostic": b',"core_admitted":true,"diagnostics":',
        "result_null": b"null",
    }
    return "\n".join((
        policy,
        *(function(shared, name) for name in (
            "input_word", "state_word", "state_put", "copy_input", "copy_state", "valid_hex")),
        *(function(authority, name) for name in (
            "artifact_reference", "artifact_start", "artifact_digest", "artifact_uri")),
        *(literal(name, raw) for name, raw in parts.items()), "\n".join(dispatch), *diagnostics,
    ))


if __name__ == "__main__":
    SOURCE.write_text(render_assembly(document(source_program(), SOURCE.stem)), encoding="utf-8")
