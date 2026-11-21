"""Retain the Agent importer's byte, Unicode, and JSON-grammar refusals."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_preflight import SOURCE as JSON_PREFLIGHT

SOURCE = Path("examples/hia_bootstrap/worker_candidate_json_ingress.hepta")
POLICY = """
# Private result word: 0 accepted, 1 encoding, 2 extent, 3 depth/nodes,
# 4 duplicate field, 32 + the established HIA JSON preflight reason.
def candidate_json(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 4194304 or length(w) < 4256:
        return 4294967293
    if length(s) > 8388608:
        put(o, 0, 2)
        return 8
    if utf8(s) == False:
        put(o, 0, 1)
        return 8
    put(w, 48, 262144)
    put(w, 56, 128)
    status = widen(preflight(s, o, w))
    if status == 3:
        return 4294967293
    if status == 1:
        status = 32 + get(w, 32)
    elif status == 2:
        status = 3
    put(o, 0, status)
    return 8

def utf8(s:readbuf) -> bool:
    # The previous bytes API checked the entire UTF-8 encoding before
    # examining any JSON token. Invalid bytes after a syntax error still win.
    index = 0
    while index < length(s):
        if byte(s, index) < 128:
            index = index + 1
        else:
            unit = decoded(s, index)
            if unit & 4294967295 == 1114113:
                return False
            index = unit >> 32
    return True

def widen(value:u32) -> u64:
    return value
"""


if __name__ == "__main__":
    SOURCE.write_text(render_assembly(document(POLICY + JSON_PREFLIGHT, SOURCE.stem)), encoding="utf-8")
