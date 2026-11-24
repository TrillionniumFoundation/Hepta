"""Author private nominal build hashing and refusal presentation.

The shared edit programs retain the complete public report owner. The object
builder invokes canonical hashing and driver refusals; its reachable projection
retains both operations and their complete diagnostics within the existing
eight-MiB static-link input bound.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_inspection import reachable_source
from tools.generate_hia_core_inspect_json import document, source_program as report_source

ENTRY = """def present_nominal_build_input(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128 or length(w) < 9280:
        return 4294967293
    mode = get(w, length(w) - 8)
    if mode == NOMINAL_HASH:
        return hash_canonical_input(s, o, w)
    if mode == DRIVER_REPORT_MODE or mode == CORE_DRIVER_REPORT_MODE:
        return driver_report(s, o, w, get(w, length(w) - 16))
    return 4294967293
"""

def source_program():
    return reachable_source(report_source(nominal=True, compact=False, entry=ENTRY),
                            entry="present_nominal_build_input")

def main():
    root = Path(__file__).resolve().parents[1]
    # The native link policy retains the private presentation role header.
    # Its distinct source path and complete admitted source hash remain explicit.
    (root / "examples/hia_bootstrap/core_nominal_build_hash.hepta").write_text(
        render_assembly(document(source_program(), "core_nominal_report_json")))

if __name__ == "__main__":
    main()
