"""Reuse the canonical-input SHA owner for the private nominal object build.

The public report program remains complete. The private builder only calls
its hash operation, so its ELF no longer embeds unrelated diagnostic tables.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_inspection import reachable_source
from tools.generate_hia_core_inspect_json import document, source_program as report_source

ENTRY = """def hash_nominal_input(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128 or length(w) < 9280:
        return 4294967293
    if get(w, length(w) - 8) != NOMINAL_HASH:
        return 4294967293
    return hash_canonical_input(s, o, w)
"""


def source_program():
    return reachable_source(report_source(nominal=True, compact=True, entry=ENTRY),
                            entry="hash_nominal_input")


def main():
    root = Path(__file__).resolve().parents[1]
    # Preserve the private presentation role header consumed by the native
    # linker. This is the hash-only reachable projection of that same owner;
    # its distinct source path and full admitted source hash remain explicit.
    (root / "examples/hia_bootstrap/core_nominal_build_hash.hepta").write_text(
        render_assembly(document(source_program(), "core_nominal_report_json")))


if __name__ == "__main__":
    main()
