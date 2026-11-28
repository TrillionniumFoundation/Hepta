"""Author the fixed HIA NDU constructor's source-build policy.

The original full-domain NDU packer remains unchanged.  This new policy admits
only the already-qualified four-image leaf, and uses the existing source-build
six-word transport to call that exact HIA packer.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import json

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = "examples/hia_bootstrap/source_ndu_evaluator.hepta"
CONTRACT = "docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json"
CONTRACT_SHA256 = "9d04ec9fab8a0f0ce2d467a951793fc92a890baae8cae985ab9cbfe7476b89a2"


def policy_source():
    raw = (ROOT / CONTRACT).read_bytes()
    if sha256(raw).hexdigest() != CONTRACT_SHA256:
        raise ValueError("NDU frozen leaf contract differs")
    value = json.loads(raw)
    sizes = {row["role"]: row["flat_bytes"] for row in value["build_inputs"]["modules"]}
    total = 48 + sum(sizes[name] for name in ("transport", "evaluator", "number", "debug"))
    checks = " or ".join("word_load(s, " + str(8 + 8 * i) + ") != " + str(sizes[name])
                         for i, name in enumerate(("transport", "evaluator", "number", "debug")))
    return f'''
def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 96:
        return 17
    phase = word_load(w, 0)
    state = word_load(w, 16)
    if phase == 0:
        if state != 0 or length(s) != 21:
            return reject(w, 16)
        if word_load(s, 0) != 1 or word_load(s, 8) != 5:
            return reject(w, 16)
        if byte(s, 16) != 98 or byte(s, 17) != 117 or byte(s, 18) != 105 or byte(s, 19) != 108 or byte(s, 20) != 100:
            return reject(w, 16)
        word_store(w, 16, 1)
        return 0
    if phase == 1:
        if state != 1 or length(s) != {total}:
            return reject(w, 16)
        if word_load(s, 0) != {int.from_bytes(b"HIANDP01", "little")} or word_load(s, 40) != 0:
            return reject(w, 16)
        if {checks}:
            return reject(w, 16)
        word_store(w, 40, length(s))
        word_store(w, 16, 2)
        return 0
    if state != 2 or length(s) != word_load(w, 40):
        return reject(w, 16)
    if phase == 2:
        return 2
    if phase == 4:
        if length(o) < length(s):
            return reject(w, 17)
        at = 0
        while length(s) - at >= 8:
            word_store(o, at, word_load(s, at))
            at = at + 8
        while at < length(s):
            store(o, at, byte(s, at))
            at = at + 1
        word_store(w, 80, length(s))
        return 0
    if phase == 5:
        if word_load(w, 72) != {value["binary_bytes"]} or length(o) < {value["binary_bytes"]}:
            return reject(w, 18)
        word_store(w, 88, {value["binary_bytes"]})
        word_store(w, 16, 3)
        return 0
    return reject(w, 16)

def reject(w:mutbuf, code:u32) -> u32:
    word_store(w, 16, 255)
    word_store(w, 88, 0)
    return code
'''


def render():
    return render_assembly(document(policy_source(), "source_ndu_evaluator"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    raw = render().encode()
    path = ROOT / OUTPUT
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit("NDU constructor policy differs")
    else:
        path.write_bytes(raw)
    print(OUTPUT, len(raw), sha256(raw).hexdigest())


if __name__ == "__main__":
    main()
