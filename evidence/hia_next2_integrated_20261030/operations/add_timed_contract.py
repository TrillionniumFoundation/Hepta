"""Add the independently reviewed native timer profile without reducing scope."""
from pathlib import Path
import hashlib
import json
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from update_contract import REPO, selectors


def main():
    path = REPO / "docs/HIA_SAFETY_CONTRACT.json"
    contract = json.loads(path.read_bytes())
    original = json.loads(json.dumps(contract["capabilities"]))
    identifier = "explicit_timed_xor_fold_native_context"
    if identifier in {row["id"] for row in original}:
        raise ValueError("timer contract already applied")
    row = {
        "id": identifier,
        "guarantee": "host_enforced_scoped_admission",
        "scope": "Explicit allow_timed_xor_fold=True selects hepta.hia.finite-u32-timed-xor-fold-context.v1 and timed_xor_fold wire mode 3. It uses the same byte XOR recurrence, single repetition, finite calls, sealed images, one-use trace, reference validation and child cleanup as the existing context. Actual CLOCK_MONOTONIC observations surround the C fold loop, including loads, indirect calls, checksum and loop overhead. The event must contain a positive exact integer timer and the complete matching result; missing/unknown/malformed timing or failed prefix cannot qualify. All eight CRC study arms and common reference priming select the same new mode.",
        "exclusions": [
            "Legacy modes 0/1 retain their wire/result shapes and expose no kernel_ns field. Map-repeat mode 2 remains separately opt-in; the extended profile switches are mutually exclusive.",
            "Timer observations are not pure LLVM-body time, CPU cycles, timing precision/independence proof, or native_outer_wall_ns substituted for unavailable loop timing.",
            "A trap or incomplete request has no fabricated completed timer; completed-prefix accounting does not count unknown partial work as zero.",
            "No additional repetition, input lifetime or resource budget, Core/native admission bypass, net improvement or NDU incremental-value claim."
        ],
        "entrypoints": ["hepta.hia_finite_context.build_bank", "hepta.hia_finite_context.FiniteU32Bank.prepare_trace", "tools.qualify_hia_crc_linear_economics.study"],
        "regression_selectors": selectors("tests.test_hia_finite_context_timed_fold"),
    }
    contract["capabilities"].append(row)
    if contract["capabilities"][:-1] != original or any(value is not False for value in contract["unproved_claims"].values()):
        raise ValueError("existing contract or universal claim changed")
    path.write_text(json.dumps(contract, sort_keys=True, indent=2) + "\n")
    digest = hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    runner = REPO / "tools/qualify_hia_safety_contract.py"
    text, count = re.subn(r'^REVIEWED_CONTRACT_SHA256 = "[0-9a-f]{64}"$',
                         'REVIEWED_CONTRACT_SHA256 = "' + digest + '"', runner.read_text(), flags=re.M)
    if count != 1:
        raise ValueError("reviewed pin not unique")
    runner.write_text(text)
    integrated = REPO / "tools/qualify_hia_integrated.py"
    marker = '    "public_selection_first_agent_decoder": ("test_hia_agent_toolstudy_v13",),\n'
    text = integrated.read_text()
    if text.count(marker) != 1:
        raise ValueError("critical-group anchor differs")
    integrated.write_text(text.replace(marker, marker + '    "explicit_timed_xor_fold_native_context": ("test_hia_finite_context_timed_fold",),\n'))
    docs = REPO / "docs/HIA_SAFETY_CONTRACT.md"
    marker = "## Typed state and instruction obligations\n"
    text = docs.read_text()
    if text.count(marker) != 1:
        raise ValueError("documentation anchor differs")
    addition = (
        "The CRC timing protocol uses a separately selected `timed_xor_fold` mode.\n"
        "Legacy fold events contain no inner-loop timer, so they cannot supply the\n"
        "new diagnostic. Mode 3 records actual monotonic clocks around the unchanged\n"
        "C fold loop, including data loads, indirect calls, checksum and loop cost.\n"
        "It does not measure a pure LLVM body. All eight arms and common reference\n"
        "priming select this same mode; input, repetition and lifetime budgets do\n"
        "not grow. Missing or malformed timing and incomplete/trapped requests\n"
        "cannot become completed zero-cost observations. Old fold output and the\n"
        "separate map-repeat profile remain unchanged. The first timing interface\n"
        "mismatch was discovered before any economic run; its original protocol\n"
        "and already completed correctness records keep their source identities.\n\n"
    )
    docs.write_text(text.replace(marker, addition + marker))
    print(json.dumps({"capabilities": len(contract["capabilities"]),
                      "distinct_selectors": len({s for c in contract["capabilities"] for s in c["regression_selectors"]}),
                      "contract_sha256": digest, "prior_capabilities_retained": len(original),
                      "new_timed_selectors": len(row["regression_selectors"])}))


if __name__ == "__main__":
    main()
