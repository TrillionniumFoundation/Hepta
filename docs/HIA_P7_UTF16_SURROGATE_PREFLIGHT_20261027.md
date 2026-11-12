# P7: Reject orphan UTF-16 surrogate input before HIA Agent JSON materialization

Base: PR #315 exact HEAD b6b201aa01b37c1f27902030b0228d08ef171386.

HIA Core's canonical UTF-8 representation does not support isolated UTF-16
surrogate code units. Its bounded in-memory encoder rejects unpaired surrogates.
However, textual JSON with a single escaped high or low surrogate could pass
the new pre-materialization scanner and reach json.loads, materializing a
Python string containing an isolated surrogate.

Extend the existing preflight_hia_json scanner, which both HIA Core and Agent
text input already use. Unescaped surrogate code points and isolated escaped
U+D800–U+DFFF units now reject before decoder materialization. A high unit
must be followed immediately by an escaped low unit. Valid paired escapes
and ordinary escaped backslashes retain their stdlib-compatible semantics.
Decoded-key collision checks still use the original scanner, with no second
parser or semantic authority.

This is strictly a P7 text-input normalization boundary. It does not alter
existing HIA instruction schemas, the Python ownership verifier, Rust scalar/
Owner shadows, the LLVM backend, Agent edit authorization, C/C++ migrators or
any published native ISA contract.

## Focused regressions

    python -m unittest tests.test_hia_surrogate_predecode \
      tests.test_hia_text_agent_predecode tests.test_hia_json_preflight -v
    python -m unittest tests.test_hia_program tests.test_hia_bounded_agent_json -v

A standalone CPython scanner replica passed three unittest methods, including
all 2,048 surrogate code units and valid paired escape controls. Those checks
are NOT a complete exact-HEAD Hepta test run. Full checked-in module tests
and Rust/native/LLVM tests remain NOT RUN in this no-GitHub-checkout environment.
CI scheduling is not a development stop, nor evidence of qualification.

whole_project_blockers_closed=false: P0–P7 formal Memory/Provenance SSA,
C/C++ L2–L3, Rust/native semantic refinement, physical GPU/DMA/IRQ, real
Agent-model A/B and sustained production performance remain OPEN.
