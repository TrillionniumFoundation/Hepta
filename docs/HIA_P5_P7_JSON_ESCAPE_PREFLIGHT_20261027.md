# HIA P5/P7: escaped JSON fragment materialization guard

Stacked on the exact two-parent HIA Rust v7 Chain/P7 Core admission
convergence commit `b7d3e3e006017af5ccb85325a91ec0d6b3c99169`.

## Real scope

The existing `hepta.hia_program_tools.bounded_json_wire` checks
individual string/key *character counts* before calling the standard
Python JSON encoder. JSONEncoder's generator may allocate a full escaped
string fragment before yielding it; with NUL/other control bytes one source
character can expand into six JSON bytes, and with `ensure_ascii=True`
a supplementary Unicode code point can expand into twelve JSON bytes.
A source string shorter than the policy byte bound could therefore
materialize an oversized fragment before the final streaming byte counter
refused it.

The same routine now checks the exact escaped UTF-8 size of every string
and every stringified JSON object key **without building escaped text**.
It matches both `ensure_ascii=True` and `False`, including ASCII DEL,
control escape short forms, Unicode BMP and supplementary code points.
Unpaired surrogates under non-ASCII encoding reject; nonfinite numeric
object keys reject. Giant integer key/value inputs have a conservative
bit-length lower-bound refusal before their decimal text is formed.

No HIA ISA, verifier, runtime, LLVM emitter, C/C++ source migrator,
public Agent wire bytes or existing per-call budget changes. Accepted
JSON values still use the original encoder unchanged. This only bounds
individual encoder fragments, **not** overall process RSS, malicious
same-user mutation or full production HIA soundness.

## Verification

```sh
python -m unittest tests.test_hia_wire_escape_preflight \\
  tests.test_hia_bounded_agent_json tests.test_hia_program_tools -v
python -m unittest tests.test_hia_inmemory_json_budget -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
```

An independently authored local CPython 3.13.5 string-length recurrence
was compared to real `json.dumps(...).encode("utf-8")` on **33,961
randomized valid ASCII/Unicode/control cases** and matched each.
This checks the core recurrence only; complete exact-HEAD repository
tests, Cargo/native LLVM, genuine Agent workload A/B and physical
hardware execution have NOT been run in this environment. Committed
in-repository regression tests are acceptance inputs, not pass claims.

All general P0–P7 blockers remain OPEN/PARTIAL:
`whole_project_blockers_closed=false`.
