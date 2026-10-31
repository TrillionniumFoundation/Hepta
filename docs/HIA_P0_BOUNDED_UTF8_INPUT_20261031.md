# HIA P0 — bounded UTF-8 text input before syntax / Core admission

## Exact source and relationship to the mutable snapshot repair

This candidate stacks on PR #458 at `1a7559360ae6a7e15003c390ebaea2da476f11b8` and makes no change to its
`_bounded_detached_snapshot` safety behavior. PR #458 fixed a mutable JSON
structure check/use race; this increment handles a separate resource budget
hole in the immutable-text intake. It is a draft review branch, not a P0–P7
production acceptance or a claim of whole-language safety.

## Source-exact problem

`_decode` executed `len(value.encode("utf-8"))` before comparing to the
8 MiB `MAX_BYTES` limit. The operation allocates the *complete encoded
string* even if the request is many times over the budget, so a malicious
very-large Unicode string can incur substantial unaccounted memory cost
before being rejected. This is distinct from the later bounded syntax scanner.

## Repair and preserved contract

`_bounded_input_utf8_bytes` counts the exact UTF-8 length of built-in immutable
Python strings, with an O(1) codepoint-count rejection, ASCII fast path, and
4096-codepoint chunks for non-ASCII text (at most 16 KiB UTF-8 per temporary).
An input exceeding the unchanged 8 MiB budget fails with `E_HIA_LIMIT` before
it reaches the JSON syntax preflight or full JSON decoding. Malformed Unicode
surrogates still fail closed as `E_HIA_FORMAT`. Exact canonical bytes, duplicate
key handling, interpreted value, Core verifier, typed SSA, resource and trap
semantics, caller-owned dict/list snapshot, and immutable bytes intake are
unchanged.

This closes only the *full-size UTF-8 encode-before-budget-check* defect. It
does not establish an atomic snapshot of concurrent nested Python mutations,
a bound on the already-held caller-owned Python string, a full-process RSS
bound, or machine-checked native/refinement correctness.

## Reproduce and false-positive controls

```sh
python -B -m unittest tests.test_hia_bounded_input_utf8 tests.test_hia_bounded_mutable_snapshot -v
python -B -m unittest tests.test_hia_program tests.test_hia_json_preflight tests.test_hia_program_composite -v
```

Independent controls include ASCII / UTF-8 exact byte limits, equality on
bytes/text/detached-input canonical output, actual scalar and ownership Core
programs, pre-syntax refusal for oversize text, malformed surrogate rejection,
and a `tracemalloc` upper bound on the temporary allocation needed to count
an 8 MiB Unicode wire. The traced peak applies to this helper only, not the
entire compiler or process.

## P0–P7 status at this implementation boundary

| Stage | Scope checked by this PR | Remaining mandatory evidence |
|---|---|---|
| P0 | Bounded UTF-8 + inherited mutable snapshot | Full exact-core semantic convergence, independent verifier/LLVM regression on final integrated SHA |
| P1 | No change | Provenance, resource/exit/refinement and adversarial obligations |
| P2 | No change | Multi-target real host ABI/native qualification |
| P3 | No change | Real C/C++ external migration, upgrade and human-cost evidence |
| P4 | No change | Strong matched Rust/C/C++ baseline and global transformation soundness |
| P5 | No change | NDU > fixed/DP in complete, independent, held-out net-benefit tests |
| P6 | No change | Fresh Agent coding tasks, equal budgets and reliable provider cost |
| P7 | No change | Safe hot-switch, final-use/fence, ledger/restart/rollback and physical hosts |

Keep all eight production stages OPEN unless a separate exact-source evidence
gate passes. Historical passing results or synthetic positives cannot close
unrelated stages.
