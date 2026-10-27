# HIA P7 — Agent JSON escape expansion preflight

Base: PR #305 at `0bd79af10ee8db3407c19ac0cf476473e20bd03b`.
This repairs the **existing** `hepta.hia_program_tools.bounded_json_wire`
used by HIA Patch, edit-query and atomic-edit pathways. It does not add a
second JSON serializer, parser, HIA opcode, verifier or compiler.

## False-negative budget class

The existing first-pass check compared `len(string)` against the maximum
encoded bytes. For NUL controls, the stdlib encoder emits six ASCII bytes
(`\\u0000`) per source character; under `ensure_ascii=True`, a single
astral Unicode character expands to two `\\u` surrogate escape sequences
(12 bytes). Thus a string far below a 1 KiB raw-character limit could
cause the encoder to materialize a multi-KiB string before the second-pass
cumulative byte check refused it.

This patch adds a linear, non-materializing exact byte-size preflight for
both string **values and object keys**, following the existing JSONEncoder
rules for controls, quotes, backslashes, ASCII/non-ASCII, BMP/astral
surrogates and UTF-8, respecting `ensure_ascii`. A non-ASCII raw surrogate
is rejected for the UTF-8 profile. Oversized numeric-key/value bit widths
also fail before giant decimal fragments can be constructed.

The original stdlib `JSONEncoder.iterencode` remains the output authority.
Its canonical bytes, cumulative byte check, duplicate/unsupported field
validation and existing Core/Agent replay/patch verification are unchanged.

## Additional pending-queue fanout bound

The same Agent preflight already checked `len(node) <= maximum - visited`
before extending the DFS work list. Repeated references to nested wide lists
could nevertheless accumulate more than `maximum` unvisited nodes across
different ancestors. A new `queued` counter accounts for *all* pending
unvisited children, and refuses a container before adding its descendants
when `len(node) > maximum - visited - queued`. This leaves valid input
bytes and the stdlib serializer unchanged.

A deterministic regression uses a small shared object graph whose unfolded
JSON fanout exceeds a 1024-node policy while each individual list fits.
The test asserts the earlier `queued-node` refusal and that JSONEncoder
never executes. A separate 1023-element valid list remains byte-identical.

## Tests and truthful qualification

```sh
python -m unittest tests.test_hia_bounded_agent_json -v
python -m unittest tests.test_hia_edit_query tests.test_hia_edit_batch \
  tests.test_hia_program_tools -v
```

New committed tests assert that `JSONEncoder.iterencode` is **never
called** for over-budget NUL, non-ASCII, astral, or long escaped key cases,
and that exact-budget valid output remains byte-identical to json.dumps
for both encoding modes.

Independently executed CPython 3.13.5 math/encoding control:
**80,000 randomized strings** plus escape/surrogate edge cases, comparing
preflight length to actual stdlib encoded UTF-8 length. Both test methods
passed. This is *not* an execution of the new exact-HEAD Hepta repository
tests or native Rust/LLVM qualifications; those remain not run here.

This increment prevents excess **single encoder string fragments**; the
existing iterative output accounting still bounds total emitted bytes.
It does not prove full process RSS limits, arbitrary Python execution
safety, FFI, source-to-Core correctness, native refinement, Agent
productivity, or P0–P7 production readiness.
`whole_project_blockers_closed=false`.

## Follow-up: U+007F DEL encoding under ensure_ascii=True (2026-10-27)

A further adversarial check exposed a missed ASCII-range exception:
CPython `json.JSONEncoder(ensure_ascii=True)` encodes DEL (U+007F) as
the six-byte sequence `\\u007f`. The prior preflight counted this one
ASCII code point as just one byte, so 350 DEL characters passed an
isolated 1 KiB string-fragment budget even though the encoder emitted
2,102 bytes for the string including quotes. The cumulative output check
eventually rejected the result, **after creating the oversized fragment**.

The current patch counts U+007F as six bytes only when
`ensure_ascii=True`; the `ensure_ascii=False` profile correctly retains
one byte. This applies to both dictionary keys and string values; no
schema, ISA, serializer or admission authority is added. The regression
suite now checks early refusal with `JSONEncoder.iterencode` mocked to
fail if entered, and includes exact-budget positive/negative DEL cases.

**Actual isolated local execution (CPython 3.13.5):** 30,000 randomized
Unicode strings, split between both encoding modes, matched the stdlib
`json.dumps` UTF-8 byte size and rejected every exact-size-minus-one
budget. The old/new DEL preflight control reproduced the false-negative
and verified the correction. These tests were run on the isolated
byte-counting recurrence, **not** on the combined exact-HEAD Hepta checkout.
The in-repository full unit/native tests remain unexecuted here.

`whole_project_blockers_closed=false`.
