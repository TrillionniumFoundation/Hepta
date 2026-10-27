# HIA P7: Agent in-memory JSON nesting preflight — 2026-10-27

**Source integration parent:** exact two-parent HIA convergence
`b2992481d67a6b2655737ed3a6811210da6f8206` (independent PR #309
escaped-DEL byte accounting and PR #310 safe Agent rendering).

## Identified gap

`hepta.hia_program_tools.bounded_json_wire` already applies cumulative
node/queued-fanout and string byte preflights to hostile in-process request
objects. It lacked a pre-encoder *nesting* gate, however. A shape consisting
of hundreds of single-child arrays can fit the configured byte/node
budgets and pass preflight while still sending deeply recursive input to
`json.JSONEncoder.iterencode`. Later `RecursionError` was caught, but
this work was not bounded *before* the recursive encoder ran.

## Narrow repair

`MAX_AGENT_JSON_DEPTH = 128` is now enforced in the iterative DFS that
already detects cycles and bounds queued nodes. Every child contributes
one level, including nested list, tuple and dict values. The existing
exact byte estimator (including U+007F escapes), cumulative encoder gate,
canonical encoding settings, cycle refusal and patch re-verification are
unchanged. The budget is Agent envelope-specific, not a change to the
executable HIA Core schema or opcode semantics.

A new regression checks a 128-level legal nested value against actual
canonical JSON bytes, and three different 129-level list/dict/tuple
shapes that MUST reject before the actual `JSONEncoder.iterencode` is
invoked.

## Reproduction (complete pinned checkout)

```sh
python -m unittest tests.test_hia_bounded_agent_json tests.test_hia_edit_query \
  tests.test_hia_edit_batch tests.test_hia_context_render_input -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
```

The isolated Python DFS boundary demonstration was tested locally; full
exact-source Hepta test/native/Rust suites have **not** been run in this
environment. This is request-input hardening, not semantic equivalence,
C++ L2/L3 migration, native LLVM refinement, proof of full language safety,
physical GPU/DMA or an AI Agent productivity result.

`whole_project_blockers_closed=false`.
