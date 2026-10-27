# HIA P5/P7 — bounded serialization of in-memory Agent JSON

**Exact parent:** PR #301 `c6e767f1bacc883c4665fa6b49820dc9b83789e0`.
Existing `hia_program_tools` remains the JSON/patch owner. This patch adds
no HIA dialect, SSA verifier, compiler, LLVM emitter or native authority.

## Defect and implementation

The text/bytes Agent patch paths already imposed size limits before parsing,
but in-process dict/list paths in `apply_program_patch`, `apply_edit` and
`apply_batch` invoked a full `json.dumps` first, then checked length.
A huge or cyclic untrusted object could cause avoidable allocation/recursion
before a formally configured 8 MiB / 16 KiB / 64 KiB rejection.

The existing patch module now owns **one** bounded JSON wire encoder:
an iterative preflight rejects cycles, unsupported values, excess array/map
fanout, excessive individual strings/keys and node count; the normal Python
JSONEncoder then emits deterministic wire fragments subject to a byte cap.
The preflight limits container fanout **before** extending its DFS pending
queue, avoiding an O(huge_array_length) temporary.

- `apply_program_patch`: bounded in-process object to 8 MiB.
- `prepare_edit`, `apply_edit`: bounded query view to 1 MiB;
  in-process response to 16 KiB.
- `prepare_batch`, `apply_batch`: bounded 1 MiB query;
  in-process response to 64 KiB.
- `render_edit_context`: refuses forged oversized query objects.
- Default query/batch canonical byte serialization remains identical for
  supported small requests; Boolean versus integer JSON distinctions remain.
  The existing `decode_json`, immutable Core SHA, exact query replay, atomic
  edits and full-module verifier still control the accepted program.

This is a bounded **input representation** claim, NOT a process RSS proof or
a proof of arbitrary program soundness. It does not make AI output behaviorally
equivalent or authorize production Final-use.

## Tests

```sh
python -m unittest tests.test_hia_bounded_agent_json \
  tests.test_hia_edit_query tests.test_hia_edit_batch -v
python -m unittest tests.test_hia_program_tools tests.test_hia_program -v
```

A standalone CPython 3.13 replica of the bounded encoder independently passed
6/6 scoped tests (wire parity, limits, cycles/shared containers, malformed
data, denial before encoder invocation, bool/int identity). The new
full-Hepta integration tests are **committed but not executed** here; the
local environment cannot clone GitHub or invoke pinned Cargo/rustc. No
exact-HEAD native/CI success is inferred.

P0–P7 full closure, general Memory SSA/Provenance, source→native refinement,
C/C++ L2–L3, controlled Agent model A/B, physical GPU/DMA and production
performance remain OPEN. `whole_project_blockers_closed=false`.
