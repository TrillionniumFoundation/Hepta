# HIA P7: bound in-process Core JSON *before* canonical serialization

## Frozen integration source

Parent is PR #304 `b959843df7b994da18086b52e159a991e60f0f0b`
on the current P0/P1/P2/P5/P7 v7 integration lineage. This change modifies
only `hepta.hia_program._structure` and adds P7-focused admission tests.
The canonical `verify_program`, HIA ISA, compiler backend, resource types
and native LLVM emitter retain their existing semantics.

## Exploitable input-memory boundary

The existing text/byte HIA decoder uses the reviewed predecode scanner to
bound decoded nodes before `json.loads`. An in-process Python `dict`/`list` is accepted directly by `verify_program`; the historical
`_structure` only counted nodes/depth, so e.g. 3,000,000 NUL characters
could become a much larger escaped JSON string inside `json.dumps`
*before* `MAX_BYTES=8 MiB` was checked. Large fanout also created a huge
pending work list before any node-count rejection.

## Patch

- Reuse the **existing** Core structure check, rather than introducing a
  second JSON parser or an Agent-specific admission authority.
- Calculate the exact UTF-8 byte length of compact
  `json.dumps(..., sort_keys=True, separators=(',', ':'), ensure_ascii=False)`
  for allowed dict/list/string/int/bool/null nodes **without materializing**
  escaped strings.
- Count all string-key/array punctuation, UTF-8 multibyte characters and
  JSON quote/control-character escapes; reject before serialization at 8 MiB.
- Bound queued work fanout against the existing 262,144-node structural cap,
  reject container cycles and unpaired Unicode surrogates.
- Retain original canonical bytes for accepted values; final `json.dumps`
  and full Core typed/SSA/ownership verification still run.

The preflight is an input-size gate, **not** verification of external
provenance, runtime Python mutation across threads, native soundness, GPU
resources, absolute RSS or arbitrary C/C++.

## Evidence

An independent Linux CPython 3.13.5 reconstruction of the same size
recurrence compared **10,000 randomly generated finite JSON structures**
against actual stdlib `json.dumps` UTF-8 lengths, with zero differences.
Four additional oversized-string/fanout/cyclic controls refused. This is an
isolated exact-length algorithm test, not a full checkout HIA execution.

The source regression module adds 300 deterministic cases, exact canonical
HIA Core bytes/VM execution, and early-refusal assertions that mock
`json.dumps`. The actual exact-head repository test suite was **not run**
in this environment (GitHub clone DNS unavailable).

```sh
python -m unittest tests.test_hia_inmemory_json_budget \
  tests.test_hia_json_preflight tests.test_hia_program -v
```

P0–P7 overall production qualification is still open:
`whole_project_blockers_closed=false`. CI queue is not a development gate.
