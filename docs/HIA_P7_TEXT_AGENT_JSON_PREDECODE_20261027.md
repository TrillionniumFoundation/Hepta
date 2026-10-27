# HIA P7: predecode budget for textual Agent JSON envelopes

**Exact parent:** PR #314 `ff5e81063f59e4f4e33df08342fe5f284490209a`.
**Change:** reuse the existing `hepta.hia_json_preflight.preflight_hia_json`
in the original `hepta.hia_program_tools.decode_json`. There is no new
parser, program checker, compiler or language syntax.

## Previously under-bounded path

The in-memory Agent encoder `bounded_json_wire` already checks node/depth
before emitting text. But clients can supply a text or bytes patch/query/
response directly to `decode_json`; that path had only an 8 MiB *byte* check
before `json.loads` materialized the entire Python value graph.

A valid approximately 512 KiB JSON array with more than 262,144 values is
within the byte budget, yet allocates a very large graph prior to any HIA
semantic validation. A tiny input with 129 nested arrays similarly exceeds
the intended Agent presentation depth. Both now refuse **before** the full
stdlib parse using the existing syntax preflight.

The new text-profile upper limits are 262,144 JSON nodes, 128 nested levels,
and the unchanged 8 MiB encoded bytes. UTF-8 is the explicit Agent wire
encoding. Float/scientific JSON values fail closed in this integer-only HIA
edit protocol rather than becoming a valid HIA operation. The canonical
`json.loads` with duplicate-key/nonfinite rejection remains the sole value
decoder. No acceptance claims from externally supplied JSON are trusted.

## Reproduction

```sh
python -m unittest tests.test_hia_text_agent_predecode \
  tests.test_hia_program_tools tests.test_hia_json_predecode -v
python -m unittest tests.test_hia_bounded_agent_json \
  tests.test_hia_cfg_render_convergence -v
```

The committed tests require genuine `decode_json` to refuse excessive
fanout and depth *before* `json.loads` is invoked. The full exact-head
Hepta checkout is unavailable in this tool container, so these in-repository
tests and Cargo/native qualification are **not** claimed as executed.

This is a bounded input-materialization guarantee only, not whole-language
soundness, functional equivalence, C/C++ migration, physical hardware,
performance or Agent model benefit. `whole_project_blockers_closed=false`.
