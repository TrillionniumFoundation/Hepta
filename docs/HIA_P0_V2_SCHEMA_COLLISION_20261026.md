# HIA P0: Independent v2 wire-schema collision (2026-10-26)

Actual Git blobs reviewed:
- PR #179, `hepta/hia_program_composite.py` at `a3fe747676e408707bbc3a8725fb62969734b690`, blob `5588807d72dbac84b635893d8bfa4fe194a58ec3`.
  Declares `SCHEMA = "hepta.hia.program.v2"` with `PROFILE = "nominal-products-enums-cooperative-tasks-over-closed-ssa-v2"`.
- Current v6 integrated PR #196, `hepta/hia_program.py` at `8d8f859323056df51c47f0a8df45298f82040c6e`, blob `9acd57da766ca579b91327ab7fcd272370c1ac89`.
  Declares `SCHEMA_V2 = "hepta.hia.program.v2"` with `PROFILE_V2 = "closed-ssa-integer-byte-resources-bulk-64-v2"`.

**Same schema label, incompatible explicitly declared semantic profiles.** Do NOT
cherry-pick the composite producer into the v6 HIA verifier unchanged, treat
the same label as wire compatibility, or transparently reinterpret stored
programs. These are distinct protocol namespaces despite both using `v2`.

`tools/audit_hia_schema_collision.py` statically parses Python top-level
literal schema/profile definitions without executing repository code. It binds
SHA256 of source bytes; rejects nonliteral/duplicate/unknown declarations,
oversize/symlink sources and output overwrite. It returns exit **3** for a
detected mismatch, **2** for invalid input/output, **0** if no declared
profile conflict. Exit 0 **never** establishes semantic equivalence.

Usage on a checkout having both producer files:
```sh
python tools/audit_hia_schema_collision.py \
  --left /path/to/pr179/hepta/hia_program_composite.py \
  --right /path/to/current/hepta/hia_program.py \
  --output /tmp/hia-schema-collision.json
python -m unittest tests.test_hia_schema_collision -v
```

**P0 closure requires** an explicit new composite schema namespace/version,
mapping every affected producer, loader, patcher, native emitter, interpreter,
JSON fixture, documentation and source identity. An adapter must independent-
verify the exact source and semantics, reject unsupported revisions and avoid
implicitly upgrading source/FFI/ownership claims. Until then, this detector
is a merge-safety guard only.

Local execution in the available Python environment: **8/8 unit tests passed**
for exact source/test byte objects. This is not a whole-compiler qualification;
P0–P7 and `whole_project_blockers_closed` remain OPEN/false.
