# Canonical HIA source suffix

Every active HIA source file uses the lowercase `.hepta` extension. The verified
migration base is commit `4161e8d12d87906fde144f039da07908ad52d98a`. It contained
87 HIA sources: 64 assembly files and 23 JSON Core programs. There were no files
with the uppercase `.HIA` suffix in that base.

| Previous name | Canonical name | Content contract |
| --- | --- | --- |
| `name.hiaasm` | `name.hepta` | `hia-asm.v1` assembly header |
| `name.hia` | `name.hepta` | Explicit primitive or composite JSON schema |
| `name.hia.json` | `name.core.hepta` | Explicit JSON schema; distinct from paired assembly |

The extension identifies source files; it does not infer a new language version.
The existing assembler checks the complete assembly grammar and lowered program.
The existing verifier checks JSON Core schemas, types, ownership and control
flow. Retired high-level HIA syntax is not restored. Existing `hepta.hia.*`
schema identifiers and the `hia` CLI entry retain their names.

```sh
hia check-assembly examples/hia_bootstrap/bytesum.hepta
hia verify examples/hia_program/counter.hepta
```

## Source and consumer checks

The Core-only gate rejects active files with retired suffixes, including case
variants, and requires the exact lowercase `.hepta` suffix for retained source.
It validates contents rather than accepting a header alone. Its existing CLI,
forbidden import, high-level fixture and source scope checks remain in force.
The suffix controls cover valid language versions, malformed grammar, invalid
UTF-8, unsupported headers, SSA/type errors and nonregular source entries.

Generators, package resources, wheel/sdist manifests, source identities,
examples, active benchmark source paths and CI use the canonical names. The
support contract binds the migration document, machine-readable rename map and
consumer tests. Full qualification independently regenerates all workflow-listed
sources and checks the complete committed Git tree, raw blobs and file modes.

## Historical evidence

Immutable historical receipts, patch archives and their manifests retain their
original bytes, filenames and hashes. A recorded `.hiaasm` path is evidence of
the original run, not an active source entry. Historical fragment tools recreate
those exact paths in separate temporary trees so original patches still apply.
New counterexamples and active maintenance protocols use `.hepta`.

Tests exercise real historical patch application, immutable archive manifests,
and the maintenance protocol's SHA-256 and Git blob identities after migration.
Old passing receipts do not qualify this renamed source tree. New reports must
bind the actual frozen commit and complete source manifest.

## Native rewrite boundary

This branch was rebuilt from the verified remote base after the earlier local
workspace was lost. Unsynchronized native components from that workspace are
not included in this branch and are not claimed as delivered or qualified.

The retained compiler and selected native applications continue to use HIA.
The CLI bridge, parts of foreign-object transport, durable SQLite transactions,
tool effects and service recovery still have hosted owners. This suffix change
does not prove whole-stack native replacement and does not authorize deletion
of those required implementations. No live worker is activated by these source
changes. `whole_native_delivery_qualified` remains false until replacement and
its actual end-to-end obligations are complete.
