# Native Worker source identity authority

The native Worker installation can bind an explicit inventory of HIA sources,
mechanical assembly, native recipe data, and retained qualification inputs.
This replaces the historical automatic Python source inventory and the backend
identity recipe's 41 raw Python source captures. It does not weaken source
capture, table pinning, compiler identity, ABI validation, or image binding.

## Authority input

The development authors accept `--native-source-authority PATH`. The document
has exactly these fields:

```json
{
  "schema": "hepta.hia.native-source-authority.v1",
  "paths": ["docs/HIA_NATIVE_CONTINUATION_ABI.json", "examples/hia_bootstrap/continuation_policy.hepta"]
}
```

The example illustrates the format only; it is deliberately not a complete
installation authority. A complete authority must include every retained
production, bootstrap, library, recipe, and qualification input selected for the
final native source distribution, including the continuation ABI and every
helper and scheduler source. The final path set is an explicit release input;
no directory glob, Python package inventory, or Rust tree expansion supplies it.

Paths are sorted, unique printable ASCII relative paths with no empty, dot,
parent, or `.git` components, backslashes, or quotation marks. The accepted
source suffixes are `.hepta`, `.S`, `.s`, `.inc`, and `.hiastd`. Native data and
documentation may use `.hiacases`, `.hiadat`, `.hiabundle`, `.json`, `.tsv`, `.md`,
or `.txt`. The original limits remain 4,096 entries, 4,095 bytes per path, and
1 MiB for the complete `HIASPI01` inventory. Host-language source paths cannot
enter this authority.

The catalog contains names, not their own digests. The existing native capture
owner supplies each source digest from its captured file. This avoids a
self-referential manifest hash while binding the catalog itself as a source
input when its relative path is included in the final authority.

## Identity and recipe semantics

`HIAWIS01` remains the length-prefixed sorted path table. The generated
`source_worker_install_identity.hepta` pins its exact byte length, entry count,
and SHA-256. The runtime `HIAWID01` request contains the captured `HIASPI01`
inventory and that table. The HIA owner validates both complete extents, rejects
missing, duplicate, unsorted, and malformed inventory rows, and computes the
SHA-256 of the canonical complete selected path-to-digest JSON object. Valid
unselected inventory entries retain their original behavior: they are checked
but do not become selected source identity.

The native backend identity preimage starts with the explicit domain
`hepta.hia.native-backend-source-authority.v1` followed by NUL, the raw 32-byte
complete source-map digest, and NUL. The existing machine-plan source/image,
family ABI, unit source/image, policy manifest, aggregate image, and
continuation binding terms follow unchanged. This is an intentional new source
authority version, not an assertion that different implementations have the
same historical backend digest.

The continuation runtime entries name the actual HIA continuation policy,
in-process packer, and source worker continuation packer. The continuation ABI
JSON remains required. The schedulers manifest contains the complete selected
native source/recipe `runtime_sha256` dictionary.

## Complete maps within the existing manifest budgets

The original manifest owner has 512 temporary digest slots. The native source
set is larger, so the selected native table uses a streaming source-pin output
operation instead of creating a temporary slot per dictionary member. The
operation is encoded as kind 4, followed by its payload length, a piece-index
word, and the fixed relative path bytes. The HIA owner obtains the corresponding
raw 32-byte pin from the already admitted inventory and writes its 64 lowercase
hexadecimal bytes directly to output.

Only the final mode-9 schedulers record uses this operation. Child-manifest
shape checks retain their prior accepted operation set. The 512-slot,
4,096-operation, 512-validator, 1 MiB table, and 1 MiB output limits remain
unchanged. Authoring rejects an authority that cannot fit those limits; it does
not truncate the source set or increase a runtime budget.

## Preparation and final integration

The parameter is supported by:

- `tools/generate_hia_worker_install_identity.py`
- `tools/generate_hia_worker_manifest.py`
- `tools/generate_hia_worker_install_recipes.py`

The installed product consumes the generated HIA and binary recipe tables. It
does not execute these development authors or import
`hia_native_worker_source_authority.py`. The unselected legacy author mode is
retained in this preparation checkpoint so integration can be reviewed before
final source removal. Its 21 generated products were compared byte for byte
with the original author outputs.

After the final relative path authority is fixed, generation must update
`worker_install_identity_paths.hiastd`, `source_worker_install_identity.hepta`,
`worker_manifest_tables.hiastd`, `source_worker_manifest.hepta`,
`HIA_WORKER_MANIFEST_RECORDS.json`, and `worker_install_identity.hiastd` together.
The other 15 Worker installation DAGs remain byte-identical. Source-contract
generation, the complete native cold run, ordinary release, Worker install,
and installed rebuild must then use that same final source inventory. This
preparation checkpoint does not freeze a final path count or authorize source
retirement before those gates.

## Qualification

The preparation exercised a 1,025-path candidate containing 900 native
source/recipe runtime entries. It used the retained v95 native compiler and
native source packer, with no Python callbacks inside either component.

- 67 actual native identity cases passed, including changed selected pins,
  missing and duplicate paths, invalid bytes and extents, table-pin mismatch,
  exactly 4,096 inventory entries, exactly 1 MiB inventory input, and their
  over-limit refusals. Seventeen malformed authority inputs were rejected by
  the authoring input reader.
- All 130 manifest positives and 67 original refusal checks passed with the
  native authority. The qualifier freshly compiled 112 sources and compared
  unchanged source images with the independent completed D13 installation.
  The complete mode-9 map matched the independent captured source-pin map.
- Exact parsing of all 16 generated installation DAGs found zero Python or
  Rust source captures. All captures belong to the explicit native authority.
  The 41 old raw Python captures were removed from the identity DAG; the other
  15 DAGs were byte-identical.

The tests above qualify the parameterized native identity and manifest
components. The final authority, full source-only release, and final install
remain separate integration gates. The candidate count is evidence of the
larger source-map path, not a hardcoded final release count.
