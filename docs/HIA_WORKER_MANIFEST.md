# Native Worker manifest framing

`source_worker_manifest.hepta` is the HIA owner of the deterministic helper,
report, scheduler and continuation-pack records needed by the Worker installer.
It accepts captured bytes, emits canonical record bytes, and has no filesystem,
Python, JSON-library, subprocess or external-compiler callback. Filesystem
custody, image construction, source admission and publication belong to the
installation owner that supplies its inputs.

## Request and output

The native generic-kit executable is invoked with the sole argument `build`.
Standard input is `HIAWMF01`, three little-endian unsigned 64-bit words
(`mode`, `role`, `piece_count`), then `piece_count` length-prefixed byte strings.
Each prefix is one unsigned little-endian 64-bit length. The final piece in
every request is the exact checked-in `worker_manifest_tables.hiastd` file.
Trailing bytes, empty pieces, unknown records and incorrect argument frames
are rejected. A successful request exits zero and writes exactly the record;
rejection exits 16 and writes no bytes. No partially framed record is emitted.

`HIA_WORKER_MANIFEST_RECORDS.json` lists every role, ordered input piece,
output path and source dependency. Its 130 records are:

| Mode | Roles | Result |
| --- | --- | --- |
| 1 | 37 helper roles, in the declared installer order | Individual image manifests |
| 2 | 0 | `helpers.json`, including eight Store-relative paths |
| 3 | 1 policy, 2 wire | Individual Worker report manifests |
| 4 | 0 | `report/manifest.json` |
| 5 | 0 | `report.json` |
| 6 | 72 global scheduler unit roles | Individual scheduler image manifests |
| 7 | Five scheduler families in `FAMILIES` order | `policy/manifest.json` |
| 8 | Five scheduler families | `inprocess-manifest.json` |
| 9 | 0 | `schedulers.json` |
| 10 | Five scheduler families | Exact `HIACTPK1` continuation pack input |

The five families are execution observation, Core lowering, Core emission,
byte wrapping and machine object construction. A family's unit order is its
pool first, followed by its admitted ABI unit order. Global mode-6 role numbers
continue across families; they do not restart at one.

Source, compiler and flat image inputs are individually bounded to 1 MiB.
An in-process aggregate can be up to 64 MiB, while the complete request must
also fit the generic kit's 64 MiB input limit. The implementation requires at least
1,114,112 bytes of workspace. A source inventory has at most 4,096 rows and 1 MiB
of encoded bytes. These are existing bounded native interfaces, not relaxed
compiler limits.

## Binding and validation

The HIA program computes SHA-256 over the final tables piece before selecting
or interpreting a record. The expected digest is embedded in the HIA source.
The tables contain literal format data, source paths, record operations and
validation descriptors; they are not executable host code. Source and table
must be admitted together by the enclosing source-capture owner.

Image manifest hashes are computed from the complete input source, image and
compiler bytes. Child manifests must match their exact canonical record
shape: sorted keys, two-space indentation, lowercase hexadecimal digests and
one final newline. A copied hash is not accepted as proof that a supplied
image was produced by a particular source. The installation owner performs
that independent source build and custody check.

The helper bundle and report bundle require consistent child compiler
identities. Scheduler policy bundles bind the exact source ABI and the actual
compiler bytes. Aggregate manifests bind their canonical policy, compiler,
actual aggregate image, and required source inventory entries. The existing
`HIAINP01` header, extent and version fields are checked before an aggregate
manifest can be emitted. The outer scheduler bundle requires all five child
aggregate manifests, consistent compiler pins and the complete declared
top-level runtime source set.

The source inventory format is `HIASPI01`, an unsigned 64-bit row count, and
rows containing an unsigned 64-bit path length, 32 raw SHA-256 bytes and the
ASCII relative path. Paths must be strictly sorted and unique. Empty,
absolute and traversal paths are rejected. Required entries are found by
bounded binary search. Missing entries are an error; there is no fallback
hash or filesystem lookup.

Mode 10 uses the original continuation pack ABI: nine header words, unit
lengths, sorted mode-number/arity pairs, then policy, pool and unit images.
Its bytes are independently compared with the original `pack_input` function.

## Reproduction and qualification

`python -B -m tools.generate_hia_worker_manifest --check` reproduces and checks
the HIA source, tables and complete record inventory. The Python generator is
an authoring tool; the emitted program evaluates all framing and validation
operations in HIA at runtime.

The generic native release kit constructs the executable from the three
`HIAKIT01` members `source_build_policy.hepta` (the framer), `selfhost.hepta`
and `source_build_packer.hepta`. The result is a native ELF, invoked with
`build`. The framer's standalone executable and table are then passed to the
native installation owner as admitted capabilities and captured data.

Run the external qualification driver with explicit paths:

```sh
python -B -m tools.qualify_hia_worker_manifest \
  --source /absolute/source \
  --worker /absolute/qualified-worker \
  --compiler /absolute/B3.image.bin \
  --executable /absolute/hia-worker-manifest \
  --source-builder /absolute/hia-source-build \
  --output /absolute/new-qualification-directory
```

The driver independently uses an existing qualified Worker's manifests as
the formatting authority and the original continuation `pack_input` as the
binary framing authority. It freshly compiles 112 HIA inputs using the
supplied native builder and compares every unchanged input's resulting image
with the installed image. The framer itself runs with an empty `PATH`.

The complete component qualification covers 130 successful records and 67
refusals: incorrect framing, argument count, modes, roles, piece counts,
table digest, canonical child shape, cross-compiler identity, ABI digest,
aggregate header/extent, inventory completeness/order/uniqueness/traversal,
and byte limits. Every refusal requires status 16 and empty stdout/stderr.
Executable, source, table, builder and compiler pins are reread at completion.
Failure inputs and outputs are retained by the external driver.

These checks qualify this framing component. Complete Worker installation,
public-call parity, original regression gates and legacy retirement remain
separate acceptance obligations.

