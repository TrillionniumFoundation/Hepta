# Native self-host contract metadata

## Operative metadata and historical evidence

`HIA_NATIVE_SELFHOST_METADATA.json` is the static metadata input to the native
source-contract producer. Its `source_identity.files` object is empty by design:
the native build captures the admitted source files and supplies their actual
pins. No source digest is invented for a missing file.

The metadata migrates 26 production path or command fields and six source
identity roles to the native build and runtime sources. Thirty old qualification
or oracle references reside in the single
`HIA_HISTORICAL_QUALIFICATION_PROVENANCE.json` record. Those entries identify
historical evidence; they are not filesystem dependencies of the current build.
`HIA_NATIVE_SELFHOST_METADATA_MIGRATION.json` records each changed field and the
immutable source contract from which it was derived.

The migration preserves all original numeric and Boolean leaves, the full
limits, ABI, support, syntax, profile, compiler-symbol and capacity-derivation
objects, and the original fixed-point and mutation equations. Hosted-boundary
statements and conservative qualification flags remain in force. Changing a
path binding does not qualify an untested hosted API or establish whole-product
completion.

The final source authority remains an explicit relative-path catalog. It must
include the actual HIA sources, readable mechanical assembly, native recipes,
source pools and qualification plans needed by the selected product. This
metadata does not derive that catalog by scanning Python or Rust suffixes.

## Captured manifest projection

`examples/hia_bootstrap/source_contract_manifest.hepta` projects the source
capture manifest into the existing source-pin inventory. It has the ordinary
six-word pure entry ABI: input pointer and extent, output pointer and extent,
and workspace pointer and extent. Workspace is unused. The ordinary native
filter packer supplies the command-line transport; it takes `HIAFLT01`, a
little-endian flat-image length, and the flat image.

Input layout:

| Field | Encoding |
| --- | --- |
| Magic | Eight bytes `HIASXM01` |
| Record count | Little-endian u64, 1 through 4096 |
| Version | Little-endian u64, exactly 1 |
| Reserved | Little-endian u64, exactly 0 |
| Each record | Path-byte length u64, captured file-byte length u64, raw SHA-256 (32 bytes), path bytes |

Output layout:

| Field | Encoding |
| --- | --- |
| Magic | Eight bytes `HIASPI01` |
| Record count | Little-endian u64 |
| Each record | Path-byte length u64, unchanged raw SHA-256 (32 bytes), unchanged path bytes |

The projection validates complete input extent, sorted unique relative paths,
the source-contract ASCII alphabet, 1 through 4095 path bytes, components of at
most 255 bytes, and captured file sizes from zero through 64 MiB. Empty, dot,
dot-dot, `.git` and `__pycache__` components refuse. The closed manifest profile
also refuses an all-zero digest. Input and output are bounded by the existing
8 MiB budget. All lengths use checked subtraction before access. The first
pass validates the complete packet and output capacity; refused input and
short output leave the output view unchanged.

The converter strips the size field and preserves the actual SHA and path. It
does not reopen files, rehash source contents or replace the upstream stable
capture and custody checks. Success returns the exact output byte count.
Malformed input returns `0xffffffff`; insufficient output returns `0xfffffffe`.
The native filter transport converts refusal into nonzero exit status with no
published output.

## Existing native producer and frozen source

`examples/hia_bootstrap/source_contract_generate.hepta` consumes:

```
HIASCG01 | metadata_bytes:u64 | inventory_bytes:u64 | reserved_zero:u64
         | metadata JSON bytes | complete HIASPI01 inventory
```

The producer preserves the metadata outside `source_identity.files` and fills
that object from the admitted inventory. It requires exactly one inventory
entry named `docs/HIA_SELFHOST_CORE_SUPPORT.json`, then excludes that self
entry from the file map. A missing self entry refuses. HIASXM01 must first pass
through the converter; changing the magic alone does not convert its records.

For a final frozen source, the build captures real files, runs the converter
and producer, and requires the result to equal the captured contract bytes.
Initial materialization may write a generated contract and capture that actual
file again; its self digest is excluded under the same producer rule. The
component qualification exercises this two-capture fixed point with an actual
file, not a placeholder digest. The final source count and whole-source fixed
point are established only after the final authority is assembled.

## Public build and qualification boundaries

The independent toolchain build uses exactly:

```
hia-cold-build --source ABS_SOURCE --bootstrap ABS_BOOTSTRAP --output NEW_ABS_OUTPUT
```

The complete cold qualification uses exactly:

```
hia-cold --source ABS_SOURCE --output NEW_ABS_OUTPUT --toolchain ABS_TOOLCHAIN --bundle ABS_DESCRIPTOR
```

The post-cold source bootstrap uses exactly:

```
hia-source-bootstrap --source ABS_SOURCE --cold ABS_COLD --bootstrap ABS_BOOTSTRAP --output NEW_ABS_OUTPUT
```

Its native entry consumes the captured `final-cold.json` and
`qualification/base/B3.flat` below the admitted cold directory. The post recipe
first performs strict report and source admission, then builds using that actual
qualified successor. This public entry replaces the development script as the
production source-bootstrap invocation; it does not create an independent
reference compiler or report the full workflow qualified before execution.

These are separate operations. Constructing the toolchain does not report that
the full cold qualification passed. The latter retains its original execution,
cleanup and replay budgets and its complete current-input native reference
checks.

Final build, authority, descriptor and capsule pins belong in external execution
receipts. A final capsule pin must not be written into a source document that is
itself captured by the authority embedded in that capsule. Static protocol and
source-binding documentation can remain in the source authority. Historical
component evidence has an explicit historical scope.

## Component qualification

The converter is built by the independent HIA assembly, reference-wire
projector, original scalar seed backend and native filter; no successor or B3
compiler supplies its implementation. The existing contract producer uses the
independently qualified unsigned-division seed profile. Qualification covers
all path bytes, complete truncation points, integer and count bounds, the exact
8 MiB input boundary, malformed records, unchanged output on refusal, actual
file capture, producer self-entry refusal, and the frozen generated-contract
fixed point. Development authors and external test drivers are not required by
the native runtime or the production recipe.

The component report is evidence for this transform and metadata migration.
Whole-native qualification remains false until the complete frozen source,
public build, cold run, final installation and installed rebuild have passed.
