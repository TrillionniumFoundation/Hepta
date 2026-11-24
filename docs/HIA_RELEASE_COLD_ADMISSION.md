# Native cold replay admission

`source_release_cold_admit.hepta` admits the cold replay report for the native
source release owner. It is a HIA policy in the existing native leaf transport.
The installed command is `hia-release-cold-admit build`; its input is binary
stdin and its successful stdout is exactly 48 bytes.

This component checks a report. It does not run the cold replay itself.
A successful synthetic fixture in the qualifier proves component behavior,
not successful qualification of a source tree.

## Required custody

Before calling this policy, the owner must capture and seal the exact cold
report, support contract, full source inventory and compiler image. The compiler
pin in the request must be independently computed from that sealed compiler.
The owner must perform the native full source AUDIT against the inventory before
admission and again before the final publication, preserving the admitted root
descriptor. This policy is deliberately a pure byte operation and cannot replace
those filesystem checks.

The complete path set and its cardinality are compiled into the HIA policy.
Consequently removing the same source from the inventory, contract and report
does not create an admissible smaller source set. Content pins are supplied in
the audited inventory and compared exactly across all three representations.

## Request

All integers are unsigned little endian 64 bit.

| Offset | Meaning |
| --- | --- |
| 0 | Eight bytes `HIACLD01` |
| 8 | Cold JSON byte length |
| 16 | Full source inventory byte length |
| 24 | Support contract JSON byte length |
| 32 | Raw 32 byte independent compiler SHA-256 |
| 64 | Cold JSON, inventory, then support contract JSON |

The inventory begins with eight bytes `HIASPI01` and a source count.
Each row is a path length, raw 32 byte SHA-256, then that many path bytes.
Paths must be strictly sorted ASCII relative paths with safe nonempty
components. Empty components, dot and dot-dot components, absolute paths,
duplicate paths, NULs and non-ASCII bytes are refused. Components use only
letters, digits, dots, hyphens and underscores. The count is 1 through 4096.

The support contract itself is included in this inventory. Its raw JSON bytes
are hashed and checked against that row. Its source identity map must equal
all other inventory rows. The cold report source manifest must equal the
entire inventory.

## Admission

An optional UTF-8 BOM is accepted only at the beginning of the cold report, as in the original byte-level JSON reader. The sealed report bytes are not rewritten.

The report must have the original cold replay schema and current profile,
status `COLD_SELFHOST_REPLAY_PASS`, an integer zero return code, exactly the
original eleven check names with literal true values, and exactly three compiler
generation hashes equal to the independently admitted compiler hash.

The entire normative support contract is compared, including fields outside
the source identity map. Object order, JSON escaping and last duplicate key
semantics do not change meaning. The source identity map is checked separately;
the remaining canonical metadata is bound by a compiled SHA-256.

The original contract comparison uses structural numeric equality. The HIA
implementation preserves boolean/integer equality and integral floating point
equality, including decimal-to-binary64 rounding and underflow, using the
existing HIA integer arithmetic conversion. Integers retain their exact decimal
value and are not rounded through binary64. Thus a rounded large floating point
value cannot silently equal a distinct 64 bit integer. The cold report return
code and check booleans retain their stricter original type checks.
Nonfinite values can occur in ignored report observations as with the original
JSON reader; they cannot satisfy any required field or normative contract value.

The input is at most 64 MiB. The JSON tape has at most 262144 nodes and nesting
at most 1024; canonical metadata is at most 16 MiB. The existing leaf output
and workspace buffers provide the required 32 MiB and 2 MiB respectively.
These are admission limits, not changes to compiler limits.

## Receipt and failure

Success emits eight bytes `HIAADC01`, the raw compiler SHA-256, and the source
count. No additional stdout is allowed. Refusal exits with the existing native
leaf invalid-input status and no receipt; insufficient capacity uses that
transport's capacity status. The finalizer may publish only after this receipt,
the owner stage gates and both full source AUDIT passes succeed.

## Reproduction

Regenerate with
`python3 -m tools.generate_hia_source_release_cold_admit`.
Use `--check` for an exact source check. The generator is an authoring tool;
the installed command does not invoke it. A source catalog or normative
contract change requires regeneration of the policy constants and a fresh
cold replay for that resulting source tree.

The portable external qualifier is
`python3 -m tools.qualify_hia_release_cold_admit --image IMAGE --compiler B3 --output EMPTY_DIRECTORY`.
It executes the actual native ELF with an empty PATH and compares acceptance
with the original admission code. Use `--trace` for process tracing.
The matrix covers valid reordered and escaped JSON; missing, extra and changed
source pins; coherently truncated inventories; wrong full contract metadata;
wrong compiler generations; malformed wire framing; return-code/check type
rules; and integral, rounded, underflowing and nonfinite numeric boundaries.

The fixture construction and reference comparison are external test code.
They are not installed runtime fallbacks, and their synthetic successful
reports must never be substituted for a completed cold replay.

The native cold-report decoder preserves Python byte-JSON surrogatepass behavior for the report only, including ignored observations containing lone escaped or raw UTF-8 surrogates. Contract JSON remains strict, and schema, checks and source pin comparisons are unchanged.

The cold-report parser also accepts UTF-16 LE/BE and UTF-32 LE/BE with or without an initial BOM, according to the original byte-JSON encoding detection. Native tagged logical token offsets remain disjoint from the physical frame, inventory and strict UTF-8 contract; no report bytes are copied or rewritten for admission. Misaligned code units and out-of-range UTF-32 scalars are rejected. The report-only surrogatepass policy is preserved.
