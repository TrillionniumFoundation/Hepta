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

The production native report uses schema `hepta.hia.selfhost-cold-replay.v2`,
status `NATIVE_COLD_SELFHOST_REPLAY_PASS`, the current profile and integer zero
return code. All fourteen native checks must be literal true. The three original
compiler generations must equal the independently captured B3 hash; the three
modified generations must retain the distinct initial generation and the
separate, equal second and third generations.

The gate checks every one of the sixty source-bound phase plans, every retained
node count, successful return code, nonzero journal/archive identity, sealing
and cleanup receipt. Independent references must precede B0 and qualification
phases must follow it. All nineteen families require both original and modified
compiler results. The original 180-second qualification and three-second cleanup
limits remain binding, including measured elapsed times. Scheduler limits remain
two phase workers, one archive worker, two pending archives and four unsealed
phases; all actual peak counts are bounded. The independent observer bytes are
checked exactly. Required report objects and source maps reject duplicate keys.

The entire frozen native metadata is compared, including fields outside the
source identity map. Object order and JSON escaping do not change meaning.
The source identity map is checked separately; the remaining canonical metadata
is bound by a compiled SHA-256. The explicit native authority and frozen metadata
select this gate; hosted support-contract discovery does not determine its
source set.

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

Generate and check the production native-v2 policy with the same explicit
source authority used by the Worker and final source capture:

```sh
python3 -B -m tools.generate_hia_source_release_cold_admit \
  --native-source-authority docs/HIA_NATIVE_SOURCE_AUTHORITY.json
python3 -B -m tools.generate_hia_source_release_cold_admit \
  --native-source-authority docs/HIA_NATIVE_SOURCE_AUTHORITY.json --check
```

The flag dispatches to the complete v2 specialization in
`tools.generate_hia_cold_report_admit`. It checks that the frozen metadata retains
the complete native plan catalog, all fourteen checks and the original resource
and time limits. It refuses a divergent template instead of silently replacing
those constraints. The generator is a development author; installed builds
consume only the emitted HIA policy. A catalog or metadata change requires
regeneration followed by a new matching whole cold replay.

After actual source compilation and native packing, the component matrix is:

```sh
python3 -B -m tools.qualify_hia_cold_report_admit \
  --image NATIVE_V2_IMAGE --compiler B3 \
  --native-source-authority docs/HIA_NATIVE_SOURCE_AUTHORITY.json \
  --fixture --output NEW_COMPONENT_EVIDENCE
```

It runs the actual ELF with an empty PATH and checks all phase, family, check,
generation, observer, budget, scheduler, source, metadata and wire obligations.
Negative cases require the native invalid-input result and no receipt; a crashed
process does not pass a refusal case. A synthetic report is recorded explicitly
as component evidence and cannot prove whole cold qualification.

To admit an independently completed current-source replay, replace `--fixture`
with `--cold-report NEW_COLD/final-cold.json` and pass that same run's
`NEW_COLD/qualification/base/B3.flat` as `--compiler`. This mode first requires
the exact frozen current contract and the exact actual source inventory, retains
the original report bytes, and rechecks source/input custody after qualification.
It records actual report admission separately from whole replay execution.

## Retained hosted compatibility domain

Without `--native-source-authority`, the original generator and
`tools.qualify_hia_release_cold_admit` retain the v1 hosted report domain:
`hepta.hia.selfhost-cold-replay.v1`, `COLD_SELFHOST_REPLAY_PASS` and the original
eleven checks, including Python isolation. Keep its output separate by passing
`--output PRIVATE_V1_SOURCE` to the generator. Its original fifty positive and
negative cases remain available. The qualifier's optional native catalog
binding still tests v1 compatibility; it is not the native-v2 production gate.
Do not run the bare hosted generator over the final native policy.

Both qualifier programs are external test tools. Neither is an installed
fallback, and neither may substitute its synthetic report for a completed cold
replay.
