# HIA artifact-page ownership and Worker custody

The ordinary HIAAgentService._hia_read dispatch admits an explicitly selected
HEPTA_HIA_ARTIFACT_PAGE_MANIFEST. HIAAPG02 policy and JSON-wire images are bound
to their installed HIA sources and the same physical compiler. Admission
failure has no retained-owner fallback. The complete original page method
remains separately named _reference_hia_read, with a whole-source fixture and
an AST comparison permitting only that rename.

## Native decisions and foreign effects

The policy owns the original operation order: artifact lookup; cursor presence,
lookup and exact artifact ID/SHA checks; offsets and limits; whole-artifact
UTF-8 classification; page trimming and base64; three ordered wire invocations
for each budget attempt; the original 230000-byte combined wire budget;
canonical cursor digest; insertion instruction; and the result graph.
SQL method binding precedes the original query argument observations.

The public artifact limit remains 64 MiB and page limits remain 512 through
65536 bytes. Original private zero/small-limit and signed SQLite offset cases
remain in the differential corpus. NULL, REAL, TEXT and BLOB offsets preserve
the original operation and interpreter exception. The HIA result graph keeps
the original artifact object reference.

The adapter uses existing NativeStoreConnection.cursor_lookup and
cursor_retain capabilities for the admitted native Store. Legacy SQLite
effects retain their binding and argument order. The actual native-Store test
forbids its SQL-compatibility _execute path and performs insertion, lookup,
close and reopen.

Every foreign effect permission is consumed once, before the effect. A real
foreign exception receives the explicit terminal exception acknowledgement;
the original exception object is raised. Native state terminates, preventing
a repeated SQL operation. A malformed acknowledgement after a real insert
remains UNKNOWN, with no automatic retry.

The Page uses its admitted HIA wire image. Independent formatter and wire
selectors retain their original observation order. A selected wire is
re-admitted; an existing Worker wire must have the same complete
schema/source/image/compiler identity. Virtual wire results, base64 and cursor
digest are HIA decisions. Opaque object access, admitted database/file effects
and mapping retain explicit host boundaries. This component gate does not
replace separate Store/durability or whole-Worker gates.

## Component construction

python -m tools.build_hia_artifact_page --output NEW --compiler B3 --cold-report COLD
requires a completed source-matching cold campaign. It checks the real report,
generation index, all three physical compiler images, exact B3 bytes, native
source map and separate Git-bound authoring inputs. Actual compile receipts,
full output framing, source/image bytes and all published files are reread
at the terminal boundary. Images, leaf manifests and bundle are created
exclusively in a private directory with mode 0600.

The explicit --development alternative cannot establish matching-cold
qualification. The development results below use the retained 04fe compiler
only as a compiler input, without transferring its old qualification.

The policy five-field schema is hepta.hia.artifact-page-native.v2; JSON wire
keeps hepta.hia.json-wire-native.v1. Their child bundle schema is
hepta.hia.artifact-page-bundle.v2. The policy-only adapter admits the exact
same five-field contract as its actual emitted manifest.

## Worker composition

hepta.hia.artifact-page-worker-bundle.v1 wraps an admitted v1, v2 or v3 base
and the Page bundle. It captures base and Page/Wire inputs before mapping.
Nested Page wrappers, partial schemas and unknown schemas are rejected.
Full source/image/compiler identity and owner process/thread are rechecked
after mapping and throughout the scope. Callers use the captured Page and
Wire objects.

The closed scheduling sequence is Store -> Core companions -> Page -> v3.
Core is optional and uses separate typed eight-field manifests. Page passes
that exact typed companion to v3. The v3 base must already declare the same
Wire selection, and full selection-map equality remains enforced. Page's
companion check rereads its own inputs without recursively validating its
base again.

The generic extension uses roles 14 (Page policy) and 15 (JSON wire) under
HIAHLM02. Original HIAHLM01 roles 1 through 8 keep their independent boundary.
Actual installed central manifests and image bytes must equal the independently
rebuilt Page outputs before the Worker wrapper is published.

The native Page manifest owner uses HIAPMF01/HIAPMT01. Its four records produce
the policy leaf, wire leaf, Page bundle and wrapper around actual scheduler
bytes. The native Worker recipe invokes that owner and publishes both real
images and leaves before passing the Page wrapper to the existing binder.

The current Worker owner uses HIAWMF02/HIAWMT02, retaining 37 original ordinals
and appending four generic helpers for 41. The separate current qualifier has
134 positive records and preserves original negative cases and child budgets.
The original 130-record qualifier, WMF01 owner and table remain unchanged.

Current generation declares its actual source domain. Hosted component
inventory and final native authority are distinct inputs. The exact
generated-file check reads the declared domain, replays it and rereads the
specification and authority. Final native freeze must regenerate with the
actual reviewed native source inventory.

## Original gates and actual evidence

tests.test_hia_artifact_read_native accepts the cold-report environment or the
mutually exclusive explicit development manifest. Its original 11 methods
retain all 42 vectors, SQL binding/errors, close/reopen, one-shot controls,
independent Core execution, source/image refusal, and a real wheel child
running -I -S -B with empty PATH and no checkout import path.

tools/qualify_hia_artifact_read_callers.py runs all five original caller
modules. It records loaded/chosen/executed IDs, all five unittest anomaly
classes, real native entries/returns, all eleven Agent tools, forbidden-owner
entries and before/after source/bundle identities. A real native hia_read
entry is required. Other tools retain their independent responsibilities.
The full Page build-input closure and five original caller files are captured
before admission and reread after execution.

| Actual run | Source and scope | Observed result |
| --- | --- | --- |
| Linux v1 | 2daf0375, development | Original 11 methods and 42 vectors all passed |
| Linux v2 | 85ad24d1, development | Original 11/42 passed again; all 69 callers ran with one strict source-contract error before final freeze |
| Linux v2 Worker controls | 85ad24d1 | Admission rejected group-writable test artifacts; failure preserved |
| Linux v3 | 3943b381 | Actual isolated wheel case passed; Worker source-mode refusals preserved |
| Linux v4 | Same 3943b381 bytes, verified Git modes | All 10 Worker/native-Store controls passed, including four native manifest records and fourteen malformed-frame refusals |
| Joined Core/Page source gate | 0a27f523 with recorded hosted current-table regeneration | All 77 source/typed controls passed; 8,156 source files unchanged; mapping doubles do not establish native execution |

All four Linux attempts, including failures, are preserved in a complete CAS
archive: 7,151 logical members, 6,590 physical files, 609,324,942 original file
bytes and 881 unique blobs. The ROG data-volume and Mac copies were separately
read and every blob and logical byte/mode mapping verified. No original
working output was removed.

The full 69-caller gate remains incomplete: its recorded error is strict
source-contract refusal before final source freeze. The current 134-record
native qualifier and merged Core/Page/v3 native scope require actual current
inputs. Final cold, release, install, installed rebuild and public Worker
qualification remain separate.

The older experimental page run remains five observed passes and 37 unknown
cases after continuity loss. New complete passes have independent identities
and do not relabel or replay those unknown operations.
