# Native static impact analyzer — development revision 1

Status: **unexecuted source**. No AST generation, B3 compilation, VM or native
entry has been performed for this revision at publication. The selected CI is
the first execution. Prior component or cold results are not inherited.

## Exact obligation and boundary

Reference: commit 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5,
hepta/hia_patch_impact.py, blob 0d270c59bcf6f844dd8fe4e48f67ce8722362474,
8,527 bytes, SHA256
b61710dc320c4b65206a2e6efed67ac525e900a782886be6c289e8acc681e3a1.

The ordinary observer first admits the original, calls the complete ordinary
patch operation, admits the candidate again, and compares all canonical bytes.
Those operations remain mandatory coordinator obligations. This component
starts after them. Its immutable inputs must be actual admitted values, the
actual issued patch receipt and the original admission's input identity.

The component owns the remaining complete observer semantics:

1. Strict v1/v2 receipt field sets, exact Boolean identities, positive integer
   edit count, status/domain and three input identities, in original order.
2. Both complete function inventories, the 1,024-function bound, unique string
   identities and refusal of removed declarations.
3. Full canonical function comparison and exact name/params/returns/effects/
   defaulted return-loans interface comparison.
4. Exact sorted interface-change receipt, original migration-policy claims and
   legacy interface refusal, before either call-graph scan.
5. Closed calls in every old and new function/block/operation, deduplicated
   separately. A union of their reverse edges drives a finite work queue.
6. Complete sorted direct, interface, potentially affected and unaffected
   function lists, complete sorted old/new edge lists and all eight original
   claims.
7. The actual complete canonical before and after hashes and the actual report
   hash, computed by HIA SHA-256. The report hash excludes its own sha256 field.

This component's success is not an admission capability or patch authority.
The claims in its private result may be published only after the enclosing
native coordinator has completed the real prerequisite calls and bound the
borrowed values to those calls. No hash equality waives semantic admission.
No native ordinary CLI/patch/impact activation is claimed here.

## Pure private ABI

Entry borrows R / W / W. Source is the exact integer JSON transport:

    [admitted_original, admitted_candidate, issued_patch_receipt, actual_original_input_sha256]

The first view stays immutable through every retry. The component is stateless
between entries: every GROW retry fully decodes and computes from that same
source. The fixed parent owns source lifetime and lease correlation; it must
not accept a different source on retry.

Output and workspace each need at least 128 bytes. Transport measurement counts
tokens and peak containers only to reserve physical space. It does not run raw
public Core limits or authorize either Core. The private frame bound is
25,167,872 bytes, sufficient for two original <=8 MiB Core values, an internal
<=8 MiB receipt and framing/identity. Decoder duplicate keys, strict integer
grammar and UTF-8 rules are retained. Its capacity bounds are measured from
this private transport; public Core gates are not changed.

Workspace contains the full lossless decoder arena followed by aligned private
scratch. Relative to scratch: SHA state at 0..1119; actual before/after/report
digests at 1200/1232/1264; control at 2048; two sorted function arrays at
4096/12288; 32-byte union rows at 20480; old/new 1024x1024 bit matrices at
61440/192512; and the 1024-entry reachability queue at 323584. Total private
scratch is 331,776 bytes. No pointer or external object is retained.

The output starts with sixteen little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0..1 | HIAIMP01, version 1 |
| 2 | 0 report; 1 GROW; 2 original semantic refusal; 3 private ABI refusal |
| 3 | Semantic/private reason, or zero |
| 4..5 | Required output and work capacities |
| 6..7 | Report offset 128 and complete report byte count, or zero count |
| 8 | Admitted candidate function count |
| 9..10 | Exact distinct old/new edge counts |
| 11..13 | Direct/interface/affected counts |
| 14..15 | Zero |

Only a successful report carries the count fields. Return 128 is report or
semantic refusal, 0xfffffffe is GROW, and 0xfffffffd is private refusal.
Every report byte is within the actual output view.

Errors 1..8 are the exact original E_HIA_IMPACT strings in MESSAGES. The earlier
"patch output changed after validation" error remains the coordinator's real
canonical-byte equality check. Foreign malformed transport is a private
refusal, not a replacement for a public parser's diagnostic.

The report has no invented 8 MiB cap. Its exact length is measured and requested
before the final hash and second emission. The private SHA view permits the
actual allocated report through its 32-bit index range. Original before/after
Core still require their original full semantic and byte bounds. A large report
test specifically exceeds 8 MiB.

## First actual qualification

One fresh image is compiled using the unchanged 669,556-byte B3 image,
SHA256 35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b.
Compiler limits remain 10 CPU seconds, 20 wall seconds, 256 MiB, 1 MiB source
and output, 128 functions, 1,536 blocks, 8,192 operations, 256 blocks per
function and 16 block parameters. Excess requires splitting semantic owners,
not increasing this profile.

Six independent native test processes each retain 90 CPU seconds, 180 wall
seconds, 1 GiB and no core dump. Planned inventory is 104 cases:

| Group | Cases | Independent oracle/scope |
| --- | ---: | --- |
| semantic | 33 | Original actual patch on independently admitted Core v1..v8 |
| receipts | 44 | Original complete observer with an explicitly foreign patch-result fixture |
| private | 24 | Malformed internal transport and short ABI controls |
| graph-1024 | 1 | All 1,024 functions reached through the original closed chain |
| graph-dense | 1 | Complete 4,096-edge old and new graphs |
| graph-long-report | 1 | Complete 16,384-edge graphs with 128-byte names and report >8 MiB |

There are 36 planned actual reference-patch cases and 80 planned full original
observer calls. These are proposed counts, not results. Private fixtures are
never counted as actual native patch or Core admission.

Each actual entry freezes and saves the entire source, output/work before and
after, guard/canary observations, return code and timing in a durable ledger.
Expected full reports, receipt bytes and original/candidate canonical bytes
are retained separately. During the native interval Python Core/patch/impact,
JSON parsing/rendering and SHA dispatch are disabled. Every final report byte
is compared with the exact original report, including its SHA. All selected
reference, generated HIA and image identities are rechecked afterwards.

## Work still required

Actual component qualification, complete native ordinary patch semantics and
the real impact coordinator remain pending. Installed routing, publication,
general build, ordinary Worker and namespace are independent open obligations.
No production owner is deleted by this revision.
