# Native type sessions and retained qualification observations

This directory preserves original observations gathered while preparing the
v60 native nominal type session. It does not grant whole-product native
qualification, delete retained owners, or promote earlier results to a later
source identity. `CUSTODY.json` records the complete original and retained
byte hashes. Files ending in `.xz` decompress to their original bytes.

## Type development

`types/types-development.tar.xz` contains the original three development
revisions, source/compile receipts, raw images and inputs, Core VM controls,
test logs and the actual pre-fix 8 MiB framing regression. Every archive member
was independently read back and matched to the custody ledger. The final r3
source is `28d5e1b6380ed5a22e24bcbb0e4ea2264e5344ed209d3c9ccd5388db52b2af98`;
its 442,630-byte development image is
`b123417efdb48fbb56856965a3a23483b4f0d3ec902db94bac4c6c94298e34d5`.

The final dedicated suite passed 18 tests in 51.375 seconds. Earlier exact
state/error/counter panels and the separate 59-case independent boundary audit
retain their original r2 identity. Two additional r3 raw-ABI controls exercise
the private byte limit and its first refusal, with all four boundary canaries
intact. These controls reuse an explicitly identified development compiler;
they do not replace fresh matching-source cold qualification.

## CI results retain their original identity

The `observations` records distinguish these outcomes:

| Source and attempt | Observed result |
| --- | --- |
| `95ba911`, first native attempt | Original 180-second cold timeout; completed-phase checks remain retained |
| `95ba911`, second native attempt | Complete cold and language passes; nine Agent setup errors because `jsonschema` was absent |
| `bfea47b`, source job | 229 tests passed in 390.236 seconds |
| `bfea47b`, first native attempt | Cold timeout; 32 completed phases / 3,718 true checks |
| `bfea47b`, only native retry | Cold timeout; index has 28 completed phases / 2,876 true checks; two additional complete scalar-cast reports add 736 checks but remain pending in the index |

The latter retry has 30 independently verified reports and 3,612 true checks.
It is still a failed cold qualification. The reused source job log is not a
second execution. All original owner results and cleanup observations remain
unchanged. There was no further blind retry or deadline increase.

## Independent remote and live observations

The remote preparation records distinguish an initial storage-inode HOLD from
the later READY result on a filesystem that meets the unchanged requirements.
They identify the actual tools, package versions and source-bound prerequisites;
historical prerequisite paths do not supply historical test passes.

The exact `95ba911` tree's full retained replay has its own durable job and
output directory. Only its eventual source-bound terminal record can establish
the full result. The preparation receipts themselves do not execute or qualify
the full suite. Original uncertain connector requests were reconciled by their
original IDs and keys, without replaying their effects under new keys.

The live HIA manifest and backend profile were obtained through issued artifact
references and their complete bytes were independently hashed. They describe
the live provider's advertised identity; they are not an independent audit of
deployed files or loaded processes. The catalog matches the recorded bfea
checkout, while advertised worker/backend digests differ and the backend says
`self_hosted: false`. No service, live worker or release pin was changed.

`local-v58-source-replay-timeout` remains a failed local workflow observation.
The separate returned-loan compiler audit identifies ten actual development B3
controls and does not misattribute the complete Core checker's fixed bug to
the source compiler, which already rejected those corresponding witnesses.
