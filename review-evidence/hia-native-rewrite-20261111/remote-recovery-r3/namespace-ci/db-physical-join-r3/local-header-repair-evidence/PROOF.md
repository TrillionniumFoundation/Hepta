# DMS8 bounded pure-read authoring revision

This revision fixes the actual role-4 profile failure from run 43154093882,
job 130969885094. The original generated document is 1,129,022 bytes with
SHA256 `e726927fe28cd72744778f2ae91ae616a205efcf95eac5516de192018b95e037`.
Its profile is 72 functions, 1,866 blocks, 6,852 operations, 234 maximum blocks
per function and 12 maximum block parameters. Only the total block gate fails.
The original failure and its authoring source remain preserved.

The new document has 72 functions, 1,524 blocks, 6,956 operations, maximum 142
blocks per function and 12 maximum block parameters. The original profile gates
remain 128 / 1,536 / 8,192 / 256 / 16. All 72 original functions, signatures,
effects and entry names remain. The complete 70,707-byte DSL is unchanged,
SHA256 `7fe09da5b8d59c14d1b5cd6fbc65b4c937677e410356d843a74affc62770d310`.
The HIA source and resulting image intentionally differ; no byte-identity claim
is made for compiled code or instruction counts.

## Why the additional expressions are total

The existing exact 0ef Builder already converts Boolean short circuits and
select arms to eager scalar operations when every expression is proven total.
The local subclass supplies additional facts only for this exact pinned DSL.
It does not change any runtime condition, error, write, call dispatch or quota.

The public image entry is the first function, `dms_entry`. Its first branch
rejects a workspace shorter than 8,192 bytes before any later header read. It
sets the poison word only when the first eight bytes exist. The source-length
branch remains short-circuited: none of `read64` or `dms_read` is newly total in
`dms_entry`. No source-taking helper is reached until the source has at least
320 bytes. Early workspace rejection helpers have no source parameter.

The exact source digest binds these guards, the reader bodies, the complete
call graph and the absence of buffer rebinding or resizing. A separate static
fixed point propagates the original input, output and workspace identities
through every buffer argument at every direct call. Buffer arguments must be
unchanged formal names. Rebinding, keywords or an unknown buffer expression
fails the proof. A generic helper whose `w` can actually be output is not given
the workspace bound. Only a proven original workspace gets constant `get`
offsets 0 through 8,184, whose final byte is at most 8,191. Only a non-entry
function receiving the original input gets constant `read64` offsets 0 through
312, or `dms_read` offsets 0 through 248. The latter adds 64, so the final byte
is at most 319. Dynamic offsets and output reads retain the original treatment.

`dms_length(s)` is total independently of source length or source origin. Its
entire pinned body is `return length(s) - 64`. The exact Builder emits
`buffer.len`, a wrapping cast to u64, and `int.sub.wrap`. Thus even source sizes
0 through 63 yield a defined modulo-2^64 value. There is no buffer load, write,
allocation, checked arithmetic or conditional trap. Marking this expression
total at the entry does not mark the adjacent header loads total and therefore
does not remove the short source guard.

The added shift rule requires both a total left operand whose actual Builder
type is u64 and an integer literal shift count from 0 through 63. The exact Core
interpreter rejects a checked shift only when the count is outside the operand
width. A left shift otherwise wraps the shifted value to that width; it does
not trap because high value bits are discarded. A u64 right shift is also
defined for every allowed count. The type test prevents applying the 64-bit
count bound to a u32 operand. Counts of 64, unknown counts and non-total left
operands retain their original treatment.

Each newly eager read is therefore in bounds and has no side effects. Earlier
Boolean values still determine the same result. The extra reads cannot change
workspace, outputs, first rejection reason or source bytes. Eager select arms
are evaluated after the original condition, and both arms are independently
total. VM step counts and internal read counts may differ; they are recorded
separately and are not masked into an equality claim.

These are properties of the private f0 ABI. Internal helpers are not newly
published entry points. The proof does not authenticate arbitrary externally
supplied workspaces or issue namespace capabilities.

## Actual evidence and remaining gate

The new source was compiled by the exact previously qualified B3 image
`35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b`.
The original disposable child, 10 CPU seconds, 20 wall seconds, 256 MiB address
space and 1 MiB output/workspace were used unchanged. The new image is 616,759
bytes, SHA256 `6996d832efd0e8458da9d98b5343fcab2d6e0b81084893c92f1eafdec3c1117e`.

The main differential runs the old document in the retained VM, the new
document in the same VM, and the new actual HIA image on identical complete
inputs, output preimages and workspaces. All 564 cases passed. The actual FS
seed initialization image issued the complete initialization ACK for the
positive continuation. The main corpus covers all source lengths 0..319,
short workspace/output boundaries, full ACK header mutations, every 70 constant
workspace offsets used by the source, page boundaries and fixed-seed multiword
mutations. A separate continuation corpus records permanent poison after a
rejected call and the short-workspace poison behavior. Each corpus keeps all
original bytes in its gzip ledger and retains full result, source and image
identity before and after. Source memory is read-only and both sides of each
logical native buffer have checked canaries plus outer guard pages.

The first local build attempt had zero B3 entries because the recovered
103-file import closure omitted the separately executed original child file.
That failure remains. A new 104-file exact 0ef dependency directory adds the
original child, verified by Git SHA; it does not alter the shared 103 files.
The second attempt generated and compiled successfully. Earlier diagnostic
script failures remain separate and are not rewritten as passes.

This evidence is local component development. It does not complete ordinary
AgentStore, SQL31, migration, unixOpen or the complete six-role physical join.
The updated CI launcher retains every original 18 physical test, all 33 actual
HIA packer controls, six fresh role compiles, complete original trace replay,
the per-ELF 90 CPU / 180 wall / 1 GiB limits and all zero-anomaly assertions.
No earlier physical result or native count is inherited.
