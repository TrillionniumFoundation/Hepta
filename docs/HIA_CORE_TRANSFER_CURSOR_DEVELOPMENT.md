# Core transfer cursor qualification

The Core-admission cursor change has passed its component gates. It preserves
all four diagnostic transfer passes and their order, and replaces only repeated
head-to-index seeks over the same args/params arrays with advancing cursors.
The other 94 functions are unchanged. Reversing the cursor-only AST substitution
restores the complete original transfer AST.

The original 20 test methods are all covered with their assertions unchanged.
The first run passed 19 methods and all 2,887 fresh reference comparisons. Its
remaining strict-builder method correctly stopped at the candidate tree's stale
development source contract. A separate fixture froze the actual 3,011-file
closure through the original contract functions, passed that complete method,
and restored the development contract. The failed first run is retained.
The source and native suites include independent complete-VM observations,
complete diagnostic bytes and first-error ordering, old function/block/arity
limits, resource and returned-loan checks, selected-no-fallback behavior, and
diagnostic thread/reentry/refusal controls.

An additional 2,068 old/new native controls compare the return and every byte
of all three views, including canaries, with zero and poisoned scratch. These
cover resource joins, closure-before-predecessor diagnostic order, declaration
mutations, scalar edge arities, and undefined-value-before-type priority.

The exact original-admitted 8,386,496-byte Core input with 53,749 block parameters
previously remained CPU-bound after a 135-second observation. The new complete
normalizer returns its full 16,773,056-byte HIAVCF01 output in 9.082 seconds.
Four smaller inputs give byte-identical complete old/new results. The original
120-second public normalization transport limit remains unchanged.

All 21 normalizer components and mechanical template carriers were constructed
by the actual native source compiler and existing HIA embed/static-link tools.
Rebuilding the unchanged complete image reproduces the original 7d2bef SHA
byte-for-byte. Replacing just the Core leaf gives the 84619bd image. No external
assembler or linker is used in this construction. The candidate remains inside
95 functions, 1,424 blocks, 7,206 operations and 15 block parameters.

The companion JSON pins the actual sources, full images and reports. This
component qualification is not a final aggregate cold-build, installed-runtime,
or whole bounded-public-workflow qualification. Those gates consume the new
image with their own captured identities.
