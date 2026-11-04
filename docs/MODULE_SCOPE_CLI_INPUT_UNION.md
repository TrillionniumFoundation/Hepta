# Module scope and ordinary CLI input preservation

This is a test-only qualification extension over #669, head
`8a267f7287b5987a3f8b92302977bccbce9861b4`, tree
`5a32f37a678a2dfc299d0d15a051c653a11aeefe`. That base already contains the
complete #667 module-scope/package-context tree and exact #668 CLI
input-preservation correction. This increment adds only five integration
files: this document, the nine-method intersection suite, its frozen combined
inventory, runner and workflow. It changes no production or component files.

The inherited component sources are:

- #667 head `a4c075528de454b96f68d2e71103d5dc208d977d`, tree
  `0fd9e848a68799cec15adae482fcd8fddac71567`.
- #668 head `73ed4229bb95a8f8df208cbce0998de16016989a`, tree
  `d76074f26996b3290e7b1704ee3bdcc5e4066519`.

Their common ancestor is `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`.
In that inherited composition, the only production difference from #667 is
five added CLI protected-set
lines and two diagnostic strings from #668. Loader, binding, checker, package
snapshot and backend implementations remain unchanged. Both additions to
MODULES_PACKAGES are preserved. The original component documents and gates
describe their own historical scope. Neither their separate CI nor earlier
#669 checks establish the nine new intersection methods in this extension.

## Sequential behavior and diagnostic priority

The CLI consumes the project admitted by module loading and checking. Package
discovery and owner-lock verification precede graph traversal. Escape and an
active import cycle precede the completed-unit package-context check. Earlier
read, parse, C-import and lock errors retain their existing priority.

A module exception, including conflicting package contexts or a forbidden
module reference, occurs before an Analysis exists. A same-source generic
collision instead returns populated project/check data with check-phase
E_GENERIC_PARAMETER. In stable ordinary fixtures, either rejection retains
exit status 1 and its original report/diagnostic shape even when the requested
output names a protected input. The output guard must not mask that rejection
as a driver error.

Only successful validation reaches an applicable protected-destination
refusal: E_DRIVER, status error, exit 2. Existing content/header preparation
and earlier validation failures remain before the destination check. The
refusal prevents the destination write, final artifact build and its retained
debug publication. Normal native validation may already have invoked a
compiler. This does not claim that no compiler process ran.

## Exact ordinary-input boundary

The protected paths are the union of the loaded graph inputs, files in the
already captured package snapshot and the verified top-level owner lock:

- Loaded Hepta sources, loaded C-import sidecars and eligible in-package
  original headers retained in project.sources.
- Participating manifests, all captured .hepta files and present sidecars,
  including unimported files and owner-relative ../ dependency entries.
- The owner's Hepta.lock only when locked mode actually read and verified it.

Shared-module context consistency does not expand snapshot enumeration.
Dependency locks are not owner locks merely because dependencies participate.
A direct-source entry inside a nested package can discover a different owner
from an outer-package entry; tests assert the actual owner rather than
protecting every encountered lock.

Unlocked owner locks, unread dependency locks, unimported standalone siblings,
ordinary new/replaced outputs and stdout remain allowed. The input set does
not include arbitrary foreign link inputs or the full native compiler
dependency closure. Low-level backend APIs and unrelated migration/import
commands are unchanged.

## Known filesystem limits are not repaired here

This composition's qualification scope is limited to stable ordinary paths
and regular-file fixtures. It does not provide atomic observation or
transactional publication.
The existing post-validation unchanged() check does not pin files or the owner
lock through later output selection and writing. Changes can occur between
validation, resolution, protection comparison and publication.

There is also an existing default-build output gap: an explicit -o is resolved
before the CLI guard, but the default build path is compared before the native
backend resolves it. A default-output file symlink can therefore resolve to a
protected input after that comparison. This known issue requires separate
repair and qualification; no such repair is included in this exact tree.
Graph paths are not all normalized uniformly, and path equality is not an
inode/samefile check. Hard-link preservation is not established either.

Do not interpret ordinary default-output controls as symlink or hard-link
qualification. Do not describe this candidate as universal physical-file
preservation, filesystem security, concurrent-mutation protection or complete
native-input isolation.

## Frozen test composition

The #667 inventory contains 502 methods and #668 contains 54. They share
31 identities: 28 module tests and three C-backend tests. The deduplicated
inherited floor is **525 methods**. The additional CLI-only identities are
15 input-preservation methods, four debug-info methods and four source-map
methods. None of those controls is dropped.

Nine new intersection methods make **534 unique combined methods**.

The new runner keeps #667's whole-module selections and adds only the three
missing modules plus the new intersection suite. It does not append #668's
three individual C-backend selectors, which are already covered and would
otherwise run twice. A checked-in ordered inventory rejects missing, duplicate,
reordered or same-count substituted identities and verifies that both original
component inventories remain present.

Focused intersections exercise valid aliases/diamonds and nested generic/local
bindings reaching protected and ordinary outputs, package routing and actual
owner identity, diagnostic precedence, C-import versus snapshot membership,
allowed overwrite compatibility, debug output, and finite native results.
Every refusal checks fixture bytes, file/directory inventories and absence of
final output publication. Methods and nested subtests are recorded separately.

## Qualification contract

The dedicated 534-method gate uses this extension's exact new head/tree and
physical compiler checkout
on Linux x86-64 and AArch64, actual GCC and pinned Rust 1.90.0. Planned,
executed and passed method IDs must equal the frozen ordered inventory, with
zero failures, errors, skips, expected failures or unexpected successes. Source,
tool, input/generated-source and artifact identities accompany observed native
results. Normal CLI builds use O3; no O0 or UBSan claim is inferred for them.

Missing local Rust is disclosed as incomplete local qualification, never a
stub compiler, passing result or relaxed assertion. Existing component gates
remain intact. All results must belong to the new combined source; neither
component greens, earlier #669 checks nor inherited tests alone establish
the new intersections.
This work adds no recursive execution, worker-lifecycle, resource-accounting
or whole-language soundness qualification, and requests no merge or deployment.
