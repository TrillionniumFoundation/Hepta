# Module scope with resolved default build aliases

This independent candidate preserves the complete #671 source and incorporates
only #670's default-build destination correction and associated controls.

- #671 head `385861d537827e4950fab5ed748dd8ae96dda18e`, tree
  `057a3864a4a150a0dfd15dd4a8d25a14a02b2910`.
- #670 head `f42339c297a781e23af671faa19981f7071df278`, tree
  `a514a793b1e877228ed40d8db6edb666c1eb5780`.

The sources diverge from #564. This candidate does not replace #671 with
#670's older module implementation. It carries the exact seven-file #670
delta onto #671, preserving all inherited scope, generic, package-context and
ordinary-input semantics. The only production difference from #671 is one
expression resolving the selected explicit-or-default build destination.

The original component inventories, runners and workflows remain unchanged.
MODULE_SCOPE_CLI_INPUT_UNION records the historical #671 qualification; its
five-file/test-only/534-method and unfixed-default-path statements describe
that historical tree. The default-path omission is addressed here by #670's
existing correction, with new intersection tests bound to this combination.

## Input boundary and sequential contract

The known-input set is unchanged: loaded graph inputs, the captured package
snapshot, and only the top-level owner's lock when verified in locked mode.
This includes eligible original C headers and loaded sidecars, plus captured
unimported package sources/sidecars. An unread dependency lock or unlocked
owner lock is not protected merely because its package participates.

Default output follows the actual analyzed entry. Directory, manifest and
nested direct-source entry forms can select different owners and routes.
The tests assert that identity rather than assuming the raw argument's
parent is the owner or output directory.

Package discovery and owner-lock verification precede graph traversal.
Escape, active cycle and completed-unit package-context checks retain their
existing order. Earlier read/parse/C-import failures retain their priority.
Scope/private errors remain module exceptions. Same-source generic
collisions retain a populated Analysis/CheckResult with check-phase
E_GENERIC_PARAMETER. These rejections remain exit 1 with their original
report shape, even if the selected output alias names a protected input.

Only successful validation reaches the build destination comparison.
Protected aliases then produce E_DRIVER, driver phase, status error, exit 2.
Native validation can already have invoked a compiler before that refusal.
The guarantee exercised is no final destination/artifact or retained debug
publication, not absence of every compiler process.

## Stable aliases and physical observations

The correction resolves explicit and default destinations before the existing
comparison. The new fixtures use ordinary stable symlinks inside self-created
temporary trees, including relative/absolute leaf aliases and a standalone
build-directory alias. Package source-directory aliases remain an earlier
E_PACKAGE_SOURCE_LINK rejection.

The intersection harness must not dereference aliases while recording the
physical fixture. It records real-file bytes, real directories and readlink
text without traversing links. The raw requested alias remains in CLI
arguments; a separately resolved path is the expected artifact destination.
This avoids accidentally bypassing the alias in an explicit -o control.

Refusals preserve the whole physical byte/file/directory/link inventory.
Allowed output aliases preserve their link text and change only the resolved
artifact and expected debug outputs. Debug source/map retention belongs beside
the resolved target, not beside the lexical default alias. Ordinary new and
existing outputs, unread locks and unimported standalone siblings stay allowed.

## Exact inventory and eight new intersections

#671 contains 534 methods. #670 contains 63, of which all 54 original #668
identities already occur in #671. The deduplicated inherited floor is
**543 methods**. Eight additional methods yield **551 unique ordered IDs**.

The new runner retains #671's module selections, appends only the new default
output module from #670, and then appends the new intersection module. It
does not duplicate the three separately named C-backend methods or inherit
old TestCase methods under new class IDs. Both historical inventories remain
present, and the exact 543-method ordered prefix is verified.

The new methods cover:

1. Nested generic/local bindings, repeated aliases and diamonds reaching
   protected graph and snapshot inputs through default aliases.
2. Actual owner and entry identity across directory/manifest/direct-source
   routes, including permitted locks and observed finite 7/42 results.
3. Both-order package-context conflicts before protected or permitted aliases.
4. Scope/private and same-source generic rejection, then renamed recovery
   reaching protected refusal or ordinary output.
5. Representative earlier stale-lock, escape, cycle and C-import failures.
6. Standalone directory aliases contrasted with package-directory rejection.
7. Permitted aliases and real debug publication at the resolved target.
8. Actual pinned-Rust parity after mandatory actual-C prerequisites.

Relative/absolute and default/explicit controls are representative subtests,
not an unbounded Cartesian product. Methods and nested observations are
reported separately. Test fixtures avoid accidental package snapshot changes
from output aliases ending in .hepta after a lock was created.

## New-source qualification

The dedicated workflow checks out the exact new head on Linux x86-64 and
AArch64, verifies the clean physical checkout, and records its commit/tree.
It requires actual GCC and pinned Rust 1.90.0. Planned, executed and passed
ordered method IDs must exactly equal the frozen inventory, with zero
failures/errors/skips/expected failures/unexpected successes.

Receipts bind physical compiler/source identities, fixture/package ownership,
raw aliases, resolved destinations, independently emitted generated source,
actual tool identity and flags, artifact hash, observed 7/42 return values,
and empty stdout/stderr. Ordinary builds are O3. Explicit debug builds are O0
with debug flags while validation remains O3. No UBSan claim is inferred.

Missing local Rust is incomplete qualification, not a passing result, a stub
compiler or a reason to relax assertions. Component CI from #670 or #671 does
not qualify this combination. All triggered workflows must be recorded for
the new head, separately from historical results and any retries.

## Limits that remain

This is stable ordinary symlink qualification, not an access-control,
filesystem-security or atomic-observation mechanism. Concurrent retargeting
between validation, resolution, comparison and publication remains possible.
unchanged() does not pin source files or owner locks through later writes.
There is no directory-descriptor/inode-bound publication protocol.

Path.resolve does not unify hardlink names. Hardlink input protection is not
established. Ordinary build publication uses os.replace, so replacing one
hardlink directory entry does not by itself change content through sibling
links. That distinction is not a broader hardlink qualification, and no
hardlink or race experiments are added.

The input inventory is not the full foreign/native dependency closure.
Low-level backend entry points and unrelated commands remain unchanged.
This work adds no recursive-execution investigation, whole-language proof,
production-readiness, merge, release or deployment claim.
