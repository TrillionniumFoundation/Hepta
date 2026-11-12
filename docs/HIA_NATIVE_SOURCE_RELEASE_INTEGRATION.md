# Native source, explicit compiler, and release integration

This is a scoped integration of the source-build and release work at
PR893 source head 9a12b6cd13ba103fc7495aa8d5decf8cd5948143 and the portable
publisher custody change at PR894 head 5386be50a1faddc0d986af3c04cad37a4ac6c102.
The integration base is 8b9fbcbeb943447bdbd4e534f081f92e5f1ad8b2.
It does not transfer the qualification of either independent branch.

## Executed ownership

The source-build HIA policy owns argument and wire admission, complete member
and role validation, the ordered compiler continuations, produced-image checks,
the final bundle and refusal decisions. Its HIA packer emits the complete
standalone executable. The fixed syscall assembly performs the requested
memory and I/O operations. These are real native executions; the Python
authoring builder is not the delivered source-build policy.

The existing bounds remain in force: at most 128 input members, at most one
MiB per source or compiled image, a 64 MiB wire/output envelope, and the
compiler's one MiB workspace and original language/profile limits. The
integration does not broaden the compiler profile or reduce any existing
accepted language to claim closure.

The explicit public compiler path is
`hia build --backend selfhost --selfhost-manifest PATH --selfhost-manifest-sha256 SHA`.
It selects the supplied sealed native compiler, with both manifest and actual
source/image identity checked. The native frontend and compiler perform their
bounded primitive Core v8 parsing, checking, compilation and object emission.
Python still owns the outer public verification/profile admission, physical
process and descriptor custody, source pins, symbol inspection and publication
bridge. This is not a claim that the general backend or whole CLI is native.
The default backend is unchanged. A selected failure does not authorize a
hosted code-generation fallback.

The native release selector additionally owns read-only verification of the
requested installed sequence and digest. Under its shared lock it checks the
entire installed tree, reopens selection state, and compares the complete
192-byte identity readback with the same selected sequence and digest. This
operation does not activate, roll back, create a lock, or rewrite selection
state. Existing install and activation behavior remains independently owned.

## Source paths and installed custody

All existing `.hiaasm` resources are retained. The actual added HIA sources are
`source_build_policy.hiaasm` and `source_build_packer.hiaasm`. The compiler
source remains the actual `selfhost.hiaasm` resource; there is no filesystem
alias to a nonexistent `selfhost.hepta` file. Canonical closed-bundle wire role
names retain the original three `.hepta` spellings. The fixed input
materializer pairs those role names with bytes captured from the actual files.

The HIA policy accepts assembly names ending in either `.hepta` or
`.hiaasm` within the unchanged name limit. Closed pack roles accept both
spellings, while the original complete role bitset rejects duplicate aliases
that leave a required role missing.

Package resources and installed-source custody use the complete union of
`DISCOVERY_FILES`, `NATIVE_SOURCE_FILES`, `SOURCE_BUILD_FILES`,
`COMPILER_BUILD_FILES` and `PUBLICATION_BUILD_FILES`.
Both compiler-build and source-build resources are included, with no duplicate
paths or silent removal of the pre-existing resources. The setup hook copies
these explicit resources without importing product policy.

## Publication refusal and sealed execution

The base integration's structured `NativePublicationRefusal` is preserved,
including its superclass, message, operation and actual returned process code.
The portable seal change only supplies Linux UAPI constant values when the
Python build omits their names; it does not replace kernel enforcement.
The bridge reads back actual seals, file extent, and every admitted executable
byte before starting the child. Missing memfd support, seal refusal, incomplete
seals, changed extent and changed content all refuse before execution.
Descriptor cleanup remains mandatory and a refused operation is never replayed.

This distinction matters for the artifact-store callers: a confirmed returned
read-only refusal is distinguishable from a lost handoff, but no such distinction
proves that a mutating operation had no effects. The integration does not
downgrade that contract to generic exception text.

## Canonical source correction

The earlier recovered authoring packet proposed actual source-builder files
ending in `.hepta`. This conflicts with the unchanged Core-only checker, which
rejects every repository path matched by `root.rglob('*.hepta')`. Exact ac3
contains no such paths. That incompatibility was found by reading the original
checker before the new source-generation run; no checker exception is added.

This new, unexecuted revision uses `.hiaasm` for generated files, physical
resource reads, package entries and source hashes. It preserves `ROLE_NAMES`
and their original `.hepta` wire strings, the dual wire aliases and all old
limits. It creates no alias files. The previous authoring packets and prior
31/17/r2 observations keep their original identities and do not qualify this
revision. The next source stage must execute the original Core-only gate.

## Test and recovery status

The pre-outage local environment was Python 3.12.14 with a retained development
compiler from the original 8aade CI B3: 669494 bytes, SHA256
81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109.
It is not a matching-source cold compiler for this integration.

The original source/ordinary-VM/kernel panel completed 31/31 in
26.421860036 seconds, with the observed source inputs unchanged. The first
actual HIA source-builder native class completed 17 tests: 14 passed, two
failed and one errored, with no skips. Its 62.288988314-second result is retained
as a failure, including the original M1 fixture role-name error, the actual
ptrace refusal, and the original EPIPE control's missing prefix.

A separate three-test correction panel completed two passes and one failure
in 6.713167695 seconds. The original M1/M2/M3 control passed after its fixture
used the canonical wire role. A new untraced real-pipe control observed its
4096-byte prefix and exit 15. The additional global seccomp restriction still
killed the child with SIGSYS before output. A subsequent small mechanism
diagnostic isolated that failure to the file/process syscall group; it did not
establish which syscall or whether host pre-exec setup caused it. The original
traced controls were not deleted, skipped, or relabelled.

The executor became unavailable before the proposed instruction-address-scoped
filter patch or a third test panel was launched. Those proposals are not tested
changes. The original generated assets and complete raw local reports were
not uploaded before the outage. Saved exact upstream inputs and visible
terminal observations are distinct from a complete raw evidence archive.

This document and the integration-only test file were reconstructed after the
outage. Other authoring files were deterministically replayed over exact pinned
Git inputs; no pre-outage complete byte-hash map is available to establish the
identity of the resulting candidate as the original scratch tree. Generated
HIA assets and the complete source contract must be regenerated from these
actual authoring inputs, followed by fresh source, native, installed-package,
and matching-source cold qualification. None of the earlier test totals
qualifies this reconstructed source.

Whole-native delivery, native default activation, live migration, and deletion
approval remain false. The user has authorized eventual removal of old owners;
it still requires complete replacements and the corresponding fresh qualified
chain.
