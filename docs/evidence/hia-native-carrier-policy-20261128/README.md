# Native carrier lifecycle policies and current typed admission

This commit owns the native Image export/release policy and Cell capture/callback
policy in HIA. The CPython resource ABI is a closed mechanical compatibility
boundary; it exposes only the enumerated object-slot operations and preserves
real CPython buffers, cells, reference counts, heap types, GC and exception identity.
It is not an arbitrary C API or a Python policy fallback.

## Product and source boundaries

The new stage-19 DAG captures exactly the two HIA policy sources, compiles each
twice through the native source-build path, compares the outputs, and publishes
carrier-image-policy.flat, carrier-cell-policy.flat and carrier-policies.hiadat.
The 304-byte HIACPUB1 publication binds both roles to source lengths and SHA256,
image lengths and SHA256, and the actual cold compiler and source-build identities.
The shared release catalog and source-authority tuples are intentionally left to
the central integration owner. source-registration.json lists all 28 changed
source files and the three new native input paths.

The old v6/closed-v1 envelope stays a separate exact domain. A new explicit current
envelope first admits its entire original typed child and all physical inputs.
Only after those checks does it select the two fixed mechanical extensions.
Stage-19 bytes must equal the policies in the actual build receipts. Cached
exports, scope ownership, child identities and final physical bytes are rechecked.
Current Artifact uses the real Image carrier; Verification's recursive callback
uses the real HIA Cell policy. The bridge alias keeps the current exception-safe
host byte reader and the exact original global lookup implementation.

## Observed gates

* Original Image: the historical e222 image was physically recovered from desktop,
  its original pinned compiler was captured, and recompilation reproduced e222.
  All five original unchanged controls passed against the HIA-owned carrier.
* Original Cell: all six unchanged methods passed against the new carrier.
  The current combined attempt initially ran zero Cell methods because its
  read-only old-C watched oracle was absent. That failure remains intact.
  A separate successor added only that exact 0400 oracle to the QA directory;
  it was not compiled or shipped. The six original methods then passed.
* Original v6 admission: six methods and 146 controls passed.
* Native policy request controls: five methods and 212 controls passed.
* Current typed Page component: seven methods and 108 controls passed.
* Current real Verification HIA graph: three methods passed, including branches,
  cycles, repeated completion, late recursive-cell rebinding, original exception
  object identity, empty-cell context and parent-release/GC.
* The actual stage-19 native release DAG completed all 41 nodes and published
  the three expected products in 0.5249202787 seconds. It reused captured native
  release-owner parts and the real original source-build/capture/subprocess ABI;
  only the diagnostic state loading and terminal observation are external.

The current combined command's return code remains 1 because of its first Cell
preparation error; successful subcommands are not used to relabel that attempt.
All earlier preparation, source-routing and private-mode refusals are preserved.
These are native component and host compatibility observations. They do not
claim a new full cold chain, ordinary Store release, default Python wheel install,
installed rebuild, or public nineteen-role qualification. The central union must
run those gates; the dedicated compatibility installer is the next source step.

## Complete physical custody

complete-attempts-physical-cas.tar.gz is the complete Mac physical archive. Its
members.json maps original relative paths, modes, sizes and hashes to immutable
blobs. It includes all original scripts, logs, failed attempts, source snapshots,
transport records and the complete Linux physical archive as a blob at original
path complete-carrier-evidence-v1/complete-physical.tar.gz.

That nested Linux archive contains 8,839 original entries / 183,938,917 file bytes
in 851 unique blobs. Each blob was read back on Linux and independently on Mac.
The Linux archive is 13,263,025 bytes, SHA256
4aa1d172cdd7e1363ddfb0151f51a1dc3857604fba67a479bca0b900057f30e8.
No original task output was pruned. The original C files exist only as retained
QA oracles inside evidence, never as either new product policy.

The Mac archive is 32,616,347 bytes, SHA256
2e5848eeaa3c5d9a479faffbf07fb8a92eade65f34f135fcb61854bb53f221b4.
The archive receipts and independent readback are adjacent. Convenience result
copies point into the complete manifest; the raw archives remain authoritative.
