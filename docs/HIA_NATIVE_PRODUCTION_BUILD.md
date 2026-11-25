# Native production construction

The default production chain has four source-bound native entry points. The
first builds the independent qualification tools. The second performs the
complete cold qualification. The third admits that actual report and compiler
before constructing the release bootstrap. The fourth builds the ordinary
release. Each step has its own captured inputs and receipt; a successful
component construction is not a successful whole cold qualification.

## Public commands and output paths

All directory arguments below are absolute. Output directories are new
directories, and the source directory contains the exact frozen native source
inventory.

~~~sh
hia-cold-build --source SOURCE --bootstrap BOOTSTRAP --output TOOLCHAIN

hia-cold --source SOURCE --output COLD \
  --toolchain TOOLCHAIN --bundle TOOLCHAIN/cold-bundle.hiadat

hia-source-bootstrap --source SOURCE --cold COLD \
  --bootstrap BOOTSTRAP --output SOURCE_BOOTSTRAP

hia-release-build --output RELEASE \
  --compiler COLD/qualification/base/B3.flat \
  --cold-report COLD/final-cold.json --source SOURCE
~~~

The first command accepts exactly seven argv entries, counting its executable;
the cold and source-bootstrap commands accept exactly nine. The ordinary release
entry also supports its existing optional timeout argument. Run the release
entry produced inside SOURCE_BOOTSTRAP so that its four embedded capability pins
select the source builder, capture owner, subprocess owner and release owner
from this construction.

TOOLCHAIN contains hia-cold, cold-bundle.hiadat, hia-cold-master,
hia-cold-process-owner and hia-cold-source-export. The descriptor names each
remaining qualification root by its relative installed path. It also identifies
the source-bound serialized plans, their actual byte lengths, node counts and
hashes. A descriptor never supplies historical execution results.

## Independent initial roots

The bootstrap directory supplies seven explicitly bound native tools:

| Index | Tool | Construction responsibility |
| --- | --- | --- |
| 0 | hia-seed-assembly | HIA source to canonical Core |
| 1 | hia-seed-projector | Selected Core entry to independent machine-construction wire |
| 2 | hia-seed-backend | Original bounded independent backend |
| 3 | hia-seed-filter-pack | Fixed transport wrapper for an actual policy flat |
| 4 | hia-cold-qualification-driver | Executes the fixed construction plan and retains every node's evidence |
| 5 | hia-independent-subprocess | Runs the sealed child with the original process limits |
| 6 | hia-cold-process-owner | Owns the complete process tree, deadline and cleanup |

The source recipes rebuild these seven tools and compare every byte with the
captured initial images. Additional div, bulk, word, endian, owned and complete-VM
backend profiles are built from source using the original independent backend;
they are not additional initial roots. The compiler being qualified does not
construct the independent reference VM or its independent machine backend.

The full reference VMs use the independent complete-VM backend and the native
kernel linker. Both the normal and separately bounded linked-reference profile
retain their original step, depth, heap, return, resource-ledger and view
contracts. A mechanical bridge is part of the readable source inventory. No
host assembler or linker is called by these serialized construction plans.

## Seven construction stages

The exact runtime programs are the seven .hiacases files under
examples/hia_bootstrap/cold_build_plans. Their source and publication bindings
are recorded in cold_build_recipe.hiadat.

| Stage | Required construction |
| --- | --- |
| 0, semantic roots | Rebuild the original backend, fixed filter, assembly frontend and projector; construct the additional independent backend profiles |
| 1, orchestration | Rebuild and compare the driver and both process owners; build the archive, master, source exporter, descriptor tools, contract tools, strict report gate and entry policies |
| 2, native tools | Construct all remaining qualification tools, including exact private process wrappers, native object inspection, native linking and actual loaded-code observers |
| 3, complete VMs | Construct both complete reference VMs through the independent machine backend and native kernel linker |
| 4 and 5, inventories | Run the native inventory tool over all sixty actual serialized qualification plans |
| 6, descriptor and entries | Reproduce the frozen source contract, compose the descriptor from actual manifests and plan inventories, bind the cold CLI and both public construction entries |

A publication has a separate temporary or installed flag. Temporary flats,
intermediate roots and inventory bundles remain private construction evidence;
they are not installed as additional product versions. Each installed
publication is captured, hashed and reread before the entry returns its public
receipt.

The fixed source authority is cold_build_sources.hiadat (HIATBS01). The prebuild
and post-cold recipes are separate HIATBR01 files and use the same sorted
authority. Bindings name a captured initial root, an exact source path, an
earlier stage publication, an actual source/tool manifest or the captured
current entry image. The post-cold variant additionally binds the actual B3
and the actual cold report.

Every stage retains the original maximum of 64 imports. The capture boundary
retains 4,096 source paths, 64 MiB per file and 2 GiB total source bytes. These
limits are not inferred from a particular checked-out source count.

## Actual manifests and the frozen source contract

The capture owner produces HIASXM01 from the actual source files. Its records
contain a relative path, actual length and SHA-256. The native
source_contract_manifest policy validates and converts that representation to
HIASPI01, preserving every path and digest and removing only the length field
required by the different wire format.

The native source-contract producer consumes HIASCG01 containing the reviewed
HIA_NATIVE_SELFHOST_METADATA.json template and the actual HIASPI01 inventory.
It requires the HIA_SELFHOST_CORE_SUPPORT.json self item exactly once and
excludes only that self item from the generated identity map. It does not
accept an empty source identity as a completed source contract.

Stage 6 requires generated contract bytes to equal the contract already
captured from SOURCE. The public build does not silently change SOURCE or
replace one captured manifest item with a different derived file. Preparing a
new source version therefore includes generating its new contract and then
capturing the final frozen source version.

The cold report admission role is source_release_cold_admit.hepta. It is the
strict current report gate shared by the prebuild, post-cold bootstrap and
ordinary release path. The current metadata, source catalog and all sixty plan
identities specialize that gate. An older matching component gate does not
admit a changed source version.

## The post-cold bootstrap

cold_source_bootstrap_recipe.hiadat selects the separate post-cold plan under
examples/hia_bootstrap/cold_source_bootstrap_plans. Its public entry captures:

- COLD/final-cold.json;
- COLD/qualification/base/B3.flat;
- the current source files and their actual source manifest;
- the same seven initial roots.

Before any candidate-compiler invocation, the strict native gate receives the
actual report, exact HIASPI01 inventory, captured contract and SHA-256 of the
captured B3. It must return the complete HIAADC01 receipt with that B3 identity
and exact admitted source count. cold-inputs.receipt binds the actual report
hash, actual B3 hash and complete gate receipt. Neither a component report nor
a report from another source version substitutes for this admission.

The admitted B3 then compiles the current source-builder policy and packer
through the independent observer. The plan also rebuilds the compiler from
its actual source and compares the whole resulting flat with B3. A source kit
contains the three actual sources and the three corresponding compiled flats.
Two successive native build-and-pack generations must reproduce the complete
source-builder executable byte for byte.

The same admitted compiler constructs the release owner, subprocess owner,
source capture owner and ordinary entry. The entry binder writes only the
specified 128-byte pin region: the exact prefix, suffix and total extent are
compared with the unbound entry. Its four pins come from the actual constructed
capability bytes. The post-cold public entry is also rebuilt independently and
compared with its captured current image.

## Custody and completion

Captured executable and input images are sealed before execution. The public
entry passes an immutable transport and a private run directory to the owned
inner process instead of passing an unbounded list of source descriptors.
Stage results require the actual successful driver receipt, complete physical
journal identity and child reaping before a publication becomes available to a
later stage. Original source, root and installed-output custody is checked
again before the public success receipt is emitted.

These properties are construction and custody obligations. Final acceptance
also requires a physically native-only source tree, a successful whole cold
report under its unchanged budget, actual report admission, ordinary release
construction, installation and an installed whole-source rebuild. Separate
component results do not satisfy those remaining gates. Retain failed
attempts and their precise source identities until the final evidence set is
complete.
