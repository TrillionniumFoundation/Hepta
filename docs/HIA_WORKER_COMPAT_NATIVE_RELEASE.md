# Worker 01 and 02 native release products

The ordinary installer remains Worker 03. The separate stage 20,
release_stage_worker_compat.hiastd, publishes the actual Worker 01 and 02
entry and owner ELFs for complete compatibility installation qualification.

## Products and execution layout

| Published asset | Protocol | Name in its independent executable directory |
| --- | --- | --- |
| hia-worker-install-owner-v1 | 01 | hia-worker-install-owner |
| hia-worker-install-v1 | 01 | hia-worker-install |
| hia-worker-install-owner-v2 | 02 | hia-worker-install-owner |
| hia-worker-install-v2 | 02 | hia-worker-install |
| worker-compat-publication.bin | Both | Read-only construction record |

A versioned entry at the release root is a published asset. Its original
runtime contract still opens the canonical owner name in its own directory.
Compatibility qualification must capture the corresponding entry and owner
into a fresh protected directory, together with the same release's
hia-subprocess, hia-source-build and hia-source-capture. The copies must preserve
complete bytes and modes and have their own regular files with one link.
The original entry verifies the four actual executable digests in the order
owner, subprocess, source-build, source-capture.

The 01, 02 and ordinary 03 installation outputs remain separate real products.
Their complete member domains are respectively 37 helpers / 130 records,
41 / 134, and 45 / 145. Copying a subset of a 03 installation cannot establish
01 or 02 qualification. Compatibility assets need not be deployed as another
ordinary installation.

## Native construction

The graph captures 55 source inputs: the two versions' complete owner and entry
construction sources, their manifest programs and tables, all 16 installation
graphs for each version, the shared source-kit/compiler sources, and the two
existing syscall adapter sources. The registered stage also includes this
graph as a resource. This is the installer-construction input set; the full
installed runtime retains the complete native source inventory and cold report
checks of the existing Worker owners.

The graph double compiles its HIA construction inputs with the source compiler.
Each actual member builder is constructed by the original native source kit
using source_filter_member.hepta and that protocol's real packer. Its canonical
named-source input is passed unchanged to the builder. Before any publication,
the complete returned HIAOBJS1 frame is compared with the complete independent
ELF bytes, all retained images, all image lengths, the member count, and footer
magic. The comparison includes every template byte, ELF extent, call
displacement and entry image length.

The original native binder receives HIAENBD1, the four real digests, and the
unbound entry. Its complete output must equal the independently formed entry
with exactly the original 128-byte pin region replaced. No runtime role or
source-filter admission is enlarged.

Only existing HIA DAG operations are used. GNU assembler is used by the
development author to obtain the same two fixed syscall templates; production
executes the checked-in native graph. Each original adapter's full source hash
is checked in the graph. There is no host assembler or Python in the native
construction path.

## Native construction record

worker-compat-publication.bin is a closed binary record, with unsigned
little-endian 64-bit lengths and integers. A pin is an eight-byte byte count
followed by the 32 raw SHA-256 bytes.

1. Eight-byte magic HIAWCR01, protocol count 2, and source count.
2. Four actual pins in order: B3 compiler, source-build seed, subprocess,
   source-capture.
3. Two ordered protocol records, 01 then 02. Each contains the eight-byte
   HIAWOP01 or HIAWOP02 magic, helper count, record count, owner pin and bound
   entry pin.
4. The sorted complete source entries. Each contains path byte length, exact
   ASCII path, source byte length and raw SHA-256.
5. No trailing bytes.

All pins are calculated by the native DAG from the actual source and output
views. Sources are captured again and compared after the child executions.
The graph does not pin its own bytes or insert a derived product hash back into
the owner source, so adding its registered stage does not create a source
identity fixed-point dependency. The final unified author still needs to
regenerate the ordinary and both compatibility owners after the shared DAG
registry and catalog have been updated.

## Component qualification and remaining full gates

The development component qualifier is tools/qualify_hia_worker_compat_release.py.
Its explicit prerequisite directory contains the recovered original source
compiler, B3, subprocess, source-capture, release owner and cold-report bytes.
These are development prerequisites, not a current cold qualification.

It reconstructs the original native release engine's three physical parts and
executes the complete stage in a mechanical checkpoint fixture. It builds a
real source kit from the current three HIA inputs; the seed is never substituted
for the kit ABI. The checkpoint supplies the two real prerequisite product-table
rows for subprocess and source-capture. All five publications are read back.
The two original complete member qualifiers are then run without removing any
of their three members, source-order checks or refusal cases. Their owners and
the independently built and bound entries must equal the published four ELFs
byte for byte.

The first complete execution on AI395 reached node 939 with five publications
in 31.439 seconds. Each protocol's original member qualification made 39 native
calls and passed all 21 refusal cases. The entire component run, including
independent construction, finished naturally in 66.249 seconds. Those results
apply to the recorded physical development source and compiler inputs.

The evidence preserves the initial author input-count rejection and the first
negative-control expectation error: an unknown member alias is rejected by the
native child with code 16, and the unchanged release owner reports code 74.
This differs from its own complete-frame comparison refusal, which reports
code 65. The corrected refusal qualifier checks each named case's exact
protocol outcome and the child receipt; arbitrary nonzero exits do not pass.

The three new actual refusal cases all passed without publication: unknown
member alias, complete-member footer mismatch, and entry-binding magic mismatch.
Two complete author replays then reproduced the graph byte for byte. The
component handoff preserves their original receipts and marks the complete raw
archive as a subsequent evidence deliverable.

Final full qualification still requires a fresh cold build at the unified
source head, ordinary release, depot installation and byte-identical installed
rebuild, followed by complete real 01 / 02 / 03 installations and their original
130 / 134 / 145 domains. A successful component run does not assert those gates.
