# Native cold master and public CLI

This checkpoint implements the generic native orchestration boundary. It does
not assert that the complete production cold qualification corpus passed. The
component fixture uses 41 small plans to qualify ownership, scheduling, source
custody, archive transport and report construction. The real 60-phase catalog is
independently assembled and must pass under the same 180-second budget.

## Public entry and trust configuration

`hia-cold --source ABS_SOURCE --output NEW_ABS_DIRECTORY --toolchain ABS_ROOT --bundle ABS_DESCRIPTOR`

The generic `cold_cli.hepta` contains no descriptor or tool image pin. Its native
packer accepts `HIAQCP01`, policy bytes, SHA-role bytes, four 32-byte pins, then
policy and SHA flats. The pins are descriptor, master ELF, cold-process-owner ELF
and source-export ELF. They are inserted into the mechanical ELF's immutable
configuration, without changing HIA source. This avoids a source-manifest hash
cycle. The descriptor is runtime transport, not a source-manifest member; every
HIA/assembly source and every independent `.hiacases` input remains in the source
closure. Rebuilding a configured CLI consists only of the independent HIA
compiler/front-end chain and this native packer.

The toolchain directory contains `hia-cold-master`, `hia-cold-process-owner` and
`hia-cold-source-export`. Each image is copied into a sealed memfd and checked
against its configured SHA. Paths are traversed one component at a time with
NOFOLLOW. A new output directory is mandatory; an ancestor `.git` is refused.
Regular input files are opened nonblocking before file-type checks.

The source exporter makes the source-only, private source/home/tmp tree before
the qualification clock starts. The CLI immediately sets the unchanged 180 s
absolute deadline, copies only descriptor-pinned roots and manifest-pinned source
files into a sealed transport, and invokes the unchanged independent process
owner with the original 180 s plus 3 s cleanup policy. Only the sealed transport
and a private run-directory descriptor are passed to the master. The original
process owner's 64-FD pass limit is preserved.

## Descriptor HIAQBD01

All words are little-endian u64. Header size 256: version at 8, root count at 16
(maximum 512), phase count at 24 (40..64), binding count at 32 (maximum 2048),
manifest bytes at 40 (32..1 MiB), manifest file count at 48, profile length at 56
(1..95), driver/archive/fast/cold root indices at 64/72/80/88, manifest offset at
96, exact descriptor extent at 104 (maximum 2 MiB), zero at 112 and 120, manifest
SHA at 128, profile text padded to 96 bytes at 160.

Tables follow: root rows 384 bytes, phase rows 384 bytes, binding rows 288 bytes,
then the exact HIASXM01 manifest. The manifest offset must equal the tables' end.

Root row: artifact bytes at 0 (maximum 64 MiB), name length 8, path length 16,
class 24 (0 toolchain / 1 exported source), SHA 32, name padded 128 at 64,
relative path padded 192 at 192. Source roots must match the manifest path,
size and SHA exactly.

Phase row: ID padded 64 at 0; kind at 64 (1 reference, 2 base, 3 qualification);
family ordinal at 72 (u64 maximum outside qualification); label at 80 (0,1,2);
zero at 88; plan bytes/nodes at 96/104; SHA at 112; binding start/count at
144/152; preceding-phase dependency mask at 160; ID length at 168; source-plan
path length at 176; zero 184..255; source-plan path padded 128 at 256. Every plan
must match its exported source-manifest member. Each phase still admits at most
64 imports.

Binding row: kind 0 static root / 1 sealed phase at 0; source index at 8; source
filename length at 16 (zero for static); target import name length at 24; source
filename padded 128 at 32 (all zero for static); target name padded 128 at 160.

The family ordinal is capacity, cfg, elf, chain, owned, bulk, loan, resource,
tail, select, effects, multi, keyword, signed, scalar-casts, explicit-traps, cli,
names, exports. Exactly one original and one modified phase per family is
required. All references precede a unique base; qualifications follow it.

## Runtime transport and bounded schedule

The runtime artifact transport is a sealed file of at most 2 GiB. This container
bound does not change the 64 MiB bound on any artifact or plan. HIAQMS01 runtime
stdin has a 128-byte header followed by root192 / phase256 / binding288 rows.
Header words are expected parent (zero means record the actual outer-owner PID),
absolute deadline, private run FD, three table counts, four tool-root indices,
qualification start, version1 and three zeros. Root rows hold FD, extent, name
length, range offset, SHA32 and name128. Phase rows preserve the first 256 bytes
of descriptor metadata, replace offset88 with the transport FD and offset176
with the plan's transport offset. All ranges are copied and independently hashed
before sealing the individual image or plan memfd. No target or successor is an
initial import; qualification compiler bindings must resolve B3.flat or M3.flat
from the unique, freshly sealed base archive.

At most two phase processes run. Finished processes waiting for the two-slot
archive queue retain their execution slot. One archive process runs at a time.
A queued or archiving phase is still unsealed; the resulting maximum is four
unsealed phase directories. Dependencies only become available after the full
archive receipt, actual SHA reread and sealed output extraction succeed. Both
actual and configured peaks are emitted. Every child receives only its explicit
FD set, a cleared environment and parent-death custody. Failure never publishes
a successful master receipt. The outer process owner supplies the full adopted
process identity ledger and final kernel ECHILD proof.

## Report publication

The CLI checks the actual owner receipt, master receipt, every phase's timestamps
and identity, and performs source/origin after-verification. It extracts all seven
generation hashes from the actual base archive, requiring B1=B2=B3 and
M1!=M2=M3!=B3. The legacy observer is read from that archive and compared with
all 1107 bytes of the independent mechanical reference before hexadecimal output.
The complete v2 JSON includes the full manifest, 14 exact checks, 19 family pairs,
all phase IDs and three actual hashes, original budgets and measured peaks.
Only after all checks does it fsync and atomically rename `final-cold.json`.
The exact file is also written to stdout. Raw owner/master/export receipts and
the admitted descriptor are preserved beside the phase archives.

## Evidence for this checkpoint

Independent master ELF: 341236 bytes,
`a690f7a5fb3f777e35c49b86494d1b3d0f1d558758126a33cb0715c159158cfe`.
Generic CLI flat: 391068 bytes,
`cbbcde45e38e7a4d36baab60be8151dbf6d8b1bac7e1dee3873733c098661b9a`.
Native CLI packer: 25708 bytes,
`b6babfa26de48991ce0581ad30c9fc77375b08872584564e1e38d5dc31eecb9f`.

The complete 41-phase component CLI ran with PATH empty in 2.52 s: nested 1.902 s,
cleanup 64.03 ms, actual peaks 2/1/2/4, all archives and report bytes checked.
Twenty-two refusal/fault gates include actual origin/export changes after phase
execution started, extra export content, symlink substitution, SIGKILL of the
live master and live archive worker, wrong pins, an ancestor Git identity,
duplicate families, future dependencies and an initial-root compiler substitution.
Both kill controls produced no PASS and proved empty cleanup plus ECHILD within
the original 3 s. The first CLI fixture exposed overlapping launch-state fields;
its refusal is preserved and the corrected component was rebuilt independently.

### Repeated artifact aliases

The complete production base plan imports one utility image under two names. The
original driver correctly requires distinct import descriptors. The master now
uses F_DUPFD_CLOEXEC for repeated per-phase references and closes those extra FDs
after the driver completes. Image bytes, seals, hashes and the fast/cold identity
checks are unchanged. The component fixture exercises both a repeated static
root and a repeated sealed-phase output, followed by all 38 qualifications. It
passes the same 22 custody and live-cancellation controls.
