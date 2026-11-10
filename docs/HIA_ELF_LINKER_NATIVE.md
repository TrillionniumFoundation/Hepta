# Native HIA linker for selfhost ELF objects

`examples/hia_bootstrap/elf_linker.hiaasm` implements the complete transformation
from the current selfhost compiler's bounded Linux x86-64 relocatable objects
to a loadable ELF shared library. The HIA program validates the object tables,
merges public symbols, lays out every output table and load segment, resolves
the admitted relocations and emits every output byte. The delivered `hia-link`
executable runs this program through the existing HIA syscall-only entry.
Neither GNU ld nor a Python ELF transformer runs during native linking.

This closes an explicitly selected linking route for the existing selfhost
object profile. The ordinary host compiler and general linker remain separate
authorities: arbitrary GNU/LLVM objects, archives, shared-library inputs,
additional undefined symbols, arbitrary relocations, cross-target linking and
the full production service are outside this profile. Unsupported input fails
without another linker being invoked. Whole-stack HIA replacement remains open.

## Input and output contracts

The input frame begins with the eight bytes `HIALNK01`, followed by a little
endian `u64` object count, one `u64` length for each object, and the concatenated
object bytes. There are 1–16 objects, at most 128 total public exports, at most
1 MiB of framed input and at most 1 MiB of output. Each input is one of the
current compiler's canonical six-section borrowed-entry objects or seven-section
explicit-export/allocator objects. The entire frame is validated before any
output is written.

The linker retains the existing C scalar ABI and six-argument borrowed `f0` ABI.
Internal calls were already resolved by the selfhost compiler and remain within
their original text block after relocation. Multiple objects can contain
identically named private source functions; private names are absent from the
dynamic symbol table. Duplicate public exports, reserved loader hooks and
unknown undefined symbols are rejected. Export names use the compiler's
128-byte ASCII identifier bound.

The existing external `calloc` and `free` imports are coalesced across objects.
Their `R_X86_64_PLT32` calls are patched to native PLT entries; those entries use
a GOT with two `R_X86_64_GLOB_DAT` relocations. `DT_NEEDED` names `libc.so.6`, and
the dynamic table requests immediate binding. This preserves the external
allocator ABI rather than pretending libc allocation has been rewritten in
HIA. The host dynamic loader, process symbol interposition and the actual
allocator implementation remain trusted.

The resulting `ET_DYN` has separate RX and RW load segments, a non-executable
stack, a full page of GNU RELRO covering its GOT and dynamic table, and no
interpreter or text relocations. The SysV dynamic lookup table reaches every
admitted public and imported symbol. The bounded table uses one bucket and an
explicit chain; it makes no general linker-performance claim.

The flat ABI uses a read-only input view, output view and 16 KiB private scratch.
Return `0xffffffff` means malformed or unsupported input; `0xfffffffe` means
insufficient output/scratch/export capacity. Both leave output unchanged. A
successful return is the exact output length, and bytes beyond that length
remain unchanged. Scratch is explicitly initialized, including when the caller
provides poisoned memory. The standalone executable uses the existing entry's
exit codes: 0 success, 2 invalid input, 3 capacity, 4 mapping/descriptor I/O,
64 unexpected arguments. As with the existing compiler filter, an output I/O
failure can occur after a correct prefix reached stdout; it is not success.

## Build and use

The publication builder requires a completed, matching three-generation cold
qualification. Its source inventory must include the exact linker source,
authoring aid, builder and host custody driver. Incomplete or historical
qualification cannot admit the current source. Both flat-image and executable
publication bind the actual native compilation receipt's compiler, input and
output identities, including the exact `selfhost_exec` source variant.

```sh
python -B -m tools.build_hia_elf_linker \
  --compiler /path/to/qualified/B3.image.bin \
  --cold-report /path/to/current-completed-cold.json \
  --output /new/private/native-linker

python -B -m tools.link_hia_elf \
  --manifest /new/private/native-linker/manifest.json \
  --output /new/private/combined.so first.o second.o

/new/private/native-linker/hia-link.elf < objects.frame > combined.so
```

The optional host custody driver captures bounded regular files, validates the
manifest/source identity, seals the captured executable in a memfd and invokes
those exact bytes. Replacing and restoring its pathname cannot substitute a
different executable. The driver records exact input/output hashes and refuses
to overwrite an existing output. It writes an exclusive temporary file, flushes
and syncs its complete bytes, then atomically links the final name without
replacement. A write/sync failure does not publish a partial final artifact.
It performs no ELF transformation. Host file
custody, manifest JSON and build orchestration remain Python in this route;
direct standalone invocation needs none of those at runtime.

The existing scalar-export and owned-buffer qualifiers also accept an explicit
`linker_manifest` keyword. The owned-buffer command exposes
`--linker-manifest /path/to/manifest.json`. They bind the selected linker's build
compiler to the compiler under test, retain all original VM/native/refusal
assertions and record the real native-link receipt. An error terminates the
selected route without a host-linker fallback. The owned-buffer suite still
builds its independent host-backend reference through ld; that reference does
not produce the candidate artifact.

```sh
python -B -m tools.qualify_hia_selfhost_owned_elf \
  --compiler /path/to/qualified/B3.image.bin \
  --linker-manifest /new/private/native-linker/manifest.json \
  --output /new/private/native-linker-owned-evidence
```

## Independent and native verification

`tests/test_hia_elf_linker.py` executes the HIA program in the independent Core VM
before creating a native seed. Two independently constructed scalar objects
exercise real object validation, symbol merging, output headers and text
placement; refusal controls check duplicate/reserved symbols, truncated frames
and output capacity. Fresh B0→B1→B2 then compiles the linker and its standalone
entry. The native result is compared against every byte observed in the VM.

The native suite links real objects produced by the native compiler, executes
the existing scalar-export qualification matrix in an isolated loader, covers
128 exports and the existing mixed 16-argument ABI, combines two objects with
private-name collisions and real allocation, and runs the legacy borrowed
entry. Existing owned-buffer cases exercise allocation success/refusal, loans,
drop, traps and writes that precede a trap. Mutated ELF headers, symbols and
relocations are refused without output. Frame counts, poisoned workspace and
canaries check bounded behavior. The loaded process's actual mappings confirm
RX code and a read-only RELRO page. A custody control temporarily replaces the
executable pathname while the captured original is executed.
The selected-route integration runs the existing export and owned qualifiers
without reducing their case/refusal inventories. Separate source-inventory ABA,
actual compiler-substitution and failed disk-sync controls protect publication.

```sh
python -B -m unittest tests.test_hia_elf_linker -v
```

These are finite component observations. They do not establish an all-input
linker-refinement proof, fresh whole-repository CI, production activation, or
eligibility to delete the existing full toolchain. Exact combined-candidate
cold, language, platform and release results retain their own source identities.
