# Owned-buffer ELF selfhosting: bounded qualification

The v12 candidate adds actual native compilation of `buffer.new`,
`buffer.try_new`, `owner.move` and `owner.drop` in the explicit `selfhost_elf`
module. The native HIA parser, capability checker, x86 encoder and ELF writer
produce the machine artifact and its closed `calloc/free` import relocations.
The flat profile retains 40 operations; the ELF profile supports 44 of the
general Core's 50 opcodes. This does not close the general Core or general
machine-refinement acceptance gates.

## Frozen identities

- Baseline source commit: `5f070218dfd7ec656147322cfb7da14bbb5894fd`.
- Qualified source commit: `4110a0f4739438ac9188ad66a7be8037feb4bdfa`.
- Branch: `codex/selfhost-owned-elf-v12-20261108-5e6c`.
- Compiler assembly SHA256: `6b9f2245c2a30a03b16195d45bfd9626678633acf228f4292a0e962f6eae626c`.
- B1 = B2 = B3 SHA256: `43297a02ef284e8f872404a316b5768382889aef3232934d4d2b50d526104d97`.
- M2 = M3 SHA256: `3e3a6f5107e8d6b59e43378b6888ac9a1ab2bb17e05edb3321aafc1f02551ca2`.

The compiler has 408,343 source bytes, 74 functions, 1,411 blocks, 5,295
operations and maximum SSA index 1,822. The original compiler limits remain
128 functions, 1,536 total blocks, 8,192 operations, maximum SSA index 2,047,
and 1 MiB each for source, output and workspace. The generated flat compiler
image is 671,181 bytes. These measurements are finite source/target identities,
not a general resource proof.

## Observed results

| Qualification | Result | Scope |
|---|---:|---|
| Final source tests | 29/29 | Core admission, exact source generation, inventory, bounds, ownership-flow references |
| Final inventory checks | 2/2 | Support identity and public release bootstrap inventory |
| Fresh B0 native qualification | 853/853 | Original and modified self-compilation, existing regressions and owned ELF cases |
| Source-only cold replay | 10/10 | Fresh isolated Python process, no inherited machine images; nested 853/853 |
| Language regression | 910/910 | Both original B3 and mutated M3; 824 scalar witnesses |

The owned suite executes 31 valid Core programs and refuses 45 inputs with each
of B3 and M3. Valid programs include empty and nonempty allocation, optional
allocation failure, mandatory allocation traps with observable preceding
writes, repeated owner moves, nested loans, two-owner calls, forwarding calls,
tail self calls, renamed CFG joins, loop backedges and maximum SSA results.
The independent VM observes every returned owner/loan lifecycle; native
successor and direct-backend executions compare complete output bytes and
return/trap observations. VM heap-budget exhaustion is explicitly distinct
from a semantic optional-allocation failure.

The language regression retains 66 positive programs, 250 refused inputs and
136 trap cases per compiler. The source-only replay takes 92.92 seconds within
its existing 180-second deadline. Main native qualification takes 95.00 seconds;
language regression takes 65.76 seconds. These wall times describe this run
only and are not a performance-benefit claim.

An initial fresh-native attempt encountered `ENOSPC` before it created its
evidence directory. That attempt did not run qualification; its original log
is preserved separately. The completed run used a fresh output name. Earlier
17/11 and 31/45 development qualifications remain in the preliminary archive
with their original source identities.

## Semantics and trust boundary

The public entry remains the six pointer/length arguments for
`(readbuf, mutbuf, mutbuf) -> u32`. Owned types and all four new operations are
refused in flat modules before output writes. Internal functions can consume
owners but still return one scalar. Only `buffer.try_new` has two instruction
results, in the exact order `(buffer, bool)`.

Positive sizes up to `INT64_MAX` use `calloc(1, size)`. Zero is a live empty
logical owner and optional allocation reports success. Oversize or null
allocation returns an empty owner and false for `try_new`, or causes a Core
allocation trap for `new`. Drop calls `free` for a nonnull allocation and adds
no new Core trap. A live descendant loan prevents owner movement, drop or
owner-taking calls. Normal returns must consume or transfer every owner.
Heap storage is supplied by libc, independently of compiler workspace.

The object has one public entry, the closed `calloc/free` undefined-function
set and `R_X86_64_PLT32` call relocations. Native HIA writes these bytes. A
read-only inspector and `readelf` check them; ordinary GNU ld and the existing
child link/load the result. The libc allocation/lifetime contract, SysV ABI,
linker, loader, kernel and hardware remain explicit dependencies. This is the
same allocator family as the independent direct backend; the earlier
conditional mmap/munmap helper experiment is not used here.

**Report-field precision:** the archived main report inherited the field
`python_parser_or_codegen_after_B0: false`, which had described the successor
compilation path. In this v12 qualification, the host does execute its
independent Core VM/direct-backend oracle after B3. The correct scoped facts
are `python_parser_or_codegen_in_successor_compilation: false` and
`host_reference_codegen_after_B0: true`. The delivery summary records that
distinction; the root integration has been asked to make the main field
explicit before its final same-source CI. Historical raw receipts have not
been rewritten. Every native successor compilation still records an empty
forbidden-compiler-module inventory.

Recursive owner chains, returned resources, general multiple-result function
ABIs, arbitrary effect combinations and complete general Core syntax remain
unsupported in this v12 profile. Finite tests do not prove all accepted Core
inputs, allocator behavior, machine execution, ABI/FFI, resource semantics or
loading. The six broad acceptance gates must retain those remaining gaps.

## Reproduction and evidence

Run against a fresh output path in the exact source checkout:

```sh
python -B tools/qualify_hia_selfhost.py --output native.json
python -B tools/replay_hia_selfhost_cold.py --output cold.json
python -B tests/test_hia_selfhost_language_coverage.py --output language.json
python -B tools/qualify_hia_selfhost_owned_elf.py --compiler native.evidence/B3.image.bin --output owned-only
```

All 17 changed source files, their byte lengths, SHA256 values and Git blob
identities are listed in
`source-manifest.json` (historical path `../review-evidence/hia-selfhost-owned-elf-20261108-5e6c/source-manifest.json`; not shipped in this tree).
`qualification-summary.json` (historical path `../review-evidence/hia-selfhost-owned-elf-20261108-5e6c/qualification-summary.json`; not shipped in this tree)
records the scoped results and all archive hashes. The native, cold, language
and preliminary ZIPs retain source inputs, machine artifacts, source-only
export, independent references, object inspection, linker logs and raw child
requests/receipts/outputs. Compression was followed by exact member comparison
before removing any already archived development outputs to recover space.
