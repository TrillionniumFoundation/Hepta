# Original C1 output versus the unchanged Safe Core contract

## Result

`HOLD_C1_SAFE_CORE_CONTRACT_DISJOINT`.

This is a new, isolated replay of the original frozen `select` candidate C1.
It is not the newer v13 compiler and is not a replay of the Python-generated
scalar fixtures used to qualify the CMOVNE instruction model. The original
Agent four-claim gate and unavailable historical provider costs remain HOLD.

The declared entry contracts are incompatible: C1 requires its first function
to be `f0(readbuf, mutbuf, mutbuf) -> u32`; the existing Safe Core profile admits
at most one borrowed range. Parameters remain part of that contract even when
a particular function body does not use them. This conclusion is about the
explicit contracts; five finite trials are not a proof of the C1 implementation
for all malformed source bytes.

## Exact provenance

| Subject | SHA-256 |
| --- | --- |
| Original candidate C1 assembly source | `2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845` |
| C1 canonical Core | `10284cea893a06091e3bb1de5c9e593148915469f820993d49952386503c428b` |
| Original frozen patch | `e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4` |
| B0 object, emitted from that exact C1 Core | `02445754182d51ae6898418a59b4d2f6f6764be7918ddd3486f08a1cefaed9e3` |
| B0 ordinary shared image | `d1efef90cc9e2f89c8bceab1a68c2b7fb4fe5468dcab149bfe22092d11bcf002` |
| C1 successor image, produced by native execution of B0 on exact C1 source | `f7dcf41864bb22793a60d12daace55ea35143733c536db7bf13f35b15efd4110` |
| Replay driver | `ba5d78c244b64225ea1c20c75607135dd1b50b5583ddd4e4ee427f289eea9e85` |

The successor contains 514,342 bytes. There is exactly one self-compilation in
this replay; no fixed-point result is claimed. The Python seed is an explicit,
unproved translation of C1. The successor's provenance identifies the bytes
that actually ran, without turning that provenance into a compiler correctness
proof. The five leaf objects were then emitted by native execution of this
successor, in the existing stdlib-only selfhost child. No Python leaf emitter
produced those object bytes.

The checker source snapshot is the CMOVNE source commit
`aad3bbb4f3cb7d08362d197704b3c99a4eb651c2`, with its full per-file source hashes
retained. The original generator was separately reconstructed for read-only
analysis: `tools/generate_hia_selfhost.py` from original source commit
`d1c97d22d503b395ba9b0dfaa87e5a1c1b208fe6`, with only the corresponding entry
of the original frozen patch applied. Its resulting SHA-256 is
`beed189aa57374d9b2c66c492f9ab6323a697ccb0592d2fc128a60a46688f9e4`.
That authoring source was not used to regenerate or replace C1.

## One five-type, bidirectional replay

For each of `u8`, `u32`, `u64`, `usize` and `bool`:

1. A small, valid, single-function Core source uses the exact C1 three-buffer
   entry. Its condition and both selected values depend on caller bytes. C1
   emits a normal `selfhost_elf` object, and ordinary GNU `ld` links it without
   any ELF metadata modification. The exact original Core, exact C1 object and
   exact final image are passed together to `validate_safe_core_artifact`.
2. The validator refuses each with
   `E_HIA_SAFE_CORE: one borrowed range and at most six ABI argument words are admitted`.
   It issues no validation report, counterexample or SMT proof: rejection occurs
   at the declared Core profile before final-machine checking.
3. In the reverse direction, a three-scalar `select` function passes both the
   ordinary Core verifier and the existing Safe Core syntax/profile admission.
   That exact assembly is passed to the same native C1 successor. C1 returns
   `INVALID` (`4294967295`); input and output remain unchanged.

All ten outcomes match the declared boundary. There are 11 native compiler
calls including the single self-compilation, five linked C1 output objects,
zero issued machine proofs and zero native calls to the resulting leaf images.
There is no source transformation, new wrapper, profile relaxation, adoption
or fabricated positive proof in this replay.

Ordinary retained `objdump` output shows one actual `48 0f 45 c1` (`cmovne
rax,rcx`) instruction in each C1 leaf object. This is a disassembly witness to
the actual output bytes, not a semantic validation of the whole artifact.

## Why extracting a fragment is a different proof subject

The independent reviewer confirmed additional machine-language boundaries in
the original C1 emitter. Its stack probe uses `48 8b 04 24`, which the current
decoder rejects because it only admits ModR/M modes 2 and 3 for memory access.
Its u32 normalization emits `89 c0`, while ordinary moves in the current model
require REX.W. Its u8 normalization uses `48 25 ff 00 00 00`, whose accumulator
AND encoding is also outside the current decoder. The `TEST`/`CMOVNE` fragment
itself is now admitted, but depends on upstream normalized scalar slots.

A scalar adapter around an extracted function would have to bind exact source
object bytes and complete function boundaries, translate scalar SysV arguments
to the original private argument-vector/result-pointer ABI, and prove the
incoming slot invariants, saved state, stack use, return conversion and any
relocations. Extracting only the seven TEST/CMOV bytes does not establish those
facts. Such an adapter would be a newly constructed subject. It would not be a
proof of the original complete C1 output, nor of C1's own lowering refinement.
No such adapter was constructed here.

## Evidence and reproduction

The raw archive retains the exact C1 source, original patch, read-only generator
reconstruction, all 212 checker/backend source files, B0 object/build/image,
successor image, all native requests and full output buffers, five input Cores,
five C1 objects and final images, normal linker logs, disassembly, five actual
validator refusals, five scalar input Cores and their actual C1 refusals.

Run the same one-shot evidence driver in a source tree containing the pinned
checker/backend and `tools/hia_selfhost_child.py`:

```sh
python -B tools/qualify_hia_original_c1_leaf_boundary.py \
  --candidate EXACT_FROZEN_C1.hiaasm --output NEW_DIRECTORY
```

It verifies the exact C1 source and Core hashes and launches a fresh worker with
`-B` and an empty bytecode cache prefix. The resulting status deliberately says
HOLD. A successful driver exit establishes that the strict refusal boundary was
reproduced; it does not establish positive machine refinement.

The next complete engineering scope is described in
`docs/HIA_C1_MACHINE_PROOF_PLAN_20261108.md`. Current frozen release sources were
not modified by this investigation.
