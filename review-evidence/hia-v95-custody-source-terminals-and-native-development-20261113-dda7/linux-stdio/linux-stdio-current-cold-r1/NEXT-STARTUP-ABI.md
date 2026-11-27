# Subsequent startup/stdio ABI assessment

Status: design only; no compiler, public profile, native entry or tests changed.
The frozen fd 0/1 profile and its `VerifiedLinuxStdioProgram` authority remain
unchanged. No result in this document is part of the cold overlay qualification.

## Exact existing boundary

The HIA entry packer currently passes three borrowed buffers to `f0`: an empty
read-only source and distinct zeroed 1 MiB output/workspace buffers. The entry
then exits with the low byte of the returned value. Its fixed CPU entry preserves
the inherited SIGPIPE disposition; it supplies neither argv nor environment.
The public verifier and reference VM use a distinct explicit profile, never the
ordinary Core/Code authority. The compiler is currently 126 functions and 8,123
operations, below the unchanged 128/8,192 limits. That headroom is not evidence
that an additional startup ABI already fits.

The discovery JSON work is a separate buffer owner. Its successful output does
not supply argument decoding, environment lookup, stream encoding, terminal
width observation or the installed CLI's full error and exit behavior. Those
remain explicit integration work, including the original Python parser and
formatter behavior where those providers are still used.

## Smallest defensible next boundary

A subsequent profile should expose a read-only **kernel-startup capability**,
created only from the original process entry state. It must retain ordered raw
argument and environment byte strings, including duplicate environment entries
and invalid text bytes. The mechanical boundary must not choose five environment
variables, convert text, collapse duplicates, implement argument policy, or
construct a Python-style argument frame. HIA policy owns those operations.

The design needs an explicit bounded way to enumerate and copy individual raw
strings. Using an unconditional 1 MiB combined snapshot is insufficient to claim
compatibility with the existing CLI, which has no matching front-door combined
snapshot rule. Oversize behavior must be proved against that actual input
domain. It must not silently discard ignored variables or add a new whole-CLI
input rejection. A typed startup-view/copy protocol is preferable to exposing
arbitrary addresses as integers. Native entry captures actual kernel state;
the VM takes an explicit immutable reference snapshot. A serialized snapshot
never becomes native process authority.

A separate fixed stderr write can reuse the existing borrow/bounds/signed-result
semantics, but requires its own explicit opcode/effect/profile and actual native
code path for fd 2. It must leave the current profile's rejection of
`linux.stderr.write` intact. Neither syscall numbers nor descriptors become
user-supplied arguments. All three fixed descriptors retain one-call short-I/O,
negative errno, zero-length, signal and cleanup observations without implicit
retry.

## Conditions before implementation can close a public CLI path

- Specify the new authority and entry schema separately from both ordinary
  Core and the existing fd 0/1 profile. Public parser, types, effects, loans,
  reference VM and native backend must agree on the same capability domain.
- Capture startup storage before using or replacing its stack. Establish exact
  extent, lifetime, immutability and copy bounds; never borrow an entry-stack
  pointer after its lifetime or let an ordinary buffer forge it.
- Prove native/VM ordering and complete bytes for empty arguments, duplicates,
  non-text bytes, boundary lengths, invalid descriptors, short writes, errno,
  inherited/default SIGPIPE and interrupted observations.
- Retain all existing compilation and buffer limits. Recompute actual function,
  block and operation counts and the L1/L2/L3 fixed point. If startup needs a
  distinct HIA module or resident-image call, state and implement that boundary
  explicitly rather than adding host code generation or widening the common
  compiler.
- The discovery JSON buffer protocol can then be a semantic consumer. Producing
  `HCLIARG4` UTF-32 input belongs to HIA policy; actual argv/environment data,
  stdout/stderr encoding, tty/columns and exit behavior still need their own
  source-bound observations and ordinary CLI callers.

This assessment does not replace the 64 MiB source-builder `.S` ports. They also
need admitted resident-image calls, their three-buffer extents, read-only capture
and publication sequencing. Neither the current direct ELF prototype nor a
future fixed fd 2 operation supplies those contracts by itself.
