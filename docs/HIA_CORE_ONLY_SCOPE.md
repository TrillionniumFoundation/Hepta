# HIA Core-only product scope

HIA Core and Agent interfaces are the only active language product. The high-level
source language, AST, source checker, source-to-Core and C/C++ migration adapters,
source-language native parser ports, exclusive tests/examples/docs and CLI have
been removed. They are not shipped as a reference or compatibility package.
Git history and separately held qualification evidence are not rewritten.

The `hepta` Python namespace and `hepta.hia.*` schema names are stable Core
identifiers, not a retained high-level language. The sole installed CLI is `hia`.
HIA retains its own type, ownership, borrow, resource, control-flow and effect
validation. Its semantics and compiler limits were not relaxed by this removal.

## Qualification boundary

This tree has a new explicit Core-only source closure. Old mixed-language
source/projection gates and historical release locks do not qualify this tree;
they were retired, not reported as passed. Generated HIA compiler, JSON frontend,
Agent dispatcher/packer and native ELF linker bytes are preserved. Fresh-source
cold bootstrap and original/modified-source witnesses must be run for this tree.

## Remaining blockers

- Hosted Agent editing still requires Python; native stdio implements only
  capabilities, Core verify and compile, not snapshot-bound edits or persistence.
- Native module graph/build orchestration and runtime/standard-library coverage
  remain incomplete. Research backends and host qualification tools are not
  production-native replacements.
- Durable publication/recovery, installation, bounded artifact lifecycle and
  clean-machine real-project acceptance remain open.
- Full native defaults and old production-stack retirement await those gates.

Removing the obsolete source language does not turn an unfinished HIA component
into a completed one. No live service, default release or external runtime is
changed by this source-tree transition.

## New qualification artifact lifecycle

New selfhost phase stages are packed only after their direct worker exits and
its exact report/input identity is checked. A ZIP retains every original file,
mode and SHA-256; a full independent replay and unchanged-original check precede
raw-stage retirement. Per-phase receipts explicitly name the archive and state
that raw member paths require recovery. Existing/pinned evidence is never swept.
This host-only lossless retention reduces repeated large zero-filled captures;
it is not yet unified native artifact management or global cache eviction.
