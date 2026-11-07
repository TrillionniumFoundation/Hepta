# Hepta / HIA

HIA is a typed assembly language for Agent-authored programs, with explicit Core
semantics, resource checks and native code generation.

## One release entry

Use **`python3 -B tools/hia_release.py`** with the default
[version contract](releases/hia-current.json). That contract binds Hepta, runtime,
worker, backend, the eleven-tool HIA catalog, target, ABI and the Selfhost-Core
subset. Full commit hashes and measured file identities select the release.

This branch supplies release metadata and the entry files. The implementation
is obtained from the exact source commits in the contract; the checkout of this
branch is not the worker installation. The source commit precedes the metadata
commit that carries its lock.

With Python 3.11+ and Git, inspect the contract and create a new source directory:

```sh
python3 -B tools/hia_release.py describe
python3 -B tools/hia_release.py materialize --directory /absolute/new/hia-release
python3 -B tools/hia_release.py check \
  --hepta-root /absolute/new/hia-release/hepta \
  --runtime-checkout /absolute/new/hia-release/runtime
```

The entry fetches the exact public GitHub commits and measures the declared
source and installed capability identities. It refuses a different commit, a
modified required file, a worker bytecode/native shadow, or an existing output
directory. It does not fall back to another branch or remote. Dependencies and
the runtime executable must be provided by the environment.

## Selected contract

| Component | Selection |
| --- | --- |
| Release | `hia-v6-20261107-faa85-r5` |
| Contract SHA-256 | `82853c9b804ecabc3760d0235b3c3aac54b0e54d838f7255887e070de8b6bab8` |
| Hepta source | [`3ead0f535c271b07766c5d7c5d15ca69f0f3e8df`](https://github.com/TrillionniumFoundation/Hepta/tree/3ead0f535c271b07766c5d7c5d15ca69f0f3e8df) |
| Runtime source | [`c53917f4d147fbdb3ce0e094bc9c32a305411866`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/c53917f4d147fbdb3ce0e094bc9c32a305411866) |
| Target | `x86_64-unknown-linux-gnu`; ELF64 / AMD64 / little-endian / LP64 |
| ABI | System V AMD64; scalar and explicit borrowed-byte profiles |
| Core subset | `selfhost-core-linux-x86_64-v6` |
| Native code generator | `hia-direct` |

The full worker, backend and catalog digests are in the contract. Read the
[release guide](docs/HIA_RELEASE_ENTRY.md) for offline local Git transports,
worker preparation, whole-server discovery and exact binary probes.

## Supported scope and qualification

Selfhost-Core v6 supports its fixed borrowed-buffer subset, bounded ELF object
profile and direct tail self calls with zero additional native stack frames.
Non-tail or mutual recursion, owned allocation/free, ownership transfer, newly
created or returned loans, a general checker, external relocations and general
ELF linking remain outside that selfhost subset. The complete support matrix,
seed implementation, compiler source and loader identities are pinned by the
contract and available in the materialized source.

Cold replay uses a fresh source directory, HOME, temporary directory and isolated
Python state. It shares the host's kernel, Python executable, linker and libc.
The required observations are B0→B1→B2→B3, B1=B2=B3, and a changed source reaching
M2=M3 with M2 different from B2; this is not a fresh-VM guarantee.

Explicit r8/r9 leaf plans are opt-in and have a finite operation whitelist.
Measured finite-workload results do not establish a default speedup, general
register allocation or NDU economic benefit.

The source contract is a reproducibility boundary. Formal endpoint operation,
current-Agent discovery of all eleven tools, production before/after task
inventories, successful first-use maintenance, CI and complete-cost NDU
comparisons retain their own acceptance receipts. Selecting this source does
not turn a held or failed operational gate into a pass.

## Previous candidate

The earlier [d21359485776 candidate](https://github.com/TrillionniumFoundation/Hepta/tree/d21359485776c0a9687e88d0f69c8ec06a3b3b98)
and its [636c3189722e evidence snapshot](https://github.com/TrillionniumFoundation/Hepta/tree/636c3189722e9bb48c39913e779d688c4e8cbcb3)
remain historical records. The default contract above selects this entry's
release; the older candidate is not a second default installation route.
