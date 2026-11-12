# Unmodified musl 1.2.5 `strncmp`

`strncmp.c`, `COPYRIGHT` and `UPSTREAM_README` were extracted byte for byte from
the official release archive identified by `UPSTREAM.json`. The implementation
retains its original `if (!n--)` and short-circuit cursor loop. The complete
upstream license is retained. No function body is manually rewritten.

The declaration-only `platform/string.h` and explicit read-slice contracts are
authored Hepta adapters. Both pointer parameters must refer to initialized,
live storage with at least `n` bytes, even when an earlier NUL would let the C
implementation stop sooner. That contract narrows the original input domain;
it does not infer ownership, provenance or arbitrary foreign-pointer validity.

The qualified build is C11 on the observed Linux LP64 target with
`-funsigned-char -fno-builtin -O2 -fPIC -Iplatform`. The signed-char configuration
is intentionally rejected by the existing typed-slice cast check. No implicit
signed/unsigned byte-view reinterpretation or other build configuration is
qualified. The independent HIA target exports only its authored scalar client;
it does not expose a native `strncmp` pointer ABI or link the original C body.

The new finite qualification captures original AST text, generates and verifies
the same HIA Core used by the VM and direct LLVM backend, compares against the
original native C implementation and an independent byte-string oracle, and
observes allocation refusals and cleanup. It records all cases and source/tool
identities. These observations do not prove all-input equivalence, universal
C/C++ migration, performance superiority or low human migration cost.
