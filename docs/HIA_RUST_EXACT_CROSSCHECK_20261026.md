# HIA P0/P1/P2: exact-byte Rust shadow crosscheck (opt-in)

Status: implementation candidate built on the existing PR #211 Rust scalar and
Owner/Loan verifier. The sole executable HIA admission authority remains
`hepta.hia_program.verify_program`. This change does not create a new ISA,
replace the Python verifier or alter native LLVM build and execution paths.

## Scope and enforcement

The new `hepta.hia_rust_crosscheck.crosscheck_rust_shadow` first calls the
existing authoritative Python verifier. It then loads a user-specified Rust
shadow executable using a Linux no-follow, bounded ordinary-file read, exact
SHA-256 pin and pre/post inode metadata check. The selected bytes are copied
into a new private executable before subprocess launch, so later mutation of
the caller's original path cannot swap the program about to execute.

The subprocess receives the **canonical verified HIA program bytes** via
stdin, uses the scalar mode or explicit `--owned-shadow`, has a finite timeout,
runs without a shell or inherited dynamic-linker/Python environment variables
and uses nonblocking stdin/stdout/stderr pipes with bounded in-memory
reads; an output flood or deadline violation kills its process group. This
is a development tool for a
caller-chosen, hash-pinned binary, **not a hostile-executable sandbox**:
the caller must trust the selected binary and host toolchain.

The returned report must have exactly the known scalar/Owner schema, full
function and block inventory, exact canonical program SHA-256, no extra keys
or duplicate JSON fields and the exact Boolean proof-claim inventory. The
unproved whole-language, native, provenance and production-authority claims
must remain the literal Boolean false. Missing executable, hash mismatch,
unsupported version/opcode, nonzero exit, output on stderr, wrong SHA,
malformed report, integer-0-for-false and timeouts all refuse.

## Read-only CLI

```sh
sha256sum /exact/path/to/hia-core-shadow
python -m hepta hia verify program.hia \
  --rust-shadow-bin /exact/path/to/hia-core-shadow \
  --rust-shadow-sha256 ACTUAL_64_HEX_SHA256 \
  --rust-shadow-profile owned
```

Pure scalar programs may use `--rust-shadow-profile scalar`. All shadow flags
must be explicitly and consistently selected; incomplete selections refuse.
Without these flags the original Python-only `hia verify` behavior remains
unchanged. `hia run`, `hia build`, C/C++ migration, Agent patch application
and native artifact publication do not consume this optional shadow report.

## Evidence and reproduction

```sh
python -m unittest tests.test_hia_rust_crosscheck \
  tests.test_hia_rust_crosscheck_cli -v
python -m unittest tests.test_hia_rust_shadow \
  tests.test_hia_rust_owned_shadow tests.test_hia_rust_calls_shadow -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python tools/release_check.py
```

An isolated Linux subprocess protocol test with a deliberately **mocked**
canonical Python verifier executed 5/5 test methods on the exact new bridge
and protocol-test source bytes. The fake shadow executables exercised good
scalar/Owner report structure, wrong binary pin, symlink refusal, forged
proof flags, wrong Core digest, extra fields, duplicate JSON keys,
stdout floods, unexpected stderr and timeout.
These tests do not certify Rust compiler output, true Hepta Core semantics
or backend refinement. The complete in-repository Python CLI suite and
actual Cargo/native HIA suites have not run on this exact Git SHA.

OPEN: complete typed Memory/Provenance SSA, Source→Core→LLVM refinement,
C/C++ L2/L3 and cross-toolchain ABI, SIMD/GPU hardware, genuine Agent/model
A/B, physical MMIO/DMA/IRQ, production resource/p99, signed release
evidence, Rust production authority and full language soundness.

`whole_project_blockers_closed=false`.
