# Experimental canonical Base64 source library

[P12](BLOCKERS.md) still requires a production standard library. This bounded
increment provides `hepta_base64` 0.1.0 as ordinary Hepta source under
[`stdlib/base64`](../stdlib/base64/hepta.toml). It adds no compiler intrinsic,
runtime dependency, foreign call or allocation. P12 remains PARTIAL.

The format is the standard alphabet and canonical padded form in
[RFC 4648 sections 3.5 and 4](https://www.rfc-editor.org/rfc/rfc4648.html#section-4).
Base64 is an encoding, not encryption, authentication or a constant-time primitive.
This is a repository-local experimental API, not an installed Python resource or
stable production standard library. Keep the manifest and source together when
vendoring it. No other research draft is needed or composed.

## Public contract

Add a local dependency to the consumer's `hepta.toml`:

```toml
[dependencies]
base64 = { path = "../vendor/hepta_base64" }
```

Then `import base64;`. All four functions return `Size { bytes: usize, ok: bool }`.
On failure `bytes` is zero and `ok` is false. A successful empty result also has
zero bytes, so callers must inspect `ok`.

- `encoded_length(length: usize)` returns the padded encoded size. It rejects
  arithmetic overflow before multiplication. Its bound uses the compiler's
  current qualified 64-bit `usize` model.
- `decoded_length(input: read [u8], start: usize, end: usize)` validates the
  **entire** half-open input range and returns its decoded size. It rejects
  invalid bounds, non-alphabet bytes, missing/excess/interior padding, invalid
  lengths and nonzero unused bits. Whitespace and URL-safe `-`/`_` are rejected.
- `encode(input: read [u8], start: usize, end: usize, output: mut [u8], offset: usize)`
  writes the canonical encoding at the output offset and returns bytes written.
- `decode(input: read [u8], start: usize, end: usize, output: mut [u8], offset: usize)`
  validates the whole input before writing the decoded bytes. It returns bytes
  written, not an absolute destination index.

Both transforms check the input range and output capacity before any write. On
invalid input, invalid offset or insufficient capacity, **every output byte is
unchanged**. On success, bytes before and after the written region are unchanged.
Input is read-only. An empty valid input range succeeds at any offset up to and
including the output length. Aliased input/mutable output is not supported;
ordinary source borrowing rules apply and the C backend rejects same-root aliases.
Foreign callers bypassing those rules are outside this package's public contract.

For example, `Zg==` decodes to `f`, but `Zh==` rejects because its unused bits are
nonzero. `Zm8=` decodes to `fo`, but `Zm9=` rejects. `AA==AAAA` rejects without
writing a decoded prefix. Unpadded groups such as `Zm9v` remain valid because the
complete group needs no padding; incomplete groups must use padding.

Encoded-size calculation is O(1). Decoded sizing and encoding are O(n); decoding
performs a full validation pass followed by a write pass and is also O(n).
Auxiliary storage is constant. No recursion, unsafe
operations, foreign calls, blocking, suspension or spawning are used. All functions
have zero-heap-allocation resource clauses. Conservative `panic` effects remain
because the checker does not prove the arithmetic/index guards; transforms also
declare `write`. Failure preservation covers ordinary returns, not concurrent
mutation, hardware faults, process termination or signal/crash-atomic writes.

The [locked packet example](../examples/packages/base64_packet/src/main.hepta)
executes through the public CLI:

```sh
python -m hepta run examples/packages/base64_packet --locked --backend c --json
python -m hepta run examples/packages/base64_packet --locked --backend rust --json
```

The selected real native compiler is required. Rust requires pinned rustc 1.90.0.
Source content locks do not authenticate authorship or prove behavior.

## Reproducible checks

```sh
HEPTA_BASE64_BACKEND=c python -m unittest discover -s tests -p test_stdlib_base64.py -v
HEPTA_BASE64_BACKEND=rust python -m unittest discover -s tests -p test_stdlib_base64.py -v
python tools/stdlib_base64_oracle.py
```

The public suite has 11 methods and requires its selected compiler without skips.
Native consumer cases run at O0 and O3; C additionally uses undefined-behavior
sanitization with recovery disabled. RFC vectors, every single-byte encoding,
independent canonical decodings, deterministic multiple-quartet inputs, malformed
suffixes, range/capacity boundaries and maximum offsets are checked against Python
`base64`. Strict decoding is followed by independent canonical re-encoding because
Python alone accepts some noncanonical trailing bits/padding. Every backing input
and output byte is checked, including failed writes. Cases are partitioned into
bounded translation units without dropping assertions.

Additional methods check overflow-safe encoded sizing without huge allocations,
repeated calls, borrow/type/mutability/effect refusals, both frontend lowerings,
resource clauses, no_std emission, relocated/stale locks and the real CLI. The Rust
lane additionally produces a native no_std object. Frontend/no_std emission in a
C-only lane does not establish native Rust execution.

The separately authored supplemental oracle uses temporary **compiler-private
generated-C ctypes adapters**, not a public C ABI. Each complete deterministic
corpus runs separately at O0 and O3 with nonrecovering UBSan: 189,028 cases per
lane, including all zero/one/two-byte inputs (65,793 encodings and 65,793 canonical
decodings), 18,432 every-byte mutations, 8,000 randomized valid transforms, 7,964
insufficient-capacity cases, 12,000 randomized ranges/capacities, 11,025 encoded-size
boundaries and 21 explicit empty/bounds/invalid-length cases. Physical input/output
canaries and whole backing bytes are checked, including private zero-length views.
Each lane records library, compiler source, generated C, adapter and full translation
unit hashes. These are finite tests, not exhaustive arbitrary-length validation.

The read-only [workflow](../.github/workflows/stdlib-base64.yml) checks the exact PR
head with C/Rust on Linux x86-64/AArch64 and Python 3.11/3.13, requires all 11 methods
with no skips/expected failures, and retains source/tool identities and raw output.
Hosted outcomes must be read for the exact commit. A workflow definition or local
C pass is not an unobserved native Rust/ARM/hosted success.

No URL-safe alphabet, permissive MIME whitespace, streaming state, text ownership,
application authentication or cryptographic timing guarantee is included. There is
no full-project, arbitrary-platform, formal, performance or release qualification.
