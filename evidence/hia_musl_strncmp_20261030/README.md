# Real musl component migration and subsequent-release maintenance

This archive retains one complete, unmodified upstream generic `strncmp`
function, captured and lowered into HIA Core, with an authored owned scalar
client and direct LLVM native code. The function's `if (!n--)` originally
rejected with `E_C_UNARY`. The frontend change adds finite local integer
postfix `if` conditions with explicit old-value/update/branch sequencing.

## Frozen executions

| Input | Implementation commit | Fresh cases | Native observations | VM observations | Whole qualification |
| --- | --- | ---: | ---: | ---: | ---: |
| musl 1.2.5 | `46534e04ec874bd5681b9f38914e210c2ef813be` | 1,158 | 2,316 | 1,158 | 32.090588394 s |
| musl 1.2.6 | `f82d016e08431bf9c16d12a613bfab6151103d8a` | 1,158 | 2,316 | 1,158 | 29.470750382 s |

The fixed matrix contains 386 inputs, each with no allocation refusal, refusal
at the first allocation and refusal at the second. Every original-C native,
HIA LLVM native and HIA VM result matched the independent byte/resource oracle.
The original C function is linked only into the reference executable. The HIA
target uses the HIA object and an observation harness, without the original
implementation or Rust code generation.

Both inputs produce Core digest
`831ce9c34374520b4d4b912638a4ef85809e3775794793807787480cc6bd2699`.
This is an identical-byte maintenance case: the original 220-byte function and
authored contracts/header/client do not change. The complete upstream COPYRIGHT
changes from 6,204 to 6,196 bytes. The maintenance command independently captures,
builds and observes the newer release; it does not copy the previous results.
The same regression matrix is deliberately reused and is not a new holdout.

## Actual recorded costs and failures

The later release's capture/lowering/verification took 1.852269697 s. Its direct
LLVM native build took 0.184467076 s. The reference/client/observer builds and
two links totalled 0.203236068 s. The entire maintenance command, including
baseline replay and archive validation, took 29.781409733 s, excluding the
separately recorded six-request acquisition interval of 0.973545013 s. Earlier
discovery, failed requests, compiler installation and development effort are
outside these intervals. They are not estimates of human labor or a comparative
migration saving. Runs used a shared host, not a performance-isolated machine.

The pre-change source rejection is retained. The first Clang 20 test attempt
failed because the extracted libclang dependency `libLLVM.so.20.1` was absent
from the loader search path; that failing log remains in the archive. After
configuring the explicit loader path, all eight focused tests passed. Twenty
existing scalar/cursor/loop-control regression tests also passed. Following the
version-selection extension, the eight focused tests passed again. Repeated
tests are not added together as independent test coverage.

## Upstream and configuration

Official release archives, complete source/license/README files, acquisition
receipts and mirror commit identities are all retained. Release 1.2.6 was
[announced by the maintainer on 2026-03-20](https://www.openwall.com/lists/musl/2026/03/20/1).
The official cgit endpoint returned HTTP 503; the exact tag commit therefore
comes explicitly from the public GitHub mirror. Commit-pinned mirror file
bytes independently matched the official archive members. No PGP signature
verification is claimed.

The admitted profile is C11, unsigned `char`, Linux x86-64 LP64, `-fno-builtin`,
`-O2`, `-fPIC`, with two initialized read slices each of at least `n` bytes.
The authored scalar adapter bounds `n` to eight bytes and owns both allocations.
It rejects excess length, handles allocation refusal, and frees successful
allocations on every return path. Its empty-input case observes zero native
allocation attempts. The signed-char configuration still rejects the unqualified
pointer element reinterpretation. Only the scalar client is exported.

## Offline verification

```bash
python evidence/hia_musl_strncmp_20261030/verify_archive.py
```

This standard-library-only command verifies the compressed archive and every
member, rehashes 160 baseline and 168 successor implementation-bound files,
compares the official archive members against the captured inputs, recomputes
all 2,316 matrix cells, matches their 4,632 native process receipts, checks all
VM resource observations, and checks identical Core and fixed input matrices.
It does not extract or execute archived code. Receipt replay is not an
independent agent review, a fresh native rerun, or cryptographic attestation of
the original execution.

The archive retains all project/capture/build/native/VM outputs and process
ledgers, both official release archives, the implementation source snapshots,
the successful and failed development logs, and the pre-change rejection. The
visible maintenance report is required to match the archived report exactly.
Binary artifacts are retained inside the byte-checked archive, not executed
by the verifier. Local absolute paths in original receipts are preserved as
historical evidence and mapped by the verifier; they are not portable commands.

## Claim boundary

This is one complete generic component plus authored adapters. It does not
establish complete musl migration, arbitrary foreign-pointer ABI compatibility,
general C++ library reuse, automatic adaptation to a changed function body,
all-input source/backend equivalence, superior performance, or measured human
or model development efficiency. Signed-overflow traps and unsupported lvalue,
side-effect and narrowing cases remain covered by explicit rejection tests.
The prior Agent-study results and stopping rules are unchanged.
