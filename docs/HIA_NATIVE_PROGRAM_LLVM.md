# Native HIA LLVM emitter

The emitter interprets verified standalone Core and renders LLVM in ten HIA
roles: owner, decoder, module, scalar, memory, bulk, flow, initialization
analysis, vector recognition and guarded outlining. The fixed assembly prefix
checks buffer views and routes direct calls. It contains no source interpreter,
LLVM rendering logic or host callback.

The component retains the existing v1 through v9 primitive lowering,
three target ABIs, conservative initialization analysis, x86 byte-sum vector
recognition and guarded outlining. Exact native output is compared against
the retained renderer as an independent development oracle.

## Construction and limits

Twelve modules, including the native packer and shared-image linker, compile
twice to identical bytes under the unchanged compiler budgets: 128 functions,
1536 blocks and 8192 operations. Each role remains bounded by 4 MiB and total
text by 16 MiB. The native `HIALLPK1` packer checks ten roles and supports an
ELF object or flat image. Its 58 rejection controls preserve output sentinels.

Native packing produces a 1,372,648-byte object and a 1,371,977-byte flat image.
The native HIA linker produces a 1,381,136-byte shared image. The object and
flat bytes equal the independently constructed qualification products; the
shared image has no platform imports.

## Native behavior

The current shared image passes all 26 unchanged original LLVM, byte-sum and
initialization tests with no failures, errors or skips. Tests compile actual
HIA-rendered LLVM with real Clang, execute it, observe allocator events, test
page boundaries and observe real aborts for invalid arithmetic and bounds.

The prior 15-case direct emitter campaign also compares canonical output for
all three targets, initialization variants and guarded outlines. Three outlined
programs execute 408 argument vectors each. Their outputs remain identical to
the current flat image.

An expanded 171-test primitive run originally had 169 passes and two failures.
The initialization negative-control seam has been corrected in the QA adapter
and now passes unchanged in the current 26-test run. That deliberate control
records the correct native hash, then changes exactly one known initialization
flag only when the original test explicitly mocks initialization admission.
The mutation is labelled unverified fault-control output and never enters the
production emitter.

The remaining expanded gate requires the original pinned AArch64 QEMU 8.2.2
executable. Its required SHA-256 is
`e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e`.
The current available QEMU does not match, so that gate remains unqualified.
No version or hash requirement has been weakened.

## Scope and reproduction

This component qualifies actual native LLVM bytes. Public verification,
compiler discovery, compiler identity, bounded process capture, publication and
receipt objects still require their native outer integration. The development
campaign uses the retained Python versions of those outer operations as
explicit oracles; it makes no whole-runtime or whole-release claim.

Use `tools.qualify_hia_program_llvm_native_build` with `--compiler` and a new
`--output` directory. Then run `tools.qualify_hia_program_llvm_native` with
the resulting library, output directory and independently captured Z3 Python
and native-library paths. The core campaign includes the initialization
negative control. The primitive campaign retains the full original suite and
accepts `--qemu-aarch64` without bypassing its original executable pin.

The machine-readable qualification binds every HIA source, mechanical bridge,
development author, product and retained report. Python authors and test tools
remain outside the production graph.
