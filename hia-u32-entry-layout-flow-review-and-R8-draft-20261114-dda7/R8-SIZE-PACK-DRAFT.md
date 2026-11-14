# Frozen R8: smallest explicit u32 size and packing experiment

This is a concrete authoring draft, not an execution authorization or a completed runner. It proposes one new R8 compilation and, only if the original framing bounds allow it, one actual HIA pack. It does not regenerate or edit R8, execute the new semantic resident, run an ELF, alter a production profile, or claim cold qualification.

## Fixed inputs

Use the actual hosted u32 B3 already extracted into `/tmp/hia-u32-entry-layout-r1-dda7/actual-inputs/B3.image.bin`: 658860 bytes, SHA256 `56cddd318fbdd7cd269c103fa70c8061d43a3bf9130e877961a5b8af2078c764`. Keep its original hosted request/receipt/output-prefix binding and 3180-file lineage. The label must identify a separately selected development u32 compiler; it is not ordinary B3 or a current-cold input.

Compile exactly `/workspace/scratch/dda74a4fae35/v117-dense-token-r8-r1/source/examples/hia_bootstrap/file_render_checker_v4.hepta`: 395910 bytes, SHA256 `83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de`, Git `093489201db8aa0eade2e2a91eddf95463ada4ea`. Its historical ordinary-B3 result is 562746 bytes, SHA256 `2138fd3f57a76e3ac5ad00fee9d2b1a3e36c0af24395b7c491a772d788a3ab21`. That old observation has no kernel/VM/pack qualification and remains untouched.

The minimal pack can reuse three actual already-built ordinary-profile images from `/workspace/scratch/dda74a4fae35/v99-canonical-roundtrip-process-r1/successor-r2/evidence/build-r2/built`:

| Role | File | Bytes | SHA256 from actual build report |
|---|---|---:|---|
| Controller | controller.image.bin | 59889 | `5f23e0aefb1cb4749c7ce4a8c50c694367357051144f34cec8867e32d5eba6e2` |
| Representation | representation.image.bin | 430261 | `0ba4d693b9533b13aa059b7e4bb68ba482119f2109f1ae87c44c0d6a72cddba7` |
| Pure HIA packer | packer.image.bin | 31031 | `7a5556523bfcc294c125106d837323a2cc5c5181b502a5ff99841e432aa0d839` |

This review read the original small report and directory inventory, not fresh binary bodies. Before freezing an executable successor, capture and re-read the real image bytes, original source, requests, stdout/stderr, receipts and complete output-prefix bindings for these three images. Require the actual original provider `6e8d31b694721b79c693417f0687338bc15277971496f6deaa7ff6e1ed357338`. No image is reconstructed from a report, no fallback provider is selected, and no image compilation is silently added if a retained input is missing. This is small-input capture, not a complete source-tree copy.

## Two possible actual calls, one unchanged owner

1. **R8 size call.** Copy the exact retained R8 `retained_buffer_observer.py` and `retained_buffer_child.py` into the new private author scope, preserving their complete bytes. Use the same `native` call shape as `run_compact_build_r1.py`, but an explicit caller/compiler source identity instead of the old hardcoded ordinary B3. Input is the exact R8 source; initial output is 1 MiB of A5, workspace is 1 MiB zero, stdin is empty and mode is `ordinary`. That mode is the observer's I/O setting, not a compiler encoding declaration. Preserve the old canaries, untouched-source, empty stdout/stderr, no forbidden modules, actual return, full three-region bytes and output-tail assertions. Retain complete before inputs, after shared buffers, child report, request and produced prefix. No u32 source or target IR is regenerated.
2. **Actual pack call, conditional on framing admission.** Form exactly the unchanged `<6Q` `HFRTPAK1` v1 header plus controller, representation and new semantic image. Preserve `_frame` and `_elf_structure` bodies from the frozen builder, with a separate private namespace and their original constants. Do not monkeypatch the public builder or `_checked_components`. If `_frame` rejects, retain that actual failure and do not invoke the packer. If it admits, invoke the exact retained pure HIA packer image once with this complete frame under the original compiler/loader ABI and bounds, capture all real buffers, and check the actual returned ELF against `_elf_structure` and all three actual payloads. The HIA packer produces all ELF bytes; Python only frames inputs and inspects the result.

Both calls, all integrity checks in their child and raw observation writes share one 180-second owner with 3-second cleanup. Each machine call retains 20 seconds, 10 CPU seconds, 1 MiB source/output/workspace, original canaries and remaining loader bounds. No test timeout/fuel is enlarged. No target semantic VM or resulting ELF is executed in this experiment. A storage preflight must cover the small captured inputs and full before/after outputs plus the existing reserve; it must not reserve or materialize a second source tree or original ZIP.

## Exact size condition from the retained pack layout

The previously recorded +10696 growth versus a 4096-byte remaining ELF page gave a conservative “6600 bytes over growth allowance” figure. Preserve that original observation and its wording as history. It is not the exact encoded-frame or final-ELF overflow.

With the actual fixed controller and representation sizes, `_elf_structure` places the controller at 1024, representation at 60928 and semantic image at **491200**. The old R5 ELF also has **1230 bytes of final padding**, in addition to the remaining 4096-byte page. The 48-byte input header permits a semantic image of at most 558378 bytes; the actual ELF layout is stricter and permits **557376 bytes**. Therefore the historical 562746-byte R8 image needs at least **5370 bytes** of actual reduction for this exact layout.

At the old R8 size, the hypothetical input frame is 1052944 bytes and the hypothetical aligned ELF is 1056768 bytes. These are static integer calculations using frozen formulas, not produced images. The actual original 1 MiB bound is unchanged. A static estimate of eligible immediate encodings is not substituted for the new real image or for actual HIA packing. The future runner should record both actual frame and ELF sizes and all physical offsets, not accept a scalar size estimate alone.

## Production and semantic gates remain closed

The real frozen builder function is `build_linux_file_roundtrip_program`; there is no `build_development` function in the reviewed R20 file. Its `_checked_components` still requires the old R5 semantic source SHA `2fbedf12008851e7f428fbc60fed144c0d0ebd99d7cc93e004058a8d5e375aa9`. Feeding it R8 would correctly reject. The proposed private pack observation does not change or bypass that production admission and must not label its output a v2 qualified build.

The original roundtrip cold reader first calls the original cold admission, requires the complete source closure and optional-profile identity, and re-admits fresh authority. Leave those functions and ordinary `SOURCE` unchanged. The u32 5052 report or an explicit B3 digest does not satisfy them. Production use requires a separately reviewed R8 profile/version, matching-current source closure and actual new-policy cold chain/reader; these are not performed here.

Even a successful size and pack experiment leaves R8's original 162 native inputs, six semantic VM cases including the original-10M failure, deliberate cache/overflow controls, and aggregate 130 kernel + 7 pipeline + 6 full-frame observations + 2 tail faults + real portable installation outstanding. The six full-frame observations belong to the pipeline group and are not six extra tests. The packed ELF must remain a nonexecuted development artifact until those independent gates are reviewed and authorized.
