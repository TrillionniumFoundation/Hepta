# Native cold exports qualification

This checkpoint migrates the complete original exports family to HIA plan replay. It does not mark the whole cold build or release complete.

The replay uses the current compiler source, an independently constructed complete HIA VM, an HIA ELF inventory owner and linker, and a separate dynamic observer that calls the complete sealed shared object through the real System V ABI. The plan derives every expected numeric export result from a fresh VM execution. `cold_exports_cases.json` contains source and caller inputs only. It contains no expected numeric results.

The original and modified compiler labels passed 281 calls each, including all 0–16-argument signatures, narrow and signed scalars, 128 dense exports, long names and changed declaration order. Each label also passed all four symbol and linkage checks, four dynamically sized short-output checks, 27 original refusals, and 28 get/put helper cases extracted by HIA from the actual compiler source. Bounds traps retain every write performed before SIGILL and compare it with both the complete independent VM and independent HIA arithmetic.

One native replay retained all 26,311 nodes in 46.053091179 seconds under the original 180-second phase budget. Its process trace contains one initial execve and 2,812 sealed-FD execveat calls. It contains no Python or host assembler/compiler/linker descendant. All raw responses, process receipts, original requests and shared-buffer bytes remain in the lossless qualification journal. Exact artifact and report pins are in the accompanying JSON.

## Interfaces

`generate_hia_cold_exports_plan.py` exposes `reference_exports`, `reference_words` and `qualify_exports`. References run before target construction in the final combined workflow. The component campaign imported independently verified original/modified compiler artifacts and deliberately retains its narrower scope in the report.

The reference packet CLI accepts `HIAEVP01` followed by nine little-endian u64 fields: mode, projection length, argument count, snapshot length, steps, call depth, heap bytes, allocation failure ordinal and zero. Argument records are `(kind,value)` pairs. Full `HIAERW02` projection bytes and concatenated external view snapshots follow. Mode 2 supports mixed scalar arguments and views: kind 14 is readbuf, kind 15 is mutbuf, and value is the view extent. Scalar kinds 2–12 are bool,u8,u16,u32,u64,usize,i8,i16,i32,i64,isize. It emits the complete `HIARPG02` program frame. This exports checkpoint admits at most 16 return values; the original observer-window gate requires a subsequent bounce-bounded extension to 129 values.

The 10M-step and 30M-step packet/VM profiles retain separate identities. Every plan supplies its original budget explicitly. The linked observer's original private Core interpreter uses 30M steps, depth 128 and 4 MiB heap; normal exports use 1M, depth 256 and 16 MiB heap. The larger VM changes only two step-admission constants. Its exact instruction, owner, loan, chain and step accounting remain unchanged, with 309 original comparisons and 12 original linked-policy/packing comparisons passing.

The VM emits `HIASPR01`, status, charged steps and detail, followed by return words only on success, 14 resource ledger words, and complete external views. Exact trap interpretation remains the existing `hia_scalar_reference_native` contract. No generic nonzero trap comparison substitutes for a required category.

The source-object linker accepts raw closed six-section f0 objects and source-emitter seven-section exported objects, then emits the complete shared ELF. It retains the existing seven allowed libc imports, symbol and relocation checks, and segment hardening. The unchanged general-emitter linker is retained separately for its different section order and symbol tags.

The scalar observer accepts `HIAEXQ01` with the seven-word header and 288-byte call records described in its HIA policy. It emits `HIAEXR01` plus complete index/kind/raw-value records. The linked six-word byte-ABI observer retains `HIAOBS03`/`HIAOBR03`, the separate return snapshot, real dlopen and normal libc startup/exit. The one-time independent construction records its system loader and mechanical linker; the cold runtime never calls that linker.

## Remaining integration

The pre-B0 native-observer windows and actual observer-pack byte reference plans are the next checkpoint. Root manages all source-role registration, full native cold orchestration, final build/install/rebuild, activation and old-stack retirement. This checkpoint deletes no source, worktree, live state or qualification evidence.
