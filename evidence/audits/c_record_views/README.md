# Independent C record-view audit

This archive retains the original counterexamples and the independent replay
against the corrected implementation. It supplements the full release gates.
It is not a proof of whole-source equivalence or foreign pointer validity.

- Original implementation: `b25f132bdeabd6ab14e6b62c5fdf87aeb03216ce`.
- Corrected implementation: `a149bc579facb80d4e4534892c717ce3dfb40de4`.
- `manifest.json` binds both Git trees, report/script hashes, issue dispositions
  and the exact fixed-commit native test run: 25 tests, zero skips, 16.299 s.

## Findings and closure

| Finding | Original observation | Corrected observation |
| --- | --- | --- |
| Signed cursor-relative index | Three defined-C calls return 13, 13 and 41; translated calls abort because a negative index was cast to usize before adding the cursor offset. | Widen before addition, then validate the absolute index. All three calls return the same values as original C. |
| Mixed translation-unit char model | Separate unsigned-char and signed-char TUs both use the first TU's record interpretation. A signed read returns 255 rather than C's -1. | Reject mixed data-model bundles with `E_C_PROJECT_MODEL`; all four active project declarations remain in the inventory. |
| Preprocessor macro used as ABI evidence | Defining or undefining `__CHAR_UNSIGNED__` changes the presumed ABI while actual native char signedness is unchanged. Pointer-based byte loads expose -1/255 mismatches. | Probe ABI from actual semantic compiler options independently of user macro overrides. Both attacks and the include-directory operand control match original C. |

The positive controls preserve these observations:

- A complete initializer ignores poisoned previous record storage.
- Unsigned scalar-field arithmetic retains C wrapping behavior.
- Unused active global/union declarations are inventoried and reject migration.
- Partial or pointer-changing initialization is rejected.
- Four mutable overlap preconditions abort before modifying any bytes in a
  shared 4 KiB record/backing region. The parent process compares the complete
  region after a forked child aborts.
- Read/read aliases into the same initialized buffer remain accepted; both C
  and Hepta return 26.

The writeback observations cover precondition rejection. They do not promise
rollback if an algorithm mutates state and subsequently fails a bounds check.
Allocation extent, provenance, initialization and foreign concurrency remain
caller obligations. Mixed data-model translation is explicitly unsupported,
not silently normalized to a common char type.

## Replay

Use a clean checkout of either commit above. The scripts do not modify it.
Provide actual Clang, GCC (on PATH) and pinned Rust 1.90.0 executables. Every
output must be new; existing reports are not overwritten. Linux `fork` and
shared mappings are required for the alias/writeback replay.

For each of `cursor_and_inventory.py`, `mixed_models.py`,
`alias_writeback.py` and `abi_macros.py`, run the following form:

```sh
python evidence/audits/c_record_views/scripts/cursor_and_inventory.py \
  --repo /path/to/exact-commit-checkout \
  --clang /path/to/clang \
  --rustc /path/to/rustc \
  --output /tmp/fresh-cursor-audit.json
```

The cursor replay imports only the frozen test module's C fixture and contract;
all migrated code still comes from the selected checkout's Clang-based
translator. The alias replay uses that checkout's frozen upstream module and
build flags. The other scripts embed their complete C counterexamples.
Reports deliberately retain the original failures. A successful replay process
means the observations were collected; compare their contents with the issue
dispositions in the manifest rather than assuming every original compiler
result should pass.

The fixed-commit native regression command was:

```sh
RUSTC=/path/to/rustc python -m unittest tests.test_c_record_views -q
```

## Discarded harness attempt

`discarded/` preserves an earlier by-value-char ABI probe. That harness used
`ctypes.c_byte` even for an unsigned-char native parameter, which can violate
ABI extension expectations. Its results are not evidence of a compiler pass
or failure. The accepted `original_abi_macros.json` and `fixed_abi_macros.json`
use pointer-based loads of initialized byte storage, so their pointer ABI is
unambiguous. No implementation claim relies on the discarded attempt.
