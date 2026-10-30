# Modular narrowing qualification

`native01` is a new qualification of the guarded-reduction followed by modular
narrowing chain. It leaves all previous optimizer experiments unchanged.

The real qualification passed **288 native observations** across the guarded
and narrowed artifacts, two kernels, twelve sizes and six seeds. A guard of 32
exercises both fast and fallback branches. Each artifact is copied to a fully
sealed memfd; both actual exported function addresses are checked against that
image before calling them. Results match a separate modular arithmetic oracle.
All recorded source and tool identities remained unchanged.

The narrowed chain discharges **30 guard/inductive/no-overflow obligations and
118 scalar/effect/first-trap obligations**, all UNSAT. The original guarded
artifact and final narrowed artifact each contain 15,536 bytes; native binary
size is not the same as vector-loop instruction count. Actual disassembly
shows wide `paddd` plus packing in the guarded fill and byte `paddb` in the
narrowed fill. The vector loop still advances by 16 bytes. This observation
does not establish faster execution or superiority to Rust/C/C++.

| Artifact | Identity |
| --- | --- |
| Result JSON SHA-256 | `6d1b49da87ca25d460846d785f756c51a2ab6dc114ba66877ee63aaa3d338353` |
| Narrowed actual native ELF SHA-256 | `c9f5dd1f3d4730301d1783ebf612aab2ef5bc7e5f7de0d390a4f35de8e8e6638` |
| Complete archive SHA-256 | `3e9ea3eae1018e9e922c103938a07354f336cdede1abbdf409d955fba6872cb9` |

The complete archive contains 19 files and 54,888 compressed bytes, including
both actual ELF images, both full LLVM/Core representations, proposals,
receipts, disassemblies, loaded mapping identities, the plan and all native
observations. Its manifest verifies each member's bytes and SHA-256. No ELF
was discarded before archiving.

Measured preparation was 658,065,737 ns for the guarded proof/build and
1,100,865,002 ns for the chain proof/build; the whole qualification was
2,042,380,519 ns. These are this small-guard qualification's costs, not the
full-limit benchmark candidate's production costs. There are **zero workload
performance samples** in this qualification. Performance requires the
independently registered eight-arm study.

Reproduce using a new output directory:

```sh
python tools/qualify_hia_narrowing.py --out NEW_DIRECTORY --clang CLANG20 --objdump LLVM_OBJDUMP20
```

The standalone proof/native controls are in `tests/test_hia_narrowing.py`.
Twelve tests passed on the original new implementation, including actual SMT
counterexamples, resource/failure preservation, chain identity, timeout/unknown
refusal, actual loaded mappings, producer mutation and post-build checker drift.
Broader final integration results are recorded separately.
