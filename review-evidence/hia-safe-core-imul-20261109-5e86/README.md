# Supplied Safe Core wrapping-multiply validation

The independent consumer now admits unsigned `int.mul.wrap` for the existing
`u8`, `u32`, `u64` and `usize` scalar types. Its Core model computes a modular
product. The machine model decodes only register-register 64-bit two-operand
`IMUL`, consumes both old operands before writing the destination, and keeps
the low 64-bit product.

The carry flag models **signed** truncation: the signed 128-bit product must
equal the sign extension of its low 64 bits for CF to be clear. The zero flag
is undefined after IMUL and becomes a fresh arbitrary Boolean per model
execution. A proof must hold for both values. The model does not preserve the
previous ZF or infer it from the low product. OF, SF, AF and PF are not observed
by this decoder's admitted condition set.

This follows Intel's IMUL instruction description in the
[Intel 64 and IA-32 instruction reference](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf).
The implementation remains a trusted Python instruction model; no claim of
machine-checked refinement to the full hardware ISA is made.

## Source and validation

- Base: `20eace37747fde9aa0fc9c14cdb0159db30f5161`.
- Tested local code commit: `1b3c761fe8a9910b23029de233d7932441373423`.
- Tested code tree: `a1f38799114c8dde11f5973818a27cf5a3fd25e6`.
- The final evidence addition changes only this directory. `SUMMARY.json` and
  the archive's `tested-source.json` bind every changed source/test/doc file.
- The regenerated v13 support contract still binds 251 files; its language
  inventory and compiler bytes are unchanged.

The five new focused tests passed in 1.056 seconds. They cover four actual
Core/object/final-ELF subjects, each with the complete five-obligation model
proof and the six scope fields; 256 native product calls against independent
Python arithmetic; all 256 decoded register combinations; ten refused
encodings; six constant signed-carry subjects; and two semantic SAT
counterexamples. The counterexamples replace multiplication by addition, and
try to rely on a zero flag established before IMUL. Refuted subjects are not
executed natively.

The existing Safe Core qualifier passed **50 tests**, zero failures/errors or
skips, in 6.407 seconds. It retained the existing three positive subjects,
five negative semantic subjects and 29 internal query replays. Separate
SafeCore two-module regression passed 47 tests; CMOVNE and source-contract
checks passed ten tests. These overlapping counts must not be added together.

The archive contains the full new proof subjects, object and final ELF bytes,
SMT inputs and original results, all original Safe Core qualifier files, logs,
and all 104 retained-query replays using the pinned Z3 binary. Each replay
returned its original expected result with exit 0 and empty stderr. ZIP CRC,
individual member sizes and SHA256 values were checked before committing.

The initial test-first run against unchanged base implementation failed four
tests with 262 error subcases because wrapping multiply/IMUL was unsupported.
That original log and later successful logs are all retained. A transient
local executor outage occurred before any patch applied; no failed proof or
CI run was discarded or relabelled.

## Reproduction and scope

With `jsonschema==4.25.1`, `z3-solver==4.15.4.0`, GNU ld and Linux x86-64:

```sh
python -B -m unittest tests.test_hia_safe_core tests.test_hia_safe_core_artifact -v
python -B tools/qualify_hia_safe_core.py --output /new/qualification-directory
python -B tools/generate_hia_selfhost_contract.py --check
```

Set `HIA_SAFE_CORE_ARTIFACT_EVIDENCE` to a new directory to retain the artifact
tests' full original inputs and queries. Supplied bytes are independently
checked without calling the production emitter during validation.

Checked multiplication, memory/narrow IMUL encodings, general resource/FFI
semantics, a complete ISA theorem and the whole compiler remain outside this
extension. No online configuration, default release lock or execution/adoption
authority changes. Overall six-track acceptance remains **HOLD**.
