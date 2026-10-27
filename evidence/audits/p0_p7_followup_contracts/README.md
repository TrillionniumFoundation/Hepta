# HIA follow-up: ABI admission, edit presentation and qualification CLI

## Validation identity and status

These changes are based on **3e2c4f73816f200409db74962420986804ef0ba6**.
That commit adds only recovery documentation to implementation
**108762baaefedde931f4160dbeadb6442fbb824b**.

**Status: Python, Clang, Rust, LLVM, native and CI validation NOT EXECUTED for
this follow-up.** The execution environment is unavailable. GitHub source reads,
bounded source review, JavaScript source-text checks and publication checks do
not substitute for executing the regression tests.

The earlier observed result of **2,424 passed tests with zero skips, failures
or errors belongs to 108762ba**, not to this follow-up. Only four passed gates of
that original 19-gate attempt were directly observed before access was lost.
Its terminal report and post-run local source identity have not been recovered.
See [the recovery checkpoint](../p0_p7_108762ba_recovery/README.md).
The full raw evidence ZIP has not been generated, verified or made available.

[static-checks.json](static-checks.json) records the actual source-text checks and
their limits. It is not a compiler execution report. The regression methods
added here have not been run and must not be added to any passed-test count.

## 1. Reject GNU-style function type attributes before ABI lowering

The C project translator previously checked function declaration children for
unsupported attributes, then extracted the return type from the prefix of
qualType. The strict scalar migrate_c entrypoint followed the same pattern.
Neither path checked attributes carried by the function type itself.

For example:

~~~c
__attribute__((ms_abi))
unsigned int probe(unsigned int x) { return x + 2u; }
~~~

Clang 20 can represent a calling convention in an AttributedType without a
corresponding ordinary attribute child. Its type printer emits CC_Win64 as
__attribute__((ms_abi)); Clang's own code-generation tests distinguish the
win64cc and default calling conventions on non-Windows x86-64.

The generated project bridge uses extern "C". Silently losing a non-default
calling convention can change the argument registers and preserved registers
even if the translated body computes the right arithmetic result.

### Change

A shared admission check examines both qualType and desugaredQualType and
rejects GNU-style function type attributes with **E_C_ATTRIBUTE** before either
signature is lowered. It examines Clang's type data, not source comments.
C++ paths that share CTranslator.signature inherit this check.

This is a refusal of an unmodeled ABI, not a new implementation of ms_abi.
It does not certify all calling conventions on all targets. In particular,
AArch64 SME streaming/state suffixes use other spellings and remain outside
this small repair. Some explicit C++ spellings were already rejected by the
existing noexcept suffix check; this audit does not claim a newly executed
C++ acceptance counterexample.

### Regression design, unexecuted

The added project test first compiles the original C function with a caller
that repeats its ms_abi declaration, then executes that reference control.
Calling that original function using default-C ctypes would invalidate the
reference, so the test does not do that.

Both public C migration entrypoints must refuse the function and leave their
output absent. An ordinary C function, with the same attribute-looking text
only in a comment, must still be admitted.

The native counterexample test is limited to x86-64 and explicitly skips on
other architectures. A skipped result cannot satisfy the unified zero-skip
qualification policy.

Primary source basis, all at the fixed Clang 20.1.8 tag:

- [Calling conventions in SemaType](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/Sema/SemaType.cpp#L8095-L8164)
- [Function type printing](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/AST/TypePrinter.cpp#L1059-L1154)
- [Clang ms_abi code-generation tests](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/test/CodeGen/ms_abi.c#L12-L27)
- [AArch64 SME type suffixes, outside this repair](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/AST/TypePrinter.cpp#L996-L1022)

## 2. Refuse inconsistent batch presentations

prepare_batch and apply_batch already reject overlapping instruction selections.
The batch renderer separately validates each nested presentation, then merges
their displayed data. It previously allowed the merge to overwrite or ignore
conflicting data.

A minimal duplicate-selection example takes a valid two-site query, replaces
site 1's nested query with a copy of site 0's nested query, and leaves the outer
site IDs as 0 and 1. Each nested presentation remains individually admissible.
Both now select the same instruction, so the old edits dictionary retains only
the site 1 marker.

Other conflicts can keep the source digests and all operations unchanged:

- The two nested queries can disagree about a shared function signature.
- Their current-block parameters or terminator can disagree; setdefault
  previously retained the first one without comparing it.
- Same-name callee signatures can disagree across sites or within one list;
  the old dictionary construction/update silently discarded one description.
- A selected function and a displayed callee can give the same name different
  signatures.

These are presentation consistency defects. They do not establish a bypass of
Core or patch admission: apply_batch reconstructs the complete query from the
verified input before applying it.

### Change

The renderer now:

1. Compares nested base_sha256 with batch base_sha256, and nested input_sha256
   with batch input_sha256, preserving their separate roles.
2. Refuses a second selected site for the same function/block/operation index.
   Shared dependency operations are still deduplicated normally.
3. Compares all displayed selected-function and callee signatures through one
   batch-wide table, checking each callee before a dictionary can discard it.
4. Compares current-block parameters and terminator before merging, matching
   the existing downstream-block consistency rule.

Comparisons use the existing bounded canonical JSON wire representation.
Matching these fields is an internal consistency check, not proof that a
presentation actually corresponds to its declared digest. Full reconstruction
and module verification at apply time remain required and unchanged.

### Regression design, unexecuted

Added coverage includes ordinary duplicate selections, different outputs of
one multi-result instruction, both snapshot roles, conflicting function/block
metadata, and legitimate composite input whose input digest differs from its
normalized Core digest.

The existing caller fixture also checks callee conflicts across sites, within
one list, and between a selected function and a callee. Valid sharing retains
both edit markers and one consistent signature per displayed callee. Existing
cross-block coverage remains in test_hia_edit_cfg_context.py, and distinct
functions with the same block name/index remain accepted.

## 3. Align the full qualification workflow with its real CLI

The workflow omitted **--lean** and **--qemu-riscv64**, although both are required
by tools/qualify_hia_unified.py. Exporting LEAN is not equivalent to supplying
the required CLI option. The RISC-V qualifier also selects ld.lld and
llvm-readobj next to the chosen Clang; the old workflow did not explicitly
install those LLVM packages.

### Change

The workflow supplies the two required options, installs qemu-user-static,
lld-20 and llvm-20, checks the required executable paths, and selects the
LLVM 20 linker. It explicitly declares the previously chosen 3,600-second
unit-gate budget. The other 18 gate limits, performance thresholds and
qualification criteria are unchanged.

A regression reads the actual workflow command, forms argv with shlex, and
calls the real unified main/argparse path while mocking only qualify().
Removing either required option must reject before qualification, even with
LEAN exported. This test has not been executed.

The recorded JavaScript extraction found these missing required options before
the edit and no missing required options afterwards. It did not invoke Python,
a shell, the package manager or a qualifier.

### Remaining execution limitations

RISC-V qualification records the selected QEMU binary's actual digest/version
and checks stability. It does not impose the AArch64 bootstrap's fixed download
identity on RISC-V. The proposed package path still needs actual installation
and all RV64 positive/negative executions.

The outer workflow job remains limited to **60 minutes**, including setup,
release_check, the unit gate, the other 18 gates and evidence upload. The
internal 3,600-second unit cap does not extend that outer budget. No same-runner
measurement establishes that the complete job finishes within it. An outer
cancellation may prevent final report construction and upload.

The follow-up branch is not in this workflow's automatic push filters, and
the stacked PR targets a branch other than main. Publishing this change does
not establish that this workflow was scheduled or ran. No remote CI pass is
assumed.

## 4. Open P3 blocker: VLA parameter entry effects

[vla-parameter.c](vla-parameter.c) and [vla-contracts.json](vla-contracts.json)
preserve a small candidate for actual differential execution:

~~~c
unsigned int probe(unsigned int n, const unsigned int data[++n]) {
    return n;
}
~~~

Use n = 7 and an array of at least eight initialized unsigned int elements.
The supplied slice contract binds data's length to n.

**Static inference, not measured output:** the original Clang 20 function
evaluates ++n at entry and returns 8. The current slice translator reads the
adjusted pointer parameter type and emits the body with the unchanged n, so
its generated path is expected to return 7. No original/native/interpreter
differential execution for this case was available in this follow-up.

Clang code generation explicitly inspects ParmVarDecl::getOriginalType() and
emits evaluation for variably modified types at function entry. The ordinary
JSON parameter type is the adjusted type, and the current capture does not
provide the needed original-type admission evidence.

Adding only -Werror=vla would be incomplete: source-level diagnostic pragmas
can suppress it. Checking only parameter inner nodes or looking for "[" in
the adjusted type would miss the lost information. This change does not use
a source regular expression as a substitute for original type semantics.

A credible next implementation route is a bound original-type probe using
the same captured Clang build. Clang 20 libclang's MakeCXType explicitly
unwraps DecayedType to its original type, but introducing that route requires
a matched libclang identity, the same source operand/arguments/cwd, reliable
declaration matching, and explicit treatment of typedef/typeof/nested variable
types. None of that new integration is implemented or qualified here.

Required future negative controls include source-suppressed VLA diagnostics,
macro-generated bounds and typeof-hidden variable arrays. **This blocker
remains open, and general safe C migration is not established.**

Primary source basis:

- [Clang function-entry original parameter type evaluation](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/lib/CodeGen/CodeGenFunction.cpp#L1326-L1342)
- [Clang VLA parameter code-generation regression](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/test/CodeGen/vla.c#L189-L193)
- [libclang DecayedType handling](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/clang/tools/libclang/CXType.cpp#L132-L174)

## Planned validation once execution is available

These commands have **not** been run for this follow-up:

~~~bash
python -m unittest \
  tests.test_hia_edit_batch \
  tests.test_hia_edit_cfg_context \
  tests.test_hia_cfg_render_convergence \
  tests.test_hia_context_render_input \
  tests.test_c_project.CProjectMigrationTests.test_function_type_abi_attributes_reject_without_publication \
  tests.test_hia_unified_workflow_cli \
  tests.test_hia_unified_unit_timeout \
  tests.test_hia_unified_qualification -v
~~~

Then revalidate the existing C/C++ project and template positive profiles and
run the complete integrated qualification under this follow-up's own frozen
source identity. Preserve rejected cases, failed attempts and incomplete
reports under separate attempt identities. Recover the original 108762ba
terminal report before assigning that older attempt a terminal verdict.

None of these changes upgrades the older model study's negative benefit result,
the older CPU attempt's inconclusive timing result, or the absence of real GPU,
physical-board and production-recovery qualification.
