# Captured C++ `if constexpr` selection

`cpp_project_migrate` now translates an `if constexpr` in a concrete captured
C++20 function when Clang provides an exact Boolean `ConstantExpr` result.
The existing scalar frontend, independently checked HIA Core, interpreter and
LLVM backend remain the execution authorities after this frontend step. This
does not add an instruction, change a Core schema, or reinterpret an old Core.

## Accepted shape and behavior

The admitted statement has one condition, a then statement, and an optional
else statement. It has no initializer or condition-variable declaration. The
condition must have `kind: ConstantExpr`, type `bool`, value category `prvalue`,
one inner expression and the exact Clang string `true` or `false`. Missing,
ambiguous, differently typed or uninstantiated values reject with
`E_CPP_PROJECT_CONSTEXPR`. `if consteval` remains unsupported.

Only the selected statement is passed to the existing statement lowerer. A
false condition without an else emits no statement. Nested selections are
processed only along the selected path. The condition is a compile-time
decision of the captured C++ frontend; it is not turned into a runtime branch
or reevaluated from source spelling. All selected arithmetic, calls, locals,
returns and effects must still satisfy the existing scalar migration rules.

This admits concrete type and integer non-type template arguments, including
`sizeof(T)` conditions, nested choices, scoped scalar locals and an absent
else. Scalar locals retain distinct Clang declaration identities and hygienic
generated names. Selected class objects, destructors, exceptions, pointers and
other unmodeled operations remain unsupported. A class or throw statement in
a discarded template branch does not imply support for executing that branch.

## Full definitions remain part of admission

Build capture replay still binds the actual compiler, ordered options, source
operands, working directory and dependencies before AST collection and after
lowering. A changed macro configuration cannot reuse an old capture.

Symbol resolution and the complete concrete function ODR comparison run before
statement selection. They are not replaced with hashes of selected statements.
Repeated complete template patterns also have a normalized AST identity. A
different macro expansion in a discarded template-pattern branch is rejected
as `E_CPP_PROJECT_ODR` even when current scalar results would coincide. This is
a conservative finite ODR check, not a general implementation of the C++ ODR.
Concrete-symbol coalescing also compares that complete pattern identity across
different template source locations; matching selected bodies alone is not
sufficient. A template identity cannot match an absent non-template identity.
Local member references inside discarded class patterns are normalized to
their exact declaration ordinals, not to Clang's process-specific pointer
addresses. Unknown external member references are not silently erased.
Global declaration accounting and unresolved-symbol rejection remain in force;
discarding a statement does not authorize omitting a captured declaration.

Each `constexpr_selections` row records the unit, source symbol, generated
function, source location, evaluated Boolean, selected branch, complete
statement identity, complete concrete function identity and template-pattern
identity where applicable. Each discarded subtree has an explicit disposition,
node count and identity. Clang may omit the contents of an uninstantiated
discarded subtree; its complete template pattern and captured source are still
retained. These rows explain frontend work. They are not proof tokens and do
not grant Core or native admission.

The trusted frontend boundary includes the selected Clang's constant evaluator.
The migration does not independently prove arbitrary C++ constant evaluation,
source equivalence, external C++ ABI behavior, or correctness of every future
instantiation.

## Reproducible finite native qualification

`examples/cpp/project_constexpr` contains a header and two translation units.
Seven concrete template instances exercise 32/64-bit type choices, integer
template arguments, nested selections, scalar shadowing, false-without-else,
and a discarded object lifecycle. One instance appears in both units so the
full-definition coalescing path is exercised.

```sh
python tools/qualify_cpp_constexpr.py \
  --output-directory /tmp/hepta-constexpr-new \
  --clang /absolute/path/to/clang \
  --clangxx /absolute/path/to/clang++
```

The qualifier predeclares 80 defined unsigned boundary cases, their independent
arithmetic oracle, compiler identities, fixture hashes and process budgets.
It compares the HIA interpreter with that oracle, builds the original C++ and
generated HIA into separate libraries, and executes 80 calls on each library.
The target link contains only the generated HIA object, with no original C++
object or implementation fallback. Raw process input/output, commands,
translation receipts, Core, LLVM, native objects and results are retained in a
new output directory. Failed attempts are reports, not successful runs.

Regression tests additionally cover unsupported init/condition shapes,
missing or ambiguous constant results, a selected object lifecycle, stale
build captures, and complete-pattern conflicts in discarded branches. A
separate AST mutation control changes only a local member's declaration
binding to ensure normalization does not erase that relation; it is not
counted as a defined C++ input or native execution.
The existence of these tests or the qualifier is not an execution result.
Actual runs must retain their own exact source identity and terminal outcome.
