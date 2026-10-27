# Independent review: internal owned LLVM result slots

## Scope and result

Reviewed commit: `8fb1f39c87282c8943edcb5a1bf07e50713502b3`.
Comparison baseline: `b62f26349d3878dfedaac4d6d3ad5cd673eff48f`.
Review date: 2026-10-25.

This was an independent, read-only review of the internal aggregate/slice
return changes in [llvm_owned_backend.py](../hepta/llvm_owned_backend.py),
with the associated test and documentation changes. **No blocking semantic
regression was identified within the admitted owned-byte host profile.**

The review ran no compiler, native program, test suite or performance
measurement. The author's existing execution results were not counted as
independent executions. This conclusion is not a backend refinement proof,
a whole-language soundness proof or a qualification of unsupported inputs.

## Checked code paths and invariants

| Concern | Relevant code paths | Static conclusion |
| --- | --- | --- |
| Nested enums and `Result` | `_Emitter.typ`, `_Function.value`, `_Emitter.return_fields`, `_Function.store_return` | Enum layout contains a tag and separate payload fields for every variant. Struct/variant construction starts from `zeroinitializer`. Return lowering writes every scalar/pointer leaf, including inactive variants and empty-field placeholders. It does not copy only the active payload into an otherwise uninitialized result. |
| Fallible allocation results | `_Emitter.allocation_runtime`, `_Function.value` | Empty, successful and failed `try_buffer` paths each initialize tag, data pointer, length and error byte before returning. The caller loads the completed result after the call. |
| Partial move and restoration | `_Function.value`, `_Function.block`, `emit_owned_llvm`; existing resource verification | Moving an owned field loads it and clears its source representation. The shared checker and independent resource verifier still reject whole-parent move/drop before required field restoration. The new result-slot path does not bypass these gates or invent cleanup for a partially initialized parent. |
| Result-slot aliasing | `_Function.slot`, `_Function.call`, `_Function.render` | Each emitted call site obtains a dedicated caller `alloca` in the entry block. The `noalias` promise applies to that result storage. Source-level arguments cannot name this compiler-created slot. Calls in a loop may reuse the slot after earlier calls complete. |
| Returned slices | `_Function.borrow`, `_Function.sequence`, `_Function.call`, `_Function.store_return` | The result contains the original borrowed data pointer and length, not a pointer to a callee-local descriptor. The caller loads the descriptor while its result slot remains alive. No `noalias` promise is added to the slice's data pointer; source/resource borrow-origin and owner-lifetime checks remain in force. |
| Public ABI and expansion bound | `_Emitter.__init__`, `_Emitter.uses_return_slot`, `_Emitter.return_fields` | Public C exports remain restricted to ordinary scalar signatures. Hidden result pointers affect only internal aggregate/slice returns. Exceeding 256 return leaves rejects emission instead of omitting fields. |

## LLVM semantic cross-check

The review consulted the official
[LLVM 20.1.0 Language Reference](https://releases.llvm.org/20.1.0/docs/LangRef.html),
specifically the `sret`, `noalias`, `load`, `store`, and well-defined-value
sections. Its requirements are consistent with the checked lowering:

- The caller supplies valid, appropriately aligned storage for `sret`, and
  the callee returns `void`.
- Parameter `noalias` concerns accesses based on the parameter. A pointer
  stored inside the result descriptor does not acquire the result-storage
  aliasing promise merely because it is returned there.
- An aggregate load ignores padding as part of the resulting aggregate
  value. Leaving padding unwritten when storing every actual field does not
  itself make this load undefined. The admitted profile has no operation
  that reinterprets these internal aggregates to observe padding bytes.

Skipping `free(NULL)` in the buffer drop helper is consistent with the
profile's standard deallocator semantics. This observation does not extend
to arbitrary custom deallocators or instrumentation that assigns observable
effects to null deallocation calls.

## Boundary of the conclusion

The conclusion depends on the existing closed profile: source-bound checked
ASTs, independent resource verification, fully initialized admitted values,
internal aggregate layouts, and rejection of foreign/raw/stored-lifetime
extensions. The review found no new path that violates these invariants;
it did not establish them for arbitrary Hepta or C++ programs. It also makes
no claim about performance improvement or benchmark acceptance.
