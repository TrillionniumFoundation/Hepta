# Reading a HIA proof result

Every element of `hia_verify.result.checks` is a complete
`hepta.hia.agent.proof-result.v1` record. Keep that record intact when displaying,
exporting or consuming a conclusion. This rule applies to `proved`, `refuted`,
`unknown`, `unsupported` and `not_run`.

`proved` means the identified checker established the stated property for the
exact subject, within the stated profile, under the listed assumptions. It does
not establish global safety and does not grant permission to execute or adopt
an artifact. An operation's top-level `completed` means the request ended.

## Fields that carry the conclusion

| Field | Meaning |
| --- | --- |
| `subject` | Exact candidate reference and canonical Core hash, optional exact base reference/hash, immutable context and target profile, plus the selected canonical lowering, Agent plan or native artifact/build receipt |
| `property` | Stable property ID and the actual proposition being checked; `claim` remains the acceptance-policy ID |
| `profile` | Validation profile ID and content hash; the compatibility field `validator` has the same value |
| `domain` | The checker's concrete quantified or bounded domain and its result-specific diagnostic |
| `assumptions` | Explicit premises with stable IDs; an assumption is not a proved obligation |
| `checker` | Method and entry point, installed worker/backend/catalog hashes, Python implementation/version, and actual SMT checker/binding/library hashes when used |
| `unproved_obligations` | Properties left open by this check, including checker soundness, complete-language safety, native semantics, ABI/FFI/loading, native resources and side channels |
| `evidence_artifact` | Retained checker evidence, including a complete binding to this result's scope and conclusion |
| `assumptions_artifact` | Retained copy of the exact subject, property, profile, checker and assumptions |
| `global_safety_proved`, `execution_authority_granted` | Always false |

The worker hash identifies the actual installed source inventory, including the
proof contract implementation. It is not a claim that the checkout is clean.
The optional SMT identity names the library and Python binding actually used,
not merely a requested solver version.

## What each existing method establishes

| Method | Positive conclusion | Obligations that remain open |
| --- | --- | --- |
| Core admission | The installed whole-program verifier accepts the exact canonical Core bytes | Soundness of that verifier, behavior relative to a base, native behavior and all external execution assumptions |
| Canonical Core identity | The exact admitted base and candidate bytes are identical; reflexivity under the same Core model | Model soundness, native execution and termination outside the stated profile |
| Complete finite domain | All declared-width inputs in the supported pure scalar acyclic domain have equal return status, values, first trap and Core resource observations | Interpreter/model soundness and every native-level property; a partial enumeration is `unknown` |
| Compositional scalar/effect checking | The pinned structural Core v1-v7 profile discharges all required scalar/effect/trap obligations with the identified solver | Checker/solver soundness, unsupported rewrites, native behavior and VM instruction-tick equality |
| Explicit machine choices | The exact plan preserves the checked canonical CFG, value lifetimes and path effects relative to canonical lowering | Correctness of canonical lowering, encoder/relocations and actual hardware execution |
| Canonical lowering refinement | This Agent profile returns `unsupported` | The requested Core-to-machine refinement has not been established |
| Encoding check | Exact retained native bytes and object identity match complete reemission/linkage by the same installed implementation | Common encoder/lowering defects, independent ISA validation, ABI/FFI/loading safety and native resource bounds |

A frozen-workload evaluation is observational evidence for those cases. Passing
that workload does not produce an all-input equivalence conclusion. An
`encoding_check` is a same-implementation reconstruction check; it must never be
presented as independent translation validation. The separate safe-Core machine
validator has its own supported profile and assumptions. It is not silently
invoked or implied by this Agent receipt.

## Consumption and recovery

Emission, evaluation and adoption read the server's retained receipt. The server
rechecks the exact candidate and base Core identities, context, target, selected
subject and validation profile. It validates every required scope field and
compares the result against the retained checker conclusion and assumption
record. A rewritten checker identity, weakened assumption, removed obligation,
relabelled status or receipt for another subject cannot satisfy a required claim.

Old receipts without the complete scope are rejected; rerun `hia_verify` under
the installed catalog and profiles with a fresh request key to obtain new
evidence. Cached verification responses are subject to the same scope and
retained-conclusion checks; their original journal records are not rewritten.
Do not patch a
serialized receipt or add a producer-supplied `verified: true`. Use
`E_HIA_PROOF_SCOPE` as a request to regenerate verification evidence, not as
permission to weaken the acceptance objective.

`refuted`, `unknown`, `unsupported` and `not_run` retain their full scope and open
obligations. None can satisfy a required proof. Even a complete `proved` record
is one input to the existing context, workload, resource and conditional
generation/epoch gates.
