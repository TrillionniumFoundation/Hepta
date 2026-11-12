# Exact Core v2 hosted primitive inventory

Base: `80ec04ae7489209b122c874531d194c67b30dfed`, tree `963e980c2486e1f7c74fa42bc8132ef6b1b8b690`. This is source inspection of the exact 80ec bridge/IR/renderer/policy, not a new execution or qualification. The bridge still implements all **19** primitive kinds. No source file in the product tree is changed by this experiment.

| Opcode | Primitive | IR call sites | Python responsibility still present |
|---:|---|---|---|
| 1 | GLOBAL | Function.expression L173 | Helper/namespace/builtins precedence and missing-name exception remain in Python; HIA chooses the name and lookup point. |
| 2 | ATTR | Function.expression L175; Function.statements L364 | CPython attribute and descriptor lookup remains hosted; HIA chooses receiver/name and order. |
| 3 | SET_ATTR | Function.assign L275; Function.statements L369 | CPython attribute assignment and descriptor effects remain hosted; HIA sequences the effect. |
| 4 | ITEM | Function.expression L178 | Subscription, indexing, hashing and equality protocols remain hosted. |
| 5 | SET_ITEM | Function.assign L277; Function.comprehension L314 | Item mutation, lookup, hashing and foreign receiver behavior remain hosted. |
| 6 | CALL | Function.expression L245 | Positional/keyword application and the actual callee remain hosted. Policy call sites may still invoke algorithms such as sorted/min/max or explicitly selected existing HIA owners; CALL alone proves neither native ownership nor fallback. |
| 7 | PACK | Function.expression L221; Function.comprehension L309 | List/tuple allocation plus set/dict hashing, equality, insertion and duplicate handling remain hosted. |
| 8 | ITER | Function.generator_expression L264; Function.iterate L291; Function.comprehension L308; Function.reduction L329; Function.statements L376 | Iterator acquisition and its __iter__/sequence behavior remain hosted. |
| 9 | NEXT | Function.iterate L293; Function.statements L378; GeneratorFunction.compile L423 | next() and StopIteration classification remain hosted; HIA chooses loop progression and body. |
| 10 | TRUTH | Function.truth L131 | bool(value), including __bool__/__len__ and exceptions, remains hosted for runtime references. Literal truth is already folded by the authoring IR. |
| 11 | BINARY | Function.expression L183; Function.reduction L337; Function.statements L367 | Twelve arithmetic/bit operations and their in-place forms use Python operator dispatch, arbitrary integer semantics and foreign operand protocols. |
| 12 | UNARY | Function.expression L192 | Unary positive/negative/invert use Python operator dispatch and value semantics. |
| 13 | COMPARE | Function.compare L166 | Six rich comparisons and membership/nonmembership use Python dispatch. HIA already handles object identity comparisons and subsequent control flow. |
| 14 | UNPACK | Function.assign L280 | Python unpacking of one through four values owns iteration and arity errors. |
| 15 | SLICE | Function.expression L180 | CPython slice object construction remains hosted; slicing itself is handled by the later ITEM operation. |
| 16 | APPEND | Function.comprehension L316 | Unbound list.append mutates the admitted list; HIA chooses when and what to append. |
| 17 | IMPORT | Function.statements L394 | Three existing module dependencies are imported by Python at the HIA-selected point. |
| 18 | RAISE | Function.statements L398 | Python raises the selected object, retaining runtime exception semantics. |
| 19 | GENERATOR | Function.generator_expression L267 | The Python generator object owns suspension/throw/close/PEP479 behavior; HIA owns its lowered body, NEXT/yield/control routing. |

## Existing HIA ownership

- Lowered policy control flow, branches, loop routing and cross-unit continuation
- Object identity comparison using existing handle identity
- Literal truth folding in Function.truth
- Lowered generator reductions and NEXT/body/yield sequencing

The 31 call-site entries are direct source-text locations read from the exact IR. They are not dynamic invocation counts. Source byte counts, SHA256 and Git blobs for all five inspected files are recorded in `INVENTORY.json`.

## Reuse decision

The smallest candidate reuses existing HIA handle identity and request packing to evaluate runtime truth for the admitted None/False/True singleton handles. It does not duplicate bigint, Unicode, object-graph or sorting algorithms. Other TRUTH operands continue to require the original hosted object protocol. This would not remove opcode10 or reduce 19 kinds to18.

The candidate is **blocked**, because initialization checks do not establish immutable handle contents for the entire session and direct step/observe consumers can observe the removed host boundary. `OPEN-DESIGN.md` records those limits. No native semantic or performance claim is made.
