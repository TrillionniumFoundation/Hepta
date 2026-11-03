# parse_array: observed eight-branch proof plan

The design below passed independent review, and its exact proof skeleton has
been prepared locally in StructuredTransport.lean. Implementation review and
pinned-kernel validation remain pending. No evaluator, theorem statement,
assumption, resource budget, or workflow change is proposed here.

## Evidence and boundary

The bounded exact-head diagnostic at 6fd4f21, run 41663553717, job 126012741909,
printed the actual goal after `unfold parseRaw; split`. It produced eight
branches, not the previously anticipated two. The diagnostic is preserved in the [exact job log](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41663553717/job/126012741909).

Keep the current two-stage diagnostic cap until complete-pipeline execution
is separately approved. A successful helper module would not establish
full transport or syntax acceptance. All runtime obligations remain unproved and
DENY_ALL remains in force.

The theorem stays exactly:

```lean
theorem parse_array (f d : Nat) (input tail : List Nat) (items : List Raw)
    (notEmptyClose : input.head? ≠ some 93)
    (children : parseItems f d input = some (items, tail)) :
    parseRaw (f + 1) (d + 1) (91 :: input) = some (.arr items, tail)
```

## Intended proof body

This eliminates the evaluator's own observed matcher. It does not introduce an
external case split on a byte or ask simp to establish a parseRaw congruence.

```lean
  unfold parseRaw
  split
  case h_1 => omega
  case h_2 => omega
  case h_3 =>
    rename_i hinput
    have bad : (91 : Nat) = 34 := (List.cons.inj hinput).1
    omega
  case h_4 =>
    rename_i hinput
    exact False.elim
      (notEmptyClose (congrArg List.head? (List.cons.inj hinput).2))
  case h_5 =>
    rename_i childFuel childDepth rest excluded hf hd hinput
    have fuelEq : f = childFuel := Nat.succ.inj hf
    have depthEq : d = childDepth := Nat.succ.inj hd
    have inputEq : input = rest := (List.cons.inj hinput).2
    rw [← fuelEq, ← depthEq, ← inputEq, children] <;> rfl
  case h_6 =>
    rename_i hinput
    have bad : (91 : Nat) = 123 := (List.cons.inj hinput).1
    omega
  case h_7 =>
    rename_i hinput
    have bad : (91 : Nat) = 123 := (List.cons.inj hinput).1
    omega
  case h_8 =>
    rename_i noString noEmptyArray noArray noEmptyObject noObject
    exact False.elim (noArray input rfl)
```

## Branch evidence and local-name counts

- h_1 contains `f + 1 = 0`; h_2 contains `d + 1 = 0`. Each contradicts Nat
  successor positivity, independently of the other inaccessible locals.
- h_3 ends in `91 :: input = 34 :: rest`. Rename only its final inaccessible
  equality; list-constructor injection gives the impossible head equality.
- h_4 ends in `91 :: input = 91 :: 93 :: rest`. Rename only that equality.
  Injection gives `input = 93 :: rest`; applying List.head? yields the exact
  negated premise. No expansion of the parser is needed in this branch.
- h_5 has three irrelevant inaccessible discriminant locals, followed by exactly
  seven inaccessible locals: childFuel, childDepth, rest, excluded, hf, hd,
  hinput. Their types are respectively Nat, Nat, List Nat,
  `∀ r, rest = 93 :: r → False`, `f + 1 = childFuel.succ`,
  `d + 1 = childDepth.succ`, and `91 :: input = 91 :: rest`.
  Rename this trailing group of seven. The three injected equalities align the
  recursive call exactly with children. The branch result is then reflexive
  Option bind/pair reduction. The unused exclusion is intentionally preserved.
- h_6 and h_7 each end in a list equality with head 123 instead of 91. Rename
  only that equality and use its head contradiction.
- h_8 has seven earlier inaccessible locals followed by five exclusion
  functions, in order: string, empty array, arbitrary array, empty object,
  arbitrary object. Rename this trailing group of five. The arbitrary-array
  exclusion has type `∀ r, 91 :: input = 91 :: r → False`; instantiate r=input
  with reflexivity. No facts about the numeric parser are needed.

## Review risks and acceptance

The trailing-group behavior of rename_i must match pinned Lean 4.19. The proof
also relies on the ordinary definitional equality f+1 = Nat.succ f when applying
Nat.succ.inj. The final rewrite can close the goal automatically; `<;> rfl`
handles both an already closed goal and any remaining reflexive monadic result.

The eight cases are justified by the recorded actual context, but the proof
text is not yet kernel checked. If Lean still rejects its construction, do not
change assumptions or count an error as a negative control. Preserve the bounded
workflow cap and diagnose the new exact failure before further changes.
