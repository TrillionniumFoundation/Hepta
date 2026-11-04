/-!
UNCHECKED Lean 4.19 proof text for the source-only byte-facts experiment.
Insert this fragment in SyntaxData; no additional import is required.
Pinned library declarations were source-checked at leanprover/lean4 v4.19.0:
Init/Data/List/Basic.lean: length_cons, all_cons, length_append.
Init/Data/List/Lemmas.lean: all_append.
Init/Prelude.lean: decide_eq_true.
This fragment has not been elaborated or kernel-checked.
-/

namespace HiaCoreSyntaxSlice.ByteFactsResearch

def facts (xs : List Nat) (n : Nat) : Prop :=
  xs.length = n ∧ xs.all (fun b => decide (b ≤ 255)) = true

theorem nil : facts ([] : List Nat) (0 : Nat) := by
  exact ⟨rfl, rfl⟩

theorem cons (b : Nat) (xs : List Nat) (n : Nat)
    (byteBound : b ≤ 255) (child : facts xs n) : facts (b :: xs) (n + 1) := by
  constructor
  · rw [List.length_cons, child.1]
  · rw [List.all_cons, decide_eq_true byteBound, child.2]
    rfl

theorem append (xs ys : List Nat) (n m : Nat)
    (left : facts xs n) (right : facts ys m) : facts (xs ++ ys) (n + m) := by
  constructor
  · rw [List.length_append, left.1, right.1]
  · rw [List.all_append, left.2, right.2]
    rfl

end HiaCoreSyntaxSlice.ByteFactsResearch
