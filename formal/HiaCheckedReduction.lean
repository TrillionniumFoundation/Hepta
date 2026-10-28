import Lean.Elab.Tactic.Omega

/- Independent arithmetic model for checked-unsigned-reduction.v1.
   `none` means unsigned overflow; successful values are mathematical naturals
   bounded by `maximum`. This file does not model the Python CFG matcher,
   resource verifier, exporter, LLVM, native ABI, execution fuel or host effects.
   Their correspondence to these definitions is a separate obligation. -/
namespace HiaCheckedReduction

def repeated (maximum value : Nat) : Nat → Option Nat
  | 0 => some 0
  | count + 1 =>
      match repeated maximum value count with
      | none => none
      | some total => if total + value ≤ maximum then some (total + value) else none

def closed (maximum count value : Nat) : Option Nat :=
  if count * value ≤ maximum then some (count * value) else none

theorem repeated_eq_closed (maximum count value : Nat) :
    repeated maximum value count = closed maximum count value := by
  induction count with
  | zero => simp [repeated, closed]
  | succ count ih =>
      rw [repeated, ih]
      by_cases h : count * value ≤ maximum
      · simp [closed, h, Nat.succ_mul]
      · have hnext : ¬ (count + 1) * value ≤ maximum := by
          rw [Nat.succ_mul]
          omega
        simp [closed, h, hnext]

theorem index_increment_within (maximum count index : Nat)
    (count_valid : count ≤ maximum) (continues : index < count) :
    index + 1 ≤ maximum := by
  omega

/- Overflow occurs before any successful return and yields exactly `none` in
   both models. This is stronger than comparing only in-range return values. -/
theorem overflow_agrees (maximum count value : Nat) :
    repeated maximum value count = none ↔ maximum < count * value := by
  rw [repeated_eq_closed]
  simp [closed]

#print axioms repeated_eq_closed
#print axioms index_increment_within
#print axioms overflow_agrees

end HiaCheckedReduction
