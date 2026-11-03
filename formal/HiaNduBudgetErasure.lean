import Lean.Elab.Tactic.Omega

/-!
Budget erasure for a finite deterministic scalar-cost decision tree.

Every edge and terminal cost is a natural number. `boundedBest` checks the
remaining budget at every step; `best` computes the unconstrained minimum.
The theorem says that checking that minimum once gives the same result.

This models the full-cost v2 profile's scalar nonnegative costs. It does not
prove the Python implementation, its model intake, native NDU, measured timing,
or multiobjective/stochastic planning. Reusing a continuation also requires
that its complete state determines legal successors and their costs.
-/

namespace HiaNduBudgetErasure

def choose : Option Nat → Option Nat → Option Nat
  | none, right => right
  | left, none => left
  | some left, some right => if left ≤ right then some left else some right

def keep (budget : Nat) : Option Nat → Option Nat
  | none => none
  | some cost => if cost ≤ budget then some cost else none

def add (charge : Nat) : Option Nat → Option Nat
  | none => none
  | some cost => some (charge + cost)

theorem keep_choose (budget : Nat) (left right : Option Nat) :
    keep budget (choose left right) =
      choose (keep budget left) (keep budget right) := by
  cases left with
  | none => simp [choose, keep]
  | some left =>
      cases right with
      | none =>
          by_cases fits : left ≤ budget
          · simp [choose, keep, fits]
          · simp [choose, keep, fits]
      | some right =>
          by_cases order : left ≤ right
          · by_cases fitsLeft : left ≤ budget
            · by_cases fitsRight : right ≤ budget
              · simp [choose, keep, order, fitsLeft, fitsRight]
              · simp [choose, keep, order, fitsLeft, fitsRight]
            · have notRight : ¬ right ≤ budget := by omega
              simp [choose, keep, order, fitsLeft, notRight]
          · by_cases fitsRight : right ≤ budget
            · by_cases fitsLeft : left ≤ budget
              · simp [choose, keep, order, fitsLeft, fitsRight]
              · simp [choose, keep, order, fitsLeft, fitsRight]
            · have notLeft : ¬ left ≤ budget := by omega
              simp [choose, keep, order, fitsRight, notLeft]

theorem keep_add (budget charge : Nat) (cost : Option Nat) :
    keep budget (add charge cost) =
      if charge ≤ budget then add charge (keep (budget - charge) cost) else none := by
  cases cost with
  | none => simp [add, keep]
  | some cost =>
      by_cases charged : charge ≤ budget
      · by_cases total : charge + cost ≤ budget
        · have tail : cost ≤ budget - charge := by omega
          simp [add, keep, charged, total, tail]
        · have tail : ¬ cost ≤ budget - charge := by omega
          simp [add, keep, charged, total, tail]
      · have total : ¬ charge + cost ≤ budget := by omega
        simp [add, keep, charged, total]

inductive Tree where
  | deadEnd
  | finish (terminalCost : Nat)
  | choice (left right : Tree)
  | pay (charge : Nat) (next : Tree)

def best : Tree → Option Nat
  | .deadEnd => none
  | .finish charge => some charge
  | .choice left right => choose (best left) (best right)
  | .pay charge next => add charge (best next)

def boundedBest : Tree → Nat → Option Nat
  | .deadEnd, _ => none
  | .finish charge, budget => keep budget (some charge)
  | .choice left right, budget =>
      choose (boundedBest left budget) (boundedBest right budget)
  | .pay charge next, budget =>
      if charge ≤ budget then add charge (boundedBest next (budget - charge)) else none

theorem erase_remaining_budget (tree : Tree) (budget : Nat) :
    boundedBest tree budget = keep budget (best tree) := by
  induction tree generalizing budget with
  | deadEnd => rfl
  | finish charge => rfl
  | choice left right leftProof rightProof =>
      simp only [boundedBest, best, leftProof, rightProof]
      exact (keep_choose budget (best left) (best right)).symm
  | pay charge next nextProof =>
      simp only [boundedBest, best, nextProof]
      exact (keep_add budget charge (best next)).symm

theorem minimum_feasible_iff (tree : Tree) (minimum budget : Nat)
    (found : best tree = some minimum) :
    boundedBest tree budget = some minimum ↔ minimum ≤ budget := by
  rw [erase_remaining_budget, found]
  by_cases fits : minimum ≤ budget
  · simp [keep, fits]
  · simp [keep, fits]

theorem cheaper_continuation_remains_feasible (spent cheap costly budget : Nat)
    (dominates : cheap ≤ costly) (feasible : spent + costly ≤ budget) :
    spent + cheap ≤ budget := by omega

#print axioms keep_choose
#print axioms keep_add
#print axioms erase_remaining_budget
#print axioms minimum_feasible_iff
#print axioms cheaper_continuation_remains_feasible

end HiaNduBudgetErasure
