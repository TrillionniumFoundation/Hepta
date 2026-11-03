/-!
UNCHECKED proof text until acceptance by the repository-pinned Lean CI lane.
Append after the exact HiaInitializationPrefix.lean input (no extra imports).

This is a partial scalar projection of a selected true edge and a local add,
not a Core interpreter or memory model. It does not establish arrival at the
add, body framing, definition of every edge operand, allocation identity,
exporter/parser refinement, or a whole-loop/backend/resource theorem.
-/

namespace HiaGuardedUsizeSlice

inductive TypeTag where
  | usize
  | other
  deriving DecidableEq, Repr

inductive CompareOp where
  | lt
  | le
  | other
  deriving DecidableEq, Repr

inductive Arm where
  | thenArm
  | elseArm
  deriving DecidableEq, Repr

inductive AddOp where
  | checked
  | wrapping
  | other
  deriving DecidableEq, Repr

inductive Value where
  | usize (value : Nat)
  | opaque
  deriving DecidableEq, Repr

abbrev Env := Nat → Option Value

structure Descriptor where
  sourceIndex : Nat
  sourceExtent : Nat
  compareOutput : Nat
  branchCondition : Nat
  indexType : TypeTag
  extentType : TypeTag
  compareOp : CompareOp
  selectedArm : Arm
  incoming : List Nat
  indexSlot : Nat
  extentSlot : Nat
  addIndexSlot : Nat
  addOp : AddOp
  addType : TypeTag
  literalType : TypeTag
  literalValue : Nat
  literalOrdinal : Nat
  addOrdinal : Nat
  deriving DecidableEq, Repr

/-- All validation facts are computed from the descriptor, not proof fields. -/
def Valid (d : Descriptor) : Prop :=
  d.indexType = .usize ∧
  d.extentType = .usize ∧
  d.compareOp = .lt ∧
  d.branchCondition = d.compareOutput ∧
  d.selectedArm = .thenArm ∧
  d.incoming[d.indexSlot]? = some d.sourceIndex ∧
  d.incoming[d.extentSlot]? = some d.sourceExtent ∧
  d.addIndexSlot = d.indexSlot ∧
  d.addOp ≠ .other ∧
  d.addType = .usize ∧
  d.literalType = .usize ∧
  d.literalValue = 1 ∧
  d.literalOrdinal < d.addOrdinal

instance (d : Descriptor) : Decidable (Valid d) := by
  unfold Valid
  infer_instance

/-- Opaque, absent, or out-of-range values cannot be used as usize. -/
def readUsize (maximum : Nat) (env : Env) (slot : Nat) : Option Nat :=
  match env slot with
  | some (.usize n) => if n ≤ maximum then some n else none
  | _ => none

/-- Every lookup reads the same immutable incoming environment. -/
def phiEnv (d : Descriptor) (env : Env) : Env := fun slot =>
  match d.incoming[slot]? with -- MUTATION_SITE_PHI_LOOKUP
  | some source => env source
  | none => none

def evalGuard (maximum : Nat) (d : Descriptor) (env : Env) : Option Bool :=
  match readUsize maximum env d.sourceIndex,
      readUsize maximum env d.sourceExtent with
  | some index, some extent =>
    match d.compareOp with
    | .lt => some (decide (index < extent))
    | .le => some (decide (index ≤ extent))
    | .other => none
  | _, _ => none

/-- The literal is a direct operand. It is never installed into phiEnv. -/
def evalAdd (mode : AddOp) (maximum index literal : Nat) : Option Nat :=
  let sum := index + literal -- MUTATION_SITE_ADD_LITERAL
  match mode with
  | .checked => if sum ≤ maximum then some sum else none
  | .wrapping => some (sum % (maximum + 1))
  | .other => none

def evalStep (mode : AddOp) (maximum : Nat) (d : Descriptor) (env : Env) : Option Nat :=
  if Valid d then
    if evalGuard maximum d env = some true then -- MUTATION_SITE_STEP_GUARD
      match readUsize maximum (phiEnv d env) d.addIndexSlot,
          readUsize maximum (phiEnv d env) d.extentSlot with
      | some index, some _extent => evalAdd mode maximum index d.literalValue
      | _, _ => none
    else none
  else none

def evalSelectedStep (maximum : Nat) (d : Descriptor) (env : Env) : Option Nat :=
  evalStep d.addOp maximum d env

theorem readUsize_bounded (maximum : Nat) (env : Env) (slot n : Nat)
    (read : readUsize maximum env slot = some n) : n ≤ maximum := by
  unfold readUsize at read
  cases hvalue : env slot with
  | none => simp [hvalue] at read
  | some value =>
    cases value with
    | «opaque» => simp [hvalue] at read
    | usize value =>
      by_cases bounded : value ≤ maximum
      · have same : value = n := by simpa [hvalue, bounded] using read
        omega
      · simp [hvalue, bounded] at read

theorem readUsize_phi (maximum : Nat) (d : Descriptor) (env : Env)
    (slot source : Nat) (position : d.incoming[slot]? = some source) :
    readUsize maximum (phiEnv d env) slot = readUsize maximum env source := by
  simp [readUsize, phiEnv, position]

/-- Strictness and source values are derived from the actual guard evaluation. -/
theorem guard_values (maximum : Nat) (d : Descriptor) (env : Env)
    (strict : d.compareOp = .lt)
    (guard : evalGuard maximum d env = some true) :
    ∃ index extent,
      readUsize maximum env d.sourceIndex = some index ∧
      readUsize maximum env d.sourceExtent = some extent ∧ index < extent := by
  unfold evalGuard at guard
  cases hi : readUsize maximum env d.sourceIndex with
  | none => simp [hi] at guard
  | some index =>
    cases hn : readUsize maximum env d.sourceExtent with
    | none => simp [hi, hn] at guard
    | some extent =>
      have below : index < extent := by simpa [hi, hn, strict] using guard
      exact ⟨index, extent, rfl, rfl, below⟩

theorem checked_add_in_range (maximum index : Nat) (bounded : index + 1 ≤ maximum) :
    evalAdd .checked maximum index 1 = some (index + 1) := by
  simp [evalAdd, bounded]

theorem wrapping_add_in_range (maximum index : Nat) (bounded : index + 1 ≤ maximum) :
    evalAdd .wrapping maximum index 1 = some (index + 1) := by
  have below : index + 1 < maximum + 1 := by omega
  simp [evalAdd, Nat.mod_eq_of_lt below]

/-- Existence of BOTH successful additions, for arbitrary environments and valid
    descriptors. No caller-supplied i<N or phi-value premise is used. -/
theorem guarded_successors (maximum : Nat) (d : Descriptor) (env : Env)
    (valid : Valid d) (guard : evalGuard maximum d env = some true) :
    ∃ index extent,
      readUsize maximum env d.sourceIndex = some index ∧
      readUsize maximum env d.sourceExtent = some extent ∧
      index < extent ∧
      evalStep .checked maximum d env = some (index + 1) ∧
      evalStep .wrapping maximum d env = some (index + 1) ∧
      index + 1 ≤ extent ∧ extent ≤ maximum ∧ index + 1 ≤ maximum := by
  have validCopy := valid
  obtain ⟨_indexType, _extentType, strict, _condition, _arm,
    indexPosition, extentPosition, addPosition, _mode, _addType,
    _literalType, one, _order⟩ := validCopy
  obtain ⟨index, extent, hi, hn, below⟩ := guard_values maximum d env strict guard
  have extentBound := readUsize_bounded maximum env d.sourceExtent extent hn
  have successorBound : index + 1 ≤ maximum :=
    HiaInitializationPrefix.increment_within_limit index extent maximum below extentBound
  have indexRead : readUsize maximum (phiEnv d env) d.addIndexSlot = some index := by
    rw [addPosition, readUsize_phi maximum d env d.indexSlot d.sourceIndex indexPosition]
    exact hi
  have extentRead : readUsize maximum (phiEnv d env) d.extentSlot = some extent := by
    rw [readUsize_phi maximum d env d.extentSlot d.sourceExtent extentPosition]
    exact hn
  have checked : evalStep .checked maximum d env = some (index + 1) := by
    simpa [evalStep, valid, guard, indexRead, extentRead, one] using
      checked_add_in_range maximum index successorBound
  have wrapping : evalStep .wrapping maximum d env = some (index + 1) := by
    simpa [evalStep, valid, guard, indexRead, extentRead, one] using
      wrapping_add_in_range maximum index successorBound
  exact ⟨index, extent, hi, hn, below, checked, wrapping, by omega,
    extentBound, successorBound⟩

/-- In particular the descriptor's actual selected opcode has a successor. -/
theorem selected_successor (maximum : Nat) (d : Descriptor) (env : Env)
    (valid : Valid d) (guard : evalGuard maximum d env = some true) :
    ∃ index extent,
      readUsize maximum env d.sourceIndex = some index ∧
      readUsize maximum env d.sourceExtent = some extent ∧
      evalSelectedStep maximum d env = some (index + 1) ∧
      index + 1 ≤ extent ∧ extent ≤ maximum ∧ index + 1 ≤ maximum := by
  obtain ⟨index, extent, hi, hn, _below, checked, wrapping, within, extentBound,
    successorBound⟩ := guarded_successors maximum d env valid guard
  have supported : d.addOp ≠ .other := valid.2.2.2.2.2.2.2.2.1
  have selected : evalSelectedStep maximum d env = some (index + 1) := by
    unfold evalSelectedStep
    cases mode : d.addOp with
    | checked => exact checked
    | wrapping => exact wrapping
    | other => exact False.elim (supported mode)
  exact ⟨index, extent, hi, hn, selected, within, extentBound, successorBound⟩

/-- Negative semantic obligation: bypassing the guard must not validate. -/
theorem false_guard_no_step (mode : AddOp) (maximum : Nat) (d : Descriptor) (env : Env)
    (guard : evalGuard maximum d env ≠ some true) :
    evalStep mode maximum d env = none := by
  simp [evalStep, guard]

theorem invalid_no_step (mode : AddOp) (maximum : Nat) (d : Descriptor) (env : Env)
    (invalid : ¬ Valid d) : evalStep mode maximum d env = none := by
  simp [evalStep, invalid]

#print axioms readUsize_bounded
#print axioms readUsize_phi
#print axioms guard_values
#print axioms checked_add_in_range
#print axioms wrapping_add_in_range
#print axioms guarded_successors
#print axioms selected_successor
#print axioms false_guard_no_step
#print axioms invalid_no_step

end HiaGuardedUsizeSlice
