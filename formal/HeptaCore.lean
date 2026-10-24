import Lean.Elab.Tactic.Omega

/-!
Hepta's small abstract core, version 0.2.

These are kernel-checked theorems about the definitions in this file. They do
not assert that the Python compiler, Rust lowering, allocator, FFI, hardware,
or scheduler refines this model. That refinement remains a separate obligation.
Loan identifiers and lifetimes are abstracted to a loan count; this is not a
complete language memory model.
-/

namespace Hepta

structure Resource where
  live : Bool
  owner : Nat
  readers : Nat
  writer : Bool
  deriving DecidableEq

def Resource.Valid (s : Resource) : Prop :=
  (s.live = false → s.readers = 0 ∧ s.writer = false) ∧
  (s.writer = true → s.readers = 0)

inductive ResourceOp where
  | borrowRead | endRead | borrowWrite | endWrite | release
  | transfer (newOwner : Nat)

def resourceStep (s : Resource) : ResourceOp → Option Resource
  | .borrowRead =>
    if s.live = true ∧ s.writer = false then
      some { s with readers := s.readers + 1 }
    else none
  | .endRead =>
    if s.readers > 0 then some { s with readers := s.readers - 1 } else none
  | .borrowWrite =>
    if s.live = true ∧ s.readers = 0 ∧ s.writer = false then
      some { s with writer := true }
    else none
  | .endWrite =>
    if s.writer = true then some { s with writer := false } else none
  | .release =>
    if s.live = true ∧ s.readers = 0 ∧ s.writer = false then
      some { s with live := false }
    else none
  | .transfer newOwner =>
    if s.live = true ∧ s.readers = 0 ∧ s.writer = false then
      some { s with owner := newOwner }
    else none

theorem resource_preservation (s t : Resource) (op : ResourceOp)
    (valid : s.Valid) (step : resourceStep s op = some t) : t.Valid := by
  cases op <;> simp only [resourceStep] at step <;>
    split at step <;> simp_all only [Option.some.injEq, reduceCtorEq]
  all_goals subst t; simp_all [Resource.Valid] <;> omega

theorem no_release_with_readers (s : Resource) (h : s.readers > 0) :
    resourceStep s .release = none := by
  simp only [resourceStep]
  split <;> simp_all <;> omega

theorem no_release_with_writer (s : Resource) (h : s.writer = true) :
    resourceStep s .release = none := by
  simp [resourceStep, h]

theorem released_cannot_be_borrowed (s : Resource) (h : s.live = false) :
    resourceStep s .borrowRead = none ∧ resourceStep s .borrowWrite = none := by
  simp [resourceStep, h]

theorem release_is_not_repeatable (s t : Resource)
    (h : resourceStep s .release = some t) : resourceStep t .release = none := by
  simp only [resourceStep] at h
  split at h
  · simp only [Option.some.injEq] at h
    subst t
    simp [resourceStep]
  · contradiction

inductive ResourceTrace : Resource → Resource → Prop where
  | refl (s) : ResourceTrace s s
  | next {s t u op} : ResourceTrace s t → resourceStep t op = some u → ResourceTrace s u

theorem resource_trace_preservation {s t : Resource} (v : s.Valid)
    (trace : ResourceTrace s t) : t.Valid := by
  induction trace with
  | refl => exact v
  | next _ step ih => exact resource_preservation _ _ _ ih step

/- Bounded task-group admission and channel occupancy. Accounting is for
admitted input payload and queue slots, not whole-process memory. -/

structure Limits where
  tasks : Nat
  inputBytes : Nat
  queueSlots : Nat

structure Usage where
  admitted : Nat
  inputBytes : Nat
  queued : Nat
  deriving DecidableEq

def Usage.Within (u : Usage) (b : Limits) : Prop :=
  u.admitted ≤ b.tasks ∧ u.inputBytes ≤ b.inputBytes ∧ u.queued ≤ b.queueSlots

inductive BudgetOp where
  | admit (bytes : Nat)
  | send | receive

def budgetStep (b : Limits) (u : Usage) : BudgetOp → Option Usage
  | .admit bytes =>
    if u.admitted + 1 ≤ b.tasks ∧ u.inputBytes + bytes ≤ b.inputBytes then
      some { u with admitted := u.admitted + 1, inputBytes := u.inputBytes + bytes }
    else none
  | .send =>
    if u.queued + 1 ≤ b.queueSlots then some { u with queued := u.queued + 1 } else none
  | .receive =>
    if u.queued > 0 then some { u with queued := u.queued - 1 } else none

theorem budget_preservation (b : Limits) (u v : Usage) (op : BudgetOp)
    (within : u.Within b) (step : budgetStep b u op = some v) : v.Within b := by
  cases op <;> simp only [budgetStep] at step <;>
    split at step <;> simp_all only [Option.some.injEq, reduceCtorEq]
  all_goals subst v; simp_all [Usage.Within] <;> omega

theorem full_channel_rejects_send (b : Limits) (u : Usage)
    (full : u.queued = b.queueSlots) : budgetStep b u .send = none := by
  simp [budgetStep, full] <;> omega

theorem exhausted_tasks_reject_admission (b : Limits) (u : Usage) (bytes : Nat)
    (full : u.admitted = b.tasks) : budgetStep b u (.admit bytes) = none := by
  simp [budgetStep, full] <;> omega

/- A precise lowering theorem for a tiny wrapping-u64 expression language.
This proves the abstract stack translation below, not emit_rust/emit_c. -/

abbrev Word := BitVec 64

inductive Expression where
  | literal (value : Word)
  | add (left right : Expression)
  | mul (left right : Expression)

def evaluate : Expression → Word
  | .literal value => value
  | .add left right => evaluate left + evaluate right
  | .mul left right => evaluate left * evaluate right

inductive Instruction where
  | push (value : Word)
  | add | mul

def executeOne : Instruction → List Word → Option (List Word)
  | .push value, stack => some (value :: stack)
  | .add, right :: left :: stack => some ((left + right) :: stack)
  | .mul, right :: left :: stack => some ((left * right) :: stack)
  | _, _ => none

def execute : List Instruction → List Word → Option (List Word)
  | [], stack => some stack
  | op :: rest, stack => (executeOne op stack).bind (execute rest)

def lower : Expression → List Instruction
  | .literal value => [.push value]
  | .add left right => lower left ++ lower right ++ [.add]
  | .mul left right => lower left ++ lower right ++ [.mul]

theorem execute_append (a b : List Instruction) (stack : List Word) :
    execute (a ++ b) stack = (execute a stack).bind (execute b) := by
  induction a generalizing stack with
  | nil => rfl
  | cons head rest ih =>
    simp only [List.cons_append, execute]
    cases h : executeOne head stack <;> simp [h, ih]

theorem lowering_preserves_value (expression : Expression) (stack : List Word) :
    execute (lower expression) stack = some (evaluate expression :: stack) := by
  induction expression generalizing stack with
  | literal value => rfl
  | add left right leftIH rightIH =>
    simp [lower, execute_append, leftIH, rightIH, execute, executeOne, evaluate]
  | mul left right leftIH rightIH =>
    simp [lower, execute_append, leftIH, rightIH, execute, executeOne, evaluate]

#print axioms resource_preservation
#print axioms resource_trace_preservation
#print axioms budget_preservation
#print axioms lowering_preserves_value

end Hepta
