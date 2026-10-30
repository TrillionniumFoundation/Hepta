import Lean.Elab.Tactic.Omega

/- A selected, phase-indexed byte-owner Core. This is an independent mathematical
   model, not a refinement proof for the Python exporter, checker, VM or LLVM.
   Empty owners are capabilities; they are not physical payload allocations.
   Heap quota stops precede an allocator attempt. Traps retain the stopped store. -/
namespace HiaOwnedExit

inductive Phase where | empty | owned
  deriving DecidableEq

structure Owner where
  identity : Nat
  bytes : Nat
  deriving DecidableEq

structure Store where
  owner : Option Owner := none
  created : Nat := 0
  dropped : Nat := 0
  allocations : Nat := 0
  frees : Nat := 0
  attempts : Nat := 0
  peak : Nat := 0
  ok : Bool := false
  deriving DecidableEq

def liveOwners (s : Store) : Nat := if s.owner.isSome then 1 else 0

def liveBytes (s : Store) : Nat := match s.owner with
  | none => 0
  | some owner => owner.bytes

def realOwners (s : Store) : Nat := if liveBytes s = 0 then 0 else 1

def Valid (quota : Nat) (s : Store) : Prop :=
  s.created = s.dropped + liveOwners s ∧
  s.allocations = s.frees + realOwners s ∧
  liveBytes s ≤ s.peak ∧ s.peak ≤ quota

def Matches : Phase → Store → Prop
  | .empty, s => s.owner = none
  | .owned, s => ∃ owner, s.owner = some owner

def createOwner (s : Store) (bytes : Nat) (ok : Bool) : Store :=
  { s with
    owner := some ⟨s.created + 1, bytes⟩
    created := s.created + 1
    allocations := s.allocations + (if bytes = 0 then 0 else 1)
    peak := max s.peak bytes
    ok := ok }

def dropOwner (s : Store) : Store :=
  { s with owner := none, dropped := s.dropped + 1, frees := s.frees + realOwners s }

structure Inputs where
  size : Nat
  quota : Nat
  cancel : Bool
  abort : Bool
  failure : Nat → Bool

def objectLimit : Nat := 9223372036854775807

inductive Allocation where
  | next (store : Store)
  | heap (store : Store)

def allocateOwner (inputs : Inputs) (requested : Nat) (s : Store) : Allocation :=
  if requested = 0 then .next (createOwner s 0 true)
  else if objectLimit < requested then .next (createOwner s 0 false)
  else if inputs.quota < requested then .heap s
  else
    let advanced := { s with attempts := s.attempts + 1 }
    if inputs.failure advanced.attempts then .next (createOwner advanced 0 false)
    else .next (createOwner advanced requested true)

inductive Extent where
  | input
  | literal (value : Nat)

def extentValue (inputs : Inputs) : Extent → Nat
  | .input => inputs.size
  | .literal value => value

inductive Condition where | ok | cancel | abort | literal (value : Bool)

def conditionValue (inputs : Inputs) (s : Store) : Condition → Bool
  | .ok => s.ok
  | .cancel => inputs.cancel
  | .abort => inputs.abort
  | .literal value => value

inductive Program : Phase → Type where
  | ret (value : Nat) : Program .empty
  | trap : Program phase
  | drop (next : Program .empty) : Program .owned
  | allocate (extent : Extent) (next : Program .owned) : Program .empty
  | callAllocate (extent : Extent) (next : Program .owned) : Program .empty
  | branch (test : Condition) (yes no : Program phase) : Program phase

inductive Exit where | returned (value : Nat) | trapped | heapExceeded
  deriving DecidableEq

inductive Event where
  | allocated (requested identity bytes : Nat) (ok : Bool)
  | dropped (identity bytes : Nat)
  | heapStopped (requested : Nat)
  | callEnter | callReturn
  deriving DecidableEq

structure Outcome where
  exit : Exit
  store : Store
  events : List Event
  deriving DecidableEq

def allocationEvent (requested : Nat) (s : Store) : Event :=
  let owner := s.owner.getD ⟨0, 0⟩
  .allocated requested owner.identity owner.bytes s.ok

def dropEvent (s : Store) : Event :=
  let owner := s.owner.getD ⟨0, 0⟩
  .dropped owner.identity owner.bytes

def emit (events : List Event) (outcome : Outcome) : Outcome :=
  { outcome with events := events ++ outcome.events }

def run : Program phase → Inputs → Store → Outcome
  | .ret value, _, s => ⟨.returned value, s, []⟩
  | .trap, _, s => ⟨.trapped, s, []⟩
  | .drop next, inputs, s => emit [dropEvent s] (run next inputs (dropOwner s))
  | .allocate extent next, inputs, s =>
      let requested := extentValue inputs extent
      match allocateOwner inputs requested s with
      | .heap stopped => ⟨.heapExceeded, stopped, [.heapStopped requested]⟩
      | .next owned => emit [allocationEvent requested owned] (run next inputs owned)
  | .callAllocate extent next, inputs, s =>
      let requested := extentValue inputs extent
      match allocateOwner inputs requested s with
      | .heap stopped => ⟨.heapExceeded, stopped, [.callEnter, .heapStopped requested]⟩
      | .next owned =>
          emit [.callEnter, allocationEvent requested owned, .callReturn] (run next inputs owned)
  | .branch test yes no, inputs, s =>
      if conditionValue inputs s test then run yes inputs s else run no inputs s

def inlineCalls : Program phase → Program phase
  | .ret value => .ret value
  | .trap => .trap
  | .drop next => .drop (inlineCalls next)
  | .allocate extent next => .allocate extent (inlineCalls next)
  | .callAllocate extent next => .allocate extent (inlineCalls next)
  | .branch test yes no => .branch test (inlineCalls yes) (inlineCalls no)

def resourceEvent : Event → Bool
  | .callEnter | .callReturn => false
  | _ => true

def observe (outcome : Outcome) : Outcome :=
  { outcome with events := outcome.events.filter resourceEvent }

theorem create_owned (s : Store) (bytes : Nat) (ok : Bool) :
    Matches .owned (createOwner s bytes ok) :=
  ⟨⟨s.created + 1, bytes⟩, rfl⟩

theorem create_preserves (quota : Nat) (s : Store) (bytes : Nat) (ok : Bool)
    (valid : Valid quota s) (empty : Matches .empty s) (fits : bytes ≤ quota) :
    Valid quota (createOwner s bytes ok) := by
  by_cases zero : bytes = 0 <;>
    simp_all [Valid, Matches, createOwner, liveOwners, realOwners, liveBytes, Nat.max_le] <;> omega

theorem create_identity_fresh (s : Store) (bytes : Nat) (ok : Bool) :
    (createOwner s bytes ok).owner = some ⟨s.created + 1, bytes⟩ ∧
    s.created < (createOwner s bytes ok).created := by
  simp [createOwner]

theorem drop_empty (s : Store) : Matches .empty (dropOwner s) := rfl

theorem drop_preserves (quota : Nat) (s : Store)
    (valid : Valid quota s) (owned : Matches .owned s) :
    Valid quota (dropOwner s) := by
  obtain ⟨owner, present⟩ := owned
  by_cases zero : owner.bytes = 0 <;>
    simp_all [Valid, dropOwner, liveOwners, realOwners, liveBytes] <;> omega

theorem zero_allocation_exact (inputs : Inputs) (s : Store) :
    allocateOwner inputs 0 s = .next (createOwner s 0 true) := by
  simp [allocateOwner]

theorem oversize_allocation_exact (inputs : Inputs) (s : Store) (requested : Nat)
    (oversize : objectLimit < requested) :
    allocateOwner inputs requested s = .next (createOwner s 0 false) := by
  have positive : requested ≠ 0 := by unfold objectLimit at oversize; omega
  simp [allocateOwner, positive, oversize]

theorem quota_stop_exact (inputs : Inputs) (s : Store) (requested : Nat)
    (positive : requested ≠ 0) (bounded : requested ≤ objectLimit)
    (overQuota : inputs.quota < requested) :
    allocateOwner inputs requested s = .heap s := by
  simp [allocateOwner, positive, Nat.not_lt.mpr bounded, overQuota]

theorem positive_refusal_exact (inputs : Inputs) (s : Store) (requested : Nat)
    (positive : requested ≠ 0) (bounded : requested ≤ objectLimit)
    (fits : requested ≤ inputs.quota) (refused : inputs.failure (s.attempts + 1) = true) :
    allocateOwner inputs requested s =
      .next (createOwner { s with attempts := s.attempts + 1 } 0 false) := by
  simp [allocateOwner, positive, Nat.not_lt.mpr bounded, Nat.not_lt.mpr fits, refused]

theorem positive_success_exact (inputs : Inputs) (s : Store) (requested : Nat)
    (positive : requested ≠ 0) (bounded : requested ≤ objectLimit)
    (fits : requested ≤ inputs.quota) (accepted : inputs.failure (s.attempts + 1) = false) :
    allocateOwner inputs requested s =
      .next (createOwner { s with attempts := s.attempts + 1 } requested true) := by
  simp [allocateOwner, positive, Nat.not_lt.mpr bounded, Nat.not_lt.mpr fits, accepted]

theorem allocation_heap_unchanged (inputs : Inputs) (s stopped : Store) (requested : Nat)
    (step : allocateOwner inputs requested s = .heap stopped) : stopped = s := by
  by_cases zero : requested = 0
  · simp [allocateOwner, zero] at step
  by_cases large : objectLimit < requested
  · simp [allocateOwner, zero, large] at step
  by_cases overQuota : inputs.quota < requested
  · simpa [allocateOwner, zero, large, overQuota] using step.symm
  by_cases refused : inputs.failure (s.attempts + 1) = true <;>
    simp [allocateOwner, zero, large, overQuota, refused] at step

theorem allocation_next_preserves (inputs : Inputs) (s owned : Store) (requested : Nat)
    (valid : Valid inputs.quota s) (empty : Matches .empty s)
    (step : allocateOwner inputs requested s = .next owned) :
    Valid inputs.quota owned ∧ Matches .owned owned := by
  by_cases zero : requested = 0
  · simp [allocateOwner, zero] at step
    subst owned
    exact ⟨create_preserves _ _ _ _ valid empty (Nat.zero_le _), create_owned _ _ _⟩
  by_cases large : objectLimit < requested
  · simp [allocateOwner, zero, large] at step
    subst owned
    exact ⟨create_preserves _ _ _ _ valid empty (Nat.zero_le _), create_owned _ _ _⟩
  by_cases overQuota : inputs.quota < requested
  · simp [allocateOwner, zero, large, overQuota] at step
  have fits : requested ≤ inputs.quota := by omega
  have advancedValid : Valid inputs.quota { s with attempts := s.attempts + 1 } := by
    simpa [Valid, liveOwners, liveBytes, realOwners] using valid
  have advancedEmpty : Matches .empty { s with attempts := s.attempts + 1 } := empty
  by_cases refused : inputs.failure (s.attempts + 1) = true
  · simp [allocateOwner, zero, large, overQuota, refused] at step
    subst owned
    exact ⟨create_preserves _ _ _ _ advancedValid advancedEmpty (Nat.zero_le _), create_owned _ _ _⟩
  · simp [allocateOwner, zero, large, overQuota, refused] at step
    subst owned
    exact ⟨create_preserves _ _ _ _ advancedValid advancedEmpty fits, create_owned _ _ _⟩

def Safe (quota : Nat) (outcome : Outcome) : Prop :=
  Valid quota outcome.store ∧
  (∀ value, outcome.exit = .returned value → outcome.store.owner = none)

theorem execute_safety (program : Program phase) (inputs : Inputs) (s : Store)
    (valid : Valid inputs.quota s) (phaseMatches : Matches phase s) :
    Safe inputs.quota (run program inputs s) := by
  induction program generalizing s with
  | ret value =>
      exact ⟨valid, by intro value returned; exact phaseMatches⟩
  | trap =>
      exact ⟨valid, by intro value impossible; cases impossible⟩
  | drop next ih =>
      simpa [run, Safe, emit] using ih (dropOwner s) (drop_preserves _ _ valid phaseMatches) (drop_empty _)
  | allocate extent next ih =>
      cases step : allocateOwner inputs (extentValue inputs extent) s with
      | heap stopped =>
          have same := allocation_heap_unchanged inputs s stopped _ step
          subst stopped
          exact ⟨by simpa [run, step] using valid, by simp [run, step]⟩
      | next owned =>
          obtain ⟨good, present⟩ := allocation_next_preserves inputs s owned _ valid phaseMatches step
          simpa [run, step, Safe, emit] using ih owned good present
  | callAllocate extent next ih =>
      cases step : allocateOwner inputs (extentValue inputs extent) s with
      | heap stopped =>
          have same := allocation_heap_unchanged inputs s stopped _ step
          subst stopped
          exact ⟨by simpa [run, step] using valid, by simp [run, step]⟩
      | next owned =>
          obtain ⟨good, present⟩ := allocation_next_preserves inputs s owned _ valid phaseMatches step
          simpa [run, step, Safe, emit] using ih owned good present
  | branch test yes no yesIH noIH =>
      cases testValue : conditionValue inputs s test <;>
        simp [run, testValue, yesIH s valid phaseMatches, noIH s valid phaseMatches]

def initial : Store := {}

theorem initial_valid (quota : Nat) : Valid quota initial := by
  simp [initial, Valid, liveOwners, realOwners, liveBytes]

theorem initial_empty : Matches .empty initial := rfl

theorem ordinary_exit_balanced (program : Program .empty) (inputs : Inputs) (value : Nat)
    (returned : (run program inputs initial).exit = .returned value) :
    (run program inputs initial).store.owner = none ∧
    (run program inputs initial).store.created = (run program inputs initial).store.dropped ∧
    (run program inputs initial).store.allocations = (run program inputs initial).store.frees := by
  obtain ⟨valid, clean⟩ := execute_safety program inputs initial (initial_valid _) initial_empty
  have empty := clean value returned
  simp only [Valid] at valid
  refine ⟨empty, ?_, ?_⟩ <;>
    simp_all [liveOwners, realOwners, liveBytes]

theorem payload_budget_bound (program : Program .empty) (inputs : Inputs) :
    liveBytes (run program inputs initial).store ≤ inputs.quota ∧
    (run program inputs initial).store.peak ≤ inputs.quota := by
  have valid := (execute_safety program inputs initial (initial_valid _) initial_empty).1
  exact ⟨Nat.le_trans valid.2.2.1 valid.2.2.2, valid.2.2.2⟩

theorem trap_keeps_store (phase : Phase) (inputs : Inputs) (s : Store) :
    (run (.trap : Program phase) inputs s).store = s := rfl

theorem observe_emit (events : List Event) (outcome : Outcome) :
    observe (emit events outcome) = emit (events.filter resourceEvent) (observe outcome) := by
  cases outcome
  simp [observe, emit, List.filter_append]

theorem call_erasure_preserves (program : Program phase) (inputs : Inputs) (s : Store) :
    observe (run (inlineCalls program) inputs s) = observe (run program inputs s) := by
  induction program generalizing s with
  | ret value => rfl
  | trap => rfl
  | drop next ih => simp [inlineCalls, run, observe_emit, ih]
  | allocate extent next ih =>
      cases step : allocateOwner inputs (extentValue inputs extent) s <;>
        simp [inlineCalls, run, step, observe_emit, ih]
  | callAllocate extent next ih =>
      cases step : allocateOwner inputs (extentValue inputs extent) s with
      | heap stopped => simp [inlineCalls, run, step, observe, resourceEvent]
      | next owned =>
          simp only [inlineCalls, run, step, observe_emit]
          simp only [List.filter_cons, List.filter_nil, resourceEvent, Bool.false_eq_true,
            if_false, if_true]
          rw [ih]
  | branch test yes no yesIH noIH =>
      cases testValue : conditionValue inputs s test <;>
        simp [inlineCalls, run, testValue, yesIH, noIH]

end HiaOwnedExit
