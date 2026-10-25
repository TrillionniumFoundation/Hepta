import Lean.Elab.Tactic.Omega

/-!
An explicit allocation-identity and typed-expression model. The definitions are
part of this model, not a description of all Rust/C pointers or the Python
compiler. In particular, numeric address equality does not confer authority.
No claim below establishes production AST/IR/native refinement, FFI validity,
general lifetimes, scheduler fairness, or physical hardware behavior.
-/

namespace Hepta.Memory

structure Allocation where
  identity : Nat
  generation : Nat
  live : Bool
  bytes : Nat
  deriving DecidableEq

structure Pointer where
  identity : Nat
  generation : Nat
  offset : Nat
  deriving DecidableEq

def authorized (a : Allocation) (p : Pointer) (width : Nat) : Prop :=
  a.live = true ∧ p.identity = a.identity ∧ p.generation = a.generation ∧
  p.offset + width ≤ a.bytes

instance (a : Allocation) (p : Pointer) (width : Nat) :
    Decidable (authorized a p width) := inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))

def access (a : Allocation) (p : Pointer) (width : Nat) : Option Nat :=
  if authorized a p width then some p.offset else none

def retire (a : Allocation) : Allocation :=
  { a with live := false, generation := a.generation + 1 }

def reuse (a : Allocation) (bytes : Nat) : Allocation :=
  { a with live := true, generation := a.generation + 1, bytes := bytes }

theorem access_authorized {a : Allocation} {p : Pointer} {width offset : Nat}
    (h : access a p width = some offset) : authorized a p width := by
  unfold access at h
  split at h
  · assumption
  · contradiction

theorem access_within_allocation {a : Allocation} {p : Pointer} {width offset : Nat}
    (h : access a p width = some offset) : p.offset + width ≤ a.bytes :=
  (access_authorized h).2.2.2

theorem other_identity_rejected (a : Allocation) (p : Pointer) (width : Nat)
    (h : p.identity ≠ a.identity) : access a p width = none := by
  simp [access, authorized, h]

theorem stale_generation_rejected (a : Allocation) (p : Pointer) (width : Nat)
    (h : p.generation ≠ a.generation) : access a p width = none := by
  simp [access, authorized, h]

theorem retired_allocation_rejected (a : Allocation) (p : Pointer) (width : Nat) :
    access (retire a) p width = none := by
  simp [access, authorized, retire]

theorem reuse_does_not_revive_old_pointer (a : Allocation) (p : Pointer)
    (width bytes : Nat) (h : p.generation = a.generation) :
    access (reuse a bytes) p width = none := by
  simp [access, authorized, reuse, h]

theorem one_past_cannot_read (a : Allocation) (p : Pointer) (width : Nat)
    (atEnd : p.offset = a.bytes) (nonempty : 0 < width) :
    access a p width = none := by
  have h : ¬ p.offset + width ≤ a.bytes := by omega
  simp [access, authorized, h]

/- A derived view can only narrow its origin's range and permission. Generation
is copied from a previously authorized view, never reconstructed from an address. -/

structure View where
  pointer : Pointer
  length : Nat
  writable : Bool
  deriving DecidableEq

def viewValid (a : Allocation) (v : View) : Prop :=
  authorized a v.pointer v.length

def narrow (v : View) (offset length : Nat) (write : Bool) : Option View :=
  if offset + length ≤ v.length ∧ (write = true → v.writable = true) then
    some { pointer := { v.pointer with offset := v.pointer.offset + offset },
           length := length, writable := write }
  else none

theorem narrowing_preserves_origin {v w : View} {offset length : Nat} {write : Bool}
    (h : narrow v offset length write = some w) :
    w.pointer.identity = v.pointer.identity ∧ w.pointer.generation = v.pointer.generation := by
  unfold narrow at h
  split at h
  · simp only [Option.some.injEq] at h
    subst w
    exact ⟨rfl, rfl⟩
  · contradiction

theorem narrowing_preserves_authority {a : Allocation} {v w : View}
    {offset length : Nat} {write : Bool}
    (valid : viewValid a v) (h : narrow v offset length write = some w) : viewValid a w := by
  unfold narrow at h
  split at h
  · simp only [Option.some.injEq] at h
    subst w
    simp only [viewValid, authorized] at *
    rcases valid with ⟨live, identity, generation, bounds⟩
    exact ⟨live, identity, generation, by omega⟩
  · contradiction

theorem narrowing_cannot_gain_write {v w : View} {offset length : Nat} {write : Bool}
    (h : narrow v offset length write = some w) (readOnly : v.writable = false) :
    w.writable = false := by
  unfold narrow at h
  split at h
  · simp only [Option.some.injEq] at h
    subst w
    cases write <;> simp_all
  · contradiction

def disjoint (a b : View) : Prop :=
  a.pointer.identity ≠ b.pointer.identity ∨
  a.pointer.generation ≠ b.pointer.generation ∨
  a.pointer.offset + a.length ≤ b.pointer.offset ∨
  b.pointer.offset + b.length ≤ a.pointer.offset

def compatible (a b : View) : Prop :=
  (a.writable = false ∧ b.writable = false) ∨ disjoint a b

instance (a b : View) : Decidable (compatible a b) :=
  inferInstanceAs (Decidable ((_ ∧ _) ∨ (_ ∨ _ ∨ _ ∨ _)))

theorem compatible_symmetric {a b : View} (h : compatible a b) : compatible b a := by
  simp only [compatible, disjoint] at *
  rcases h with h | h
  · exact Or.inl ⟨h.2, h.1⟩
  · right
    rcases h with id | generation | left | right
    · exact Or.inl (Ne.symm id)
    · exact Or.inr (Or.inl (Ne.symm generation))
    · exact Or.inr (Or.inr (Or.inr left))
    · exact Or.inr (Or.inr (Or.inl right))

def admit (existing : List View) (candidate : View) : Option (List View) :=
  if ∀ previous ∈ existing, compatible candidate previous then
    some (candidate :: existing)
  else none

theorem admission_preserves_exclusivity {existing accepted : List View} {candidate : View}
    (valid : existing.Pairwise compatible)
    (h : admit existing candidate = some accepted) : accepted.Pairwise compatible := by
  unfold admit at h
  split at h
  · simp only [Option.some.injEq] at h
    subst accepted
    exact List.pairwise_cons.mpr ⟨by assumption, valid⟩
  · contradiction

theorem overlapping_mutable_view_rejected (existing candidate : View)
    (write : candidate.writable = true) (overlap : ¬ disjoint candidate existing) :
    admit [existing] candidate = none := by
  simp [admit, compatible, write, overlap]

end Hepta.Memory

/- A small, extrinsically typed source core with actual small-step semantics.
Progress includes a value alternative and preservation quantifies over every
transition. These theorems concern closed expressions, not the production AST. -/

namespace Hepta.TypedCore

inductive Ty where
  | word | boolean
  deriving DecidableEq

inductive Expr where
  | word (value : BitVec 64)
  | boolean (value : Bool)
  | add (left right : Expr)
  | equal (left right : Expr)
  | choose (condition yes no : Expr)
  deriving DecidableEq

inductive Typed : Expr → Ty → Prop where
  | word (n) : Typed (.word n) .word
  | boolean (b) : Typed (.boolean b) .boolean
  | add : Typed l .word → Typed r .word → Typed (.add l r) .word
  | equal : Typed l .word → Typed r .word → Typed (.equal l r) .boolean
  | choose : Typed c .boolean → Typed y t → Typed n t → Typed (.choose c y n) t

inductive Value : Expr → Prop where
  | word (n) : Value (.word n)
  | boolean (b) : Value (.boolean b)

inductive Step : Expr → Expr → Prop where
  | addLeft : Step l l' → Step (.add l r) (.add l' r)
  | addRight : Step r r' → Step (.add (.word n) r) (.add (.word n) r')
  | add (a b) : Step (.add (.word a) (.word b)) (.word (a + b))
  | equalLeft : Step l l' → Step (.equal l r) (.equal l' r)
  | equalRight : Step r r' → Step (.equal (.word n) r) (.equal (.word n) r')
  | equal (a b) : Step (.equal (.word a) (.word b)) (.boolean (a == b))
  | condition : Step c c' → Step (.choose c y n) (.choose c' y n)
  | yes (y n) : Step (.choose (.boolean true) y n) y
  | no (y n) : Step (.choose (.boolean false) y n) n

theorem word_canonical {e : Expr} (typed : Typed e .word) (value : Value e) :
    ∃ n, e = .word n := by
  cases value with
  | word n => exact ⟨n, rfl⟩
  | boolean b => cases typed

theorem bool_canonical {e : Expr} (typed : Typed e .boolean) (value : Value e) :
    ∃ b, e = .boolean b := by
  cases value with
  | boolean b => exact ⟨b, rfl⟩
  | word n => cases typed

theorem preservation {e e' : Expr} {t : Ty} (step : Step e e')
    (typed : Typed e t) : Typed e' t := by
  induction step generalizing t with
  | addLeft step ih => cases typed with | add l r => exact .add (ih l) r
  | addRight step ih => cases typed with | add l r => exact .add l (ih r)
  | add a b => cases typed; exact .word _
  | equalLeft step ih => cases typed with | equal l r => exact .equal (ih l) r
  | equalRight step ih => cases typed with | equal l r => exact .equal l (ih r)
  | equal a b => cases typed; exact .boolean _
  | condition step ih => cases typed with | choose c y n => exact .choose (ih c) y n
  | yes y n => cases typed with | choose c y n => exact y
  | no y n => cases typed with | choose c y n => exact n

theorem progress {e : Expr} {t : Ty} (typed : Typed e t) :
    Value e ∨ ∃ e', Step e e' := by
  induction typed with
  | word n => exact .inl (.word n)
  | boolean b => exact .inl (.boolean b)
  | @add l r tl tr il ir =>
    rcases il with vl | ⟨l', sl⟩
    · obtain ⟨a, rfl⟩ := word_canonical tl vl
      rcases ir with vr | ⟨r', sr⟩
      · obtain ⟨b, rfl⟩ := word_canonical tr vr
        exact .inr ⟨_, .add a b⟩
      · exact .inr ⟨_, .addRight sr⟩
    · exact .inr ⟨_, .addLeft sl⟩
  | @equal l r tl tr il ir =>
    rcases il with vl | ⟨l', sl⟩
    · obtain ⟨a, rfl⟩ := word_canonical tl vl
      rcases ir with vr | ⟨r', sr⟩
      · obtain ⟨b, rfl⟩ := word_canonical tr vr
        exact .inr ⟨_, .equal a b⟩
      · exact .inr ⟨_, .equalRight sr⟩
    · exact .inr ⟨_, .equalLeft sl⟩
  | @choose c y n t tc ty tn ic iy inn =>
    rcases ic with vc | ⟨c', sc⟩
    · obtain ⟨b, rfl⟩ := bool_canonical tc vc
      cases b
      · exact .inr ⟨_, .no _ _⟩
      · exact .inr ⟨_, .yes _ _⟩
    · exact .inr ⟨_, .condition sc⟩

inductive Steps : Expr → Expr → Prop where
  | refl (e) : Steps e e
  | next : Steps e m → Step m n → Steps e n

theorem trace_preservation {e e' : Expr} {t : Ty}
    (typed : Typed e t) (steps : Steps e e') : Typed e' t := by
  induction steps with
  | refl => exact typed
  | next before step ih => exact preservation step ih

theorem well_typed_cannot_get_stuck {e e' : Expr} {t : Ty}
    (typed : Typed e t) (steps : Steps e e') : Value e' ∨ ∃ e'', Step e' e'' :=
  progress (trace_preservation typed steps)

end Hepta.TypedCore
