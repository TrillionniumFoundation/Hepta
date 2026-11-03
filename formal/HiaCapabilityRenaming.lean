/-
Sequential Core capability-flow specification. Names are mathematical
naturals; kinds and origins are uninterpreted tags. This proves facts for
ALL finite capability lists and injective maps, without an execution-length
bound. It is not a proof of every instruction, Python, LLVM, FFI, or hardware.
Projection may forget only external capabilities and must keep the selected
graph closed. The trace theorems below compose these edge rules for every
finite trace; they do not model the intervening instructions in a CFG block.
-/
import Lean.Elab.Tactic.Omega

namespace HiaCapabilityRenaming

structure Capability where
  name : Nat
  root : Nat
  parent : Option Nat
  kind : Nat
  external : Bool
  origin : Option Nat
  deriving DecidableEq

def Injective (f : Nat → Nat) : Prop := ∀ a b, f a = f b → a = b

def rename (f : Nat → Nat) (c : Capability) : Capability :=
  { name := f c.name, root := f c.root, parent := c.parent.map f,
    kind := c.kind, external := c.external, origin := c.origin }

def ChildOf (child parent : Capability) : Prop := child.parent = some parent.name

def ExclusiveAlias (mutableKind : Nat) (a b : Capability) : Prop :=
  a.name ≠ b.name ∧ a.root = b.root ∧ (a.kind = mutableKind ∨ b.kind = mutableKind)

def Closed (caps : List Capability) : Prop :=
  ∀ c ∈ caps, (∃ root ∈ caps, root.name = c.root) ∧
    (∀ p, c.parent = some p → ∃ parent ∈ caps, parent.name = p)

theorem name_preserved (f : Nat → Nat) (c : Capability) :
    (rename f c).name = f c.name := rfl

theorem kind_preserved (f : Nat → Nat) (c : Capability) :
    (rename f c).kind = c.kind := rfl

theorem external_preserved (f : Nat → Nat) (c : Capability) :
    (rename f c).external = c.external := rfl

theorem origin_preserved (f : Nat → Nat) (c : Capability) :
    (rename f c).origin = c.origin := rfl

theorem name_equal_iff (f : Nat → Nat) (inj : Injective f) (a b : Capability) :
    (rename f a).name = (rename f b).name ↔ a.name = b.name := by
  constructor
  · exact inj a.name b.name
  · intro h; exact congrArg f h

theorem root_equal_iff (f : Nat → Nat) (inj : Injective f) (a b : Capability) :
    (rename f a).root = (rename f b).root ↔ a.root = b.root := by
  constructor
  · exact inj a.root b.root
  · intro h; exact congrArg f h

theorem parent_map_iff (f : Nat → Nat) (inj : Injective f) (p : Option Nat) (n : Nat) :
    p.map f = some (f n) ↔ p = some n := by
  cases p with
  | none => simp
  | some p =>
      constructor
      · intro h; exact congrArg some (inj p n (Option.some.inj h))
      · intro h; cases h; rfl

theorem child_of_iff (f : Nat → Nat) (inj : Injective f) (a b : Capability) :
    ChildOf (rename f a) (rename f b) ↔ ChildOf a b := by
  exact parent_map_iff f inj a.parent b.name

theorem exclusive_alias_iff (f : Nat → Nat) (inj : Injective f)
    (mutableKind : Nat) (a b : Capability) :
    ExclusiveAlias mutableKind (rename f a) (rename f b) ↔
      ExclusiveAlias mutableKind a b := by
  simp only [ExclusiveAlias, ne_eq, name_equal_iff f inj,
             root_equal_iff f inj, kind_preserved]

theorem suspended_iff (f : Nat → Nat) (inj : Injective f)
    (caps : List Capability) (c : Capability) :
    (∃ child ∈ caps.map (rename f), ChildOf child (rename f c)) ↔
      (∃ child ∈ caps, ChildOf child c) := by
  constructor
  · rintro ⟨child, member, relation⟩
    obtain ⟨old, oldMember, rfl⟩ := List.mem_map.mp member
    exact ⟨old, oldMember, (child_of_iff f inj old c).mp relation⟩
  · rintro ⟨child, member, relation⟩
    exact ⟨rename f child, List.mem_map.mpr ⟨child, member, rfl⟩,
      (child_of_iff f inj child c).mpr relation⟩

theorem closed_preserved (f : Nat → Nat) (caps : List Capability)
    (closed : Closed caps) : Closed (caps.map (rename f)) := by
  intro c member
  obtain ⟨old, oldMember, rfl⟩ := List.mem_map.mp member
  obtain ⟨rootExists, parentExists⟩ := closed old oldMember
  obtain ⟨root, rootMember, rootName⟩ := rootExists
  constructor
  · exact ⟨rename f root, List.mem_map.mpr ⟨root, rootMember, rfl⟩,
      congrArg f rootName⟩
  · intro p relation
    cases hp : old.parent with
    | none => simp [rename, hp] at relation
    | some oldParent =>
        have mapped : f oldParent = p := by simpa [rename, hp] using relation
        obtain ⟨parent, parentMember, parentName⟩ := parentExists oldParent hp
        exact ⟨rename f parent, List.mem_map.mpr ⟨parent, parentMember, rfl⟩,
          (congrArg f parentName).trans mapped⟩

theorem number_preserved (f : Nat → Nat) (caps : List Capability) :
    (caps.map (rename f)).length = caps.length := by simp

theorem rename_composes (f g : Nat → Nat) (c : Capability) :
    rename g (rename f c) = rename (fun n => g (f n)) c := by
  cases c with
  | mk name root parent kind external origin =>
      cases parent <;> rfl

theorem identity_rename (c : Capability) : rename (fun n => n) c = c := by
  cases c with
  | mk name root parent kind external origin =>
      cases parent <;> rfl

/- The executable helper selects a subset before renaming. Selection is a
filter, so it cannot invent or duplicate capabilities. The explicit retention
premise is exactly the helper's rule for local owners and local loans. -/

def project (keep : Nat → Bool) (caps : List Capability) : List Capability :=
  caps.filter (fun c => keep c.name)

def AdmissibleProjection (caps : List Capability) (keep : Nat → Bool) : Prop :=
  (∀ c ∈ caps, c.external = false → keep c.name = true) ∧ Closed (project keep caps)

def localInventory : List Capability → List (Nat × Option Nat)
  | [] => []
  | c :: rest =>
      if c.external then localInventory rest else (c.kind, c.origin) :: localInventory rest

theorem projected_member (caps : List Capability) (keep : Nat → Bool) (c : Capability) :
    c ∈ project keep caps ↔ c ∈ caps ∧ keep c.name = true := by
  simp [project]

theorem local_retained (caps : List Capability) (keep : Nat → Bool)
    (admitted : AdmissibleProjection caps keep) (c : Capability)
    (member : c ∈ caps) (localCap : c.external = false) : c ∈ project keep caps := by
  exact (projected_member caps keep c).mpr ⟨member, admitted.1 c member localCap⟩

theorem only_external_forgotten (caps : List Capability) (keep : Nat → Bool)
    (admitted : AdmissibleProjection caps keep) (c : Capability)
    (member : c ∈ caps) (forgotten : c ∉ project keep caps) : c.external = true := by
  cases external : c.external with
  | false => exact False.elim (forgotten (local_retained caps keep admitted c member external))
  | true => rfl

theorem local_inventory_projection (caps : List Capability) (keep : Nat → Bool)
    (retained : ∀ c ∈ caps, c.external = false → keep c.name = true) :
    localInventory (project keep caps) = localInventory caps := by
  induction caps with
  | nil => rfl
  | cons c rest ih =>
      have restRetained : ∀ x ∈ rest, x.external = false → keep x.name = true := by
        intro x member external
        exact retained x (List.mem_cons_of_mem c member) external
      have tail := ih restRetained
      cases external : c.external with
      | false =>
          have kept := retained c (by simp) external
          simp [project, localInventory, external, kept] at tail ⊢
          exact tail
      | true =>
          cases kept : keep c.name <;> simp [project, localInventory, external, kept] at tail ⊢
          all_goals exact tail

theorem local_inventory_rename (caps : List Capability) (f : Nat → Nat) :
    localInventory (caps.map (rename f)) = localInventory caps := by
  induction caps with
  | nil => rfl
  | cons c rest ih => simp [localInventory, rename, ih]

/- Parent ranks are witnesses for strict descent, not runtime addresses or
integer counters. Their existence excludes every positive parent cycle. -/

def ParentRanks (caps : List Capability) (rank : Nat → Nat) : Prop :=
  ∀ child ∈ caps, ∀ parent ∈ caps, ChildOf child parent → rank parent.name < rank child.name

def Ranked (caps : List Capability) : Prop := ∃ rank, ParentRanks caps rank

inductive ParentPath (caps : List Capability) : Nat → Nat → Prop where
  | edge {child parent} : child ∈ caps → parent ∈ caps → ChildOf child parent →
      ParentPath caps child.name parent.name
  | trans {a b c} : ParentPath caps a b → ParentPath caps b c → ParentPath caps a c

theorem parent_path_descends (caps : List Capability) (rank : Nat → Nat)
    (ranked : ParentRanks caps rank) {a b : Nat} (path : ParentPath caps a b) :
    rank b < rank a := by
  induction path with
  | edge childMember parentMember relation => exact ranked _ childMember _ parentMember relation
  | trans _ _ left right => exact Nat.lt_trans right left

theorem ranked_no_parent_cycle (caps : List Capability) (ranked : Ranked caps) (name : Nat) :
    ¬ ParentPath caps name name := by
  intro path
  obtain ⟨rank, ordered⟩ := ranked
  exact (Nat.lt_irrefl (rank name)) (parent_path_descends caps rank ordered path)

theorem ranked_projection (caps : List Capability) (keep : Nat → Bool)
    (ranked : Ranked caps) : Ranked (project keep caps) := by
  obtain ⟨rank, ordered⟩ := ranked
  refine ⟨rank, ?_⟩
  intro child childMember parent parentMember relation
  exact ordered child ((projected_member caps keep child).mp childMember).1
    parent ((projected_member caps keep parent).mp parentMember).1 relation

noncomputable def transportedRank (f rank : Nat → Nat) (name : Nat) : Nat := by
  classical
  exact if witness : ∃ before, f before = name then rank (Classical.choose witness) else 0

theorem transported_rank_at (f rank : Nat → Nat) (inj : Injective f) (name : Nat) :
    transportedRank f rank (f name) = rank name := by
  unfold transportedRank
  split
  next witness =>
    have same : Classical.choose witness = name := inj _ _ (Classical.choose_spec witness)
    rw [same]
  next absent => exact False.elim (absent ⟨name, rfl⟩)

theorem ranked_rename (caps : List Capability) (f : Nat → Nat)
    (inj : Injective f) (ranked : Ranked caps) : Ranked (caps.map (rename f)) := by
  obtain ⟨rank, ordered⟩ := ranked
  refine ⟨transportedRank f rank, ?_⟩
  intro child childMember parent parentMember relation
  obtain ⟨oldChild, oldChildMember, rfl⟩ := List.mem_map.mp childMember
  obtain ⟨oldParent, oldParentMember, rfl⟩ := List.mem_map.mp parentMember
  have oldRelation := (child_of_iff f inj oldChild oldParent).mp relation
  simpa only [name_preserved, transported_rank_at f rank inj] using
    ordered oldChild oldChildMember oldParent oldParentMember oldRelation

def Transfer (before after : List Capability) : Prop :=
  ∃ keep f, AdmissibleProjection before keep ∧ Injective f ∧
    after = (project keep before).map (rename f)

theorem transfer_closed {before after : List Capability} (step : Transfer before after) :
    Closed after := by
  obtain ⟨keep, f, admitted, _, rfl⟩ := step
  exact closed_preserved f (project keep before) admitted.2

theorem transfer_local_inventory {before after : List Capability} (step : Transfer before after) :
    localInventory after = localInventory before := by
  obtain ⟨keep, f, admitted, _, rfl⟩ := step
  rw [local_inventory_rename, local_inventory_projection before keep admitted.1]

theorem transfer_ranked {before after : List Capability} (step : Transfer before after)
    (ranked : Ranked before) : Ranked after := by
  obtain ⟨keep, f, _, inj, rfl⟩ := step
  exact ranked_rename (project keep before) f inj (ranked_projection before keep ranked)

inductive EdgeTrace : List Capability → List Capability → Prop where
  | refl (caps) : EdgeTrace caps caps
  | next {before middle after} : EdgeTrace before middle → Transfer middle after →
      EdgeTrace before after

theorem trace_local_inventory {before after : List Capability} (trace : EdgeTrace before after) :
    localInventory after = localInventory before := by
  induction trace with
  | refl => rfl
  | next _ step ih => exact (transfer_local_inventory step).trans ih

theorem trace_closed {before after : List Capability} (trace : EdgeTrace before after)
    (closed : Closed before) : Closed after := by
  cases trace with
  | refl => exact closed
  | next _ step => exact transfer_closed step

theorem trace_ranked {before after : List Capability} (trace : EdgeTrace before after)
    (ranked : Ranked before) : Ranked after := by
  induction trace with
  | refl => exact ranked
  | next _ step ih => exact transfer_ranked step ih

theorem trace_no_parent_cycle {before after : List Capability} (trace : EdgeTrace before after)
    (ranked : Ranked before) (name : Nat) : ¬ ParentPath after name name :=
  ranked_no_parent_cycle after (trace_ranked trace ranked) name

end HiaCapabilityRenaming
