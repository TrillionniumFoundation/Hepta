/-
Sequential Core capability-flow specification. Names are mathematical
naturals; kinds and origins are uninterpreted tags. This proves facts for
ALL finite capability lists and injective maps, without an execution-length
bound. It is not a proof of every instruction, Python, LLVM, FFI, or hardware.
The list is the selected closed graph carried by an edge. Forgetting unused
external capabilities before selection is not modeled by these theorems.
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

end HiaCapabilityRenaming
