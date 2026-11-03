/-
Structural preservation for allocation, borrowing and release. This model
concerns capability graphs, not heap execution or the production checker.
It does not prove alias exclusivity, FFI, calls or concurrent memory safety.
-/
import HiaCapabilityRenaming

namespace HiaCapabilityLifecycle
open HiaCapabilityRenaming

def Fresh (caps : List Capability) (name : Nat) : Prop :=
  ∀ c ∈ caps, c.name ≠ name

def Unique (caps : List Capability) : Prop := (caps.map Capability.name).Nodup

def owner (name kind : Nat) : Capability :=
  ⟨name, name, none, kind, false, none⟩

def loan (source : Capability) (name kind : Nat) : Capability :=
  ⟨name, source.root, some source.name, kind, false, source.origin⟩

def erase (name : Nat) (caps : List Capability) : List Capability :=
  caps.filter (fun c => c.name != name)

def Unreferenced (caps : List Capability) (name : Nat) : Prop :=
  ∀ c ∈ caps, c.name ≠ name → c.root ≠ name ∧ c.parent ≠ some name

def extendRank (rank : Nat → Nat) (name value : Nat) (n : Nat) : Nat :=
  if n = name then value else rank n

theorem fresh_not_member (caps : List Capability) (name : Nat)
    (fresh : Fresh caps name) (c : Capability) (same : c.name = name) : c ∉ caps := by
  intro member
  exact fresh c member same

theorem fresh_parent_absent (caps : List Capability) (name : Nat)
    (closed : Closed caps) (fresh : Fresh caps name) (c : Capability) (member : c ∈ caps) :
    c.parent ≠ some name := by
  intro relation
  obtain ⟨parent, parentMember, parentName⟩ := (closed c member).2 name relation
  exact fresh parent parentMember parentName

theorem extend_rank_old (caps : List Capability) (rank : Nat → Nat) (name value : Nat)
    (fresh : Fresh caps name) (c : Capability) (member : c ∈ caps) :
    extendRank rank name value c.name = rank c.name := by
  simp [extendRank, fresh c member]

theorem fresh_cons_unique (caps : List Capability) (c : Capability)
    (unique : Unique caps) (fresh : Fresh caps c.name) : Unique (c :: caps) := by
  simp only [Unique, List.map_cons, List.nodup_cons]
  refine ⟨?_, unique⟩
  intro member
  obtain ⟨old, oldMember, same⟩ := List.mem_map.mp member
  exact fresh old oldMember same

theorem owner_closed (caps : List Capability) (name kind : Nat)
    (closed : Closed caps) : Closed (owner name kind :: caps) := by
  intro c member
  rcases List.mem_cons.mp member with same | oldMember
  · subst c
    constructor
    · exact ⟨owner name kind, by simp, rfl⟩
    · intro p relation
      simp [owner] at relation
  · obtain ⟨rootExists, parentExists⟩ := closed c oldMember
    constructor
    · obtain ⟨root, rootMember, rootName⟩ := rootExists
      exact ⟨root, List.mem_cons_of_mem _ rootMember, rootName⟩
    · intro p relation
      obtain ⟨parent, parentMember, parentName⟩ := parentExists p relation
      exact ⟨parent, List.mem_cons_of_mem _ parentMember, parentName⟩

theorem loan_closed (caps : List Capability) (source : Capability) (name kind : Nat)
    (closed : Closed caps) (sourceMember : source ∈ caps) :
    Closed (loan source name kind :: caps) := by
  intro c member
  rcases List.mem_cons.mp member with same | oldMember
  · subst c
    constructor
    · obtain ⟨root, rootMember, rootName⟩ := (closed source sourceMember).1
      exact ⟨root, List.mem_cons_of_mem _ rootMember, rootName⟩
    · intro p relation
      have same : source.name = p := Option.some.inj relation
      exact ⟨source, List.mem_cons_of_mem _ sourceMember, same⟩
  · obtain ⟨rootExists, parentExists⟩ := closed c oldMember
    constructor
    · obtain ⟨root, rootMember, rootName⟩ := rootExists
      exact ⟨root, List.mem_cons_of_mem _ rootMember, rootName⟩
    · intro p relation
      obtain ⟨parent, parentMember, parentName⟩ := parentExists p relation
      exact ⟨parent, List.mem_cons_of_mem _ parentMember, parentName⟩

theorem owner_ranked (caps : List Capability) (name kind : Nat)
    (closed : Closed caps) (fresh : Fresh caps name) (ranked : Ranked caps) :
    Ranked (owner name kind :: caps) := by
  obtain ⟨rank, ordered⟩ := ranked
  refine ⟨extendRank rank name 0, ?_⟩
  intro child childMember parent parentMember relation
  rcases List.mem_cons.mp childMember with childNew | childOld
  · subst child
    simp [ChildOf, owner] at relation
  · rcases List.mem_cons.mp parentMember with parentNew | parentOld
    · subst parent
      exact False.elim (fresh_parent_absent caps name closed fresh child childOld relation)
    · simpa only [extend_rank_old caps rank name 0 fresh child childOld,
                  extend_rank_old caps rank name 0 fresh parent parentOld] using
        ordered child childOld parent parentOld relation

theorem loan_ranked (caps : List Capability) (source : Capability) (name kind : Nat)
    (closed : Closed caps) (fresh : Fresh caps name) (sourceMember : source ∈ caps)
    (ranked : Ranked caps) : Ranked (loan source name kind :: caps) := by
  obtain ⟨rank, ordered⟩ := ranked
  refine ⟨extendRank rank name (rank source.name + 1), ?_⟩
  intro child childMember parent parentMember relation
  rcases List.mem_cons.mp childMember with childNew | childOld
  · subst child
    have same : source.name = parent.name := Option.some.inj relation
    rcases List.mem_cons.mp parentMember with parentNew | parentOld
    · subst parent
      exact False.elim (fresh source sourceMember same)
    · simp only [loan, extendRank, if_pos rfl]
      rw [← same]
      simp [extendRank, fresh source sourceMember]
  · rcases List.mem_cons.mp parentMember with parentNew | parentOld
    · subst parent
      exact False.elim (fresh_parent_absent caps name closed fresh child childOld relation)
    · simpa only [extend_rank_old caps rank name (rank source.name + 1) fresh child childOld,
                  extend_rank_old caps rank name (rank source.name + 1) fresh parent parentOld] using
        ordered child childOld parent parentOld relation

theorem erased_member (caps : List Capability) (name : Nat) (c : Capability) :
    c ∈ erase name caps ↔ c ∈ caps ∧ c.name ≠ name := by
  simp [erase]

theorem erase_closed (caps : List Capability) (name : Nat)
    (closed : Closed caps) (free : Unreferenced caps name) : Closed (erase name caps) := by
  intro c member
  obtain ⟨oldMember, notName⟩ := (erased_member caps name c).mp member
  obtain ⟨rootExists, parentExists⟩ := closed c oldMember
  constructor
  · obtain ⟨root, rootMember, rootName⟩ := rootExists
    have retained : root.name ≠ name := by
      intro same
      exact (free c oldMember notName).1 (rootName.symm.trans same)
    exact ⟨root, (erased_member caps name root).mpr ⟨rootMember, retained⟩, rootName⟩
  · intro p relation
    obtain ⟨parent, parentMember, parentName⟩ := parentExists p relation
    have retained : parent.name ≠ name := by
      intro same
      have pName : p = name := parentName.symm.trans same
      exact (free c oldMember notName).2 (relation.trans (congrArg some pName))
    exact ⟨parent, (erased_member caps name parent).mpr ⟨parentMember, retained⟩, parentName⟩

theorem erase_ranked (caps : List Capability) (name : Nat) (ranked : Ranked caps) :
    Ranked (erase name caps) := by
  obtain ⟨rank, ordered⟩ := ranked
  refine ⟨rank, ?_⟩
  intro child childMember parent parentMember relation
  exact ordered child ((erased_member caps name child).mp childMember).1
    parent ((erased_member caps name parent).mp parentMember).1 relation

theorem erase_unique (caps : List Capability) (name : Nat) (unique : Unique caps) :
    Unique (erase name caps) := by
  have subset : (erase name caps).Sublist caps := List.filter_sublist
  exact (subset.map Capability.name).nodup unique

/- This is a closed structural slice, not the complete borrow checker.
The borrow rules retain root/origin and prohibit shared-to-mutable escalation.
The separate production checker enforces conflicting alias exclusions. -/
inductive Step : List Capability → List Capability → Prop where
  | allocate {caps name kind} : Fresh caps name → (kind = 0 ∨ kind = 1) →
      Step caps (owner name kind :: caps)
  | borrowRead {caps source name} : source ∈ caps → Fresh caps name →
      (source.kind = 0 ∨ source.kind = 2 ∨ source.kind = 3) →
      Step caps (loan source name 2 :: caps)
  | borrowMut {caps source name} : source ∈ caps → Fresh caps name →
      (source.kind = 0 ∨ source.kind = 3) →
      Step caps (loan source name 3 :: caps)
  | endLoan {caps c} : c ∈ caps → c.external = false →
      (c.kind = 2 ∨ c.kind = 3) → Unreferenced caps c.name →
      Step caps (erase c.name caps)
  | dropOwner {caps c} : c ∈ caps → c.external = false →
      (c.kind = 0 ∨ c.kind = 1) → c.root = c.name → c.parent = none →
      Unreferenced caps c.name → Step caps (erase c.name caps)

theorem step_closed {before after : List Capability} (step : Step before after)
    (closed : Closed before) : Closed after := by
  cases step with
  | allocate fresh kind => exact owner_closed _ _ _ closed
  | borrowRead sourceMember fresh kind => exact loan_closed _ _ _ _ closed sourceMember
  | borrowMut sourceMember fresh kind => exact loan_closed _ _ _ _ closed sourceMember
  | endLoan member localCap kind free => exact erase_closed _ _ closed free
  | dropOwner member localCap kind root parent free => exact erase_closed _ _ closed free

theorem step_ranked {before after : List Capability} (step : Step before after)
    (closed : Closed before) (ranked : Ranked before) : Ranked after := by
  cases step with
  | allocate fresh kind => exact owner_ranked _ _ _ closed fresh ranked
  | borrowRead sourceMember fresh kind => exact loan_ranked _ _ _ _ closed fresh sourceMember ranked
  | borrowMut sourceMember fresh kind => exact loan_ranked _ _ _ _ closed fresh sourceMember ranked
  | endLoan member localCap kind free => exact erase_ranked _ _ ranked
  | dropOwner member localCap kind root parent free => exact erase_ranked _ _ ranked

theorem step_unique {before after : List Capability} (step : Step before after)
    (unique : Unique before) : Unique after := by
  cases step with
  | allocate fresh kind => exact fresh_cons_unique _ _ unique fresh
  | borrowRead sourceMember fresh kind => exact fresh_cons_unique _ _ unique fresh
  | borrowMut sourceMember fresh kind => exact fresh_cons_unique _ _ unique fresh
  | endLoan member localCap kind free => exact erase_unique _ _ unique
  | dropOwner member localCap kind root parent free => exact erase_unique _ _ unique

theorem unique_projection (caps : List Capability) (keep : Nat → Bool)
    (unique : Unique caps) : Unique (project keep caps) := by
  have subset : (project keep caps).Sublist caps := List.filter_sublist
  exact (subset.map Capability.name).nodup unique

theorem unique_rename (caps : List Capability) (f : Nat → Nat) (inj : Injective f)
    (unique : Unique caps) : Unique (caps.map (rename f)) := by
  induction caps with
  | nil => simp [Unique]
  | cons c rest ih =>
      have old : c.name ∉ rest.map Capability.name ∧ Unique rest := by
        simpa only [Unique, List.map_cons, List.nodup_cons] using unique
      simp only [List.map_cons, Unique, List.nodup_cons]
      refine ⟨?_, ih old.2⟩
      intro member
      obtain ⟨renamed, renamedMember, same⟩ := List.mem_map.mp member
      obtain ⟨original, originalMember, rfl⟩ := List.mem_map.mp renamedMember
      have originalName : original.name = c.name := inj _ _ same
      exact old.1 (List.mem_map.mpr ⟨original, originalMember, originalName⟩)

theorem transfer_unique {before after : List Capability} (step : Transfer before after)
    (unique : Unique before) : Unique after := by
  obtain ⟨keep, f, admitted, inj, rfl⟩ := step
  exact unique_rename _ f inj (unique_projection before keep unique)

inductive Trace : List Capability → List Capability → Prop where
  | refl (caps) : Trace caps caps
  | instruction {before middle after} : Trace before middle → Step middle after → Trace before after
  | edge {before middle after} : Trace before middle → Transfer middle after → Trace before after

theorem trace_closed {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) : Closed after := by
  induction trace with
  | refl => exact closed
  | instruction _ step ih => exact step_closed step ih
  | edge _ step ih => exact transfer_closed step

theorem trace_ranked {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) (ranked : Ranked before) : Ranked after := by
  induction trace with
  | refl => exact ranked
  | instruction earlier step ih => exact step_ranked step (trace_closed earlier closed) ih
  | edge _ step ih => exact transfer_ranked step ih

theorem trace_unique {before after : List Capability} (trace : Trace before after)
    (unique : Unique before) : Unique after := by
  induction trace with
  | refl => exact unique
  | instruction _ step ih => exact step_unique step ih
  | edge _ step ih => exact transfer_unique step ih

theorem trace_no_parent_cycle {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) (ranked : Ranked before) (name : Nat) :
    ¬ ParentPath after name name :=
  ranked_no_parent_cycle after (trace_ranked trace closed ranked) name

end HiaCapabilityLifecycle
