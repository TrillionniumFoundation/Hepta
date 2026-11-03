/-
Borrow compatibility and suspended-parent access for a selected capability
slice. Guards inspect the before state. This extends, rather than changes,
the structural Lifecycle relation. No heap, source, LLVM or FFI refinement
is claimed. Concrete checker observations are separate finite witnesses.
-/
import HiaCapabilityLifecycle

namespace HiaCapabilityBorrow
open HiaCapabilityRenaming HiaCapabilityLifecycle

def Ancestor (caps : List Capability) (child parent : Nat) : Prop :=
  child = parent ∨ ParentPath caps child parent

def Comparable (caps : List Capability) (a b : Nat) : Prop :=
  a = b ∨ ParentPath caps a b ∨ ParentPath caps b a

def Compatible (caps : List Capability) : Prop :=
  ∀ a ∈ caps, ∀ b ∈ caps, a.root = b.root →
    (a.kind = 3 ∨ b.kind = 3) → Comparable caps a.name b.name

/- Same-root capabilities outside the source's ancestor chain prohibit a
mutable borrow; a shared borrow excludes mutable capabilities there. -/
def BorrowGuard (caps : List Capability) (source : Capability) (kind : Nat) : Prop :=
  ∀ other ∈ caps, other.root = source.root →
    (kind = 3 ∨ other.kind = 3) → Ancestor caps source.name other.name

def Childless (caps : List Capability) (name : Nat) : Prop :=
  ∀ child ∈ caps, child.parent ≠ some name

def Access (caps : List Capability) (c : Capability) (write : Bool) : Prop :=
  c ∈ caps ∧ (if write then c.kind = 3 else c.kind = 2 ∨ c.kind = 3) ∧
    Childless caps c.name

theorem unique_same_name (caps : List Capability) (unique : Unique caps)
    (a b : Capability) (ha : a ∈ caps) (hb : b ∈ caps) (same : a.name = b.name) : a = b := by
  induction caps with
  | nil => simp at ha
  | cons c rest ih =>
      have nodup : c.name ∉ rest.map Capability.name ∧ Unique rest := by
        simpa only [Unique, List.map_cons, List.nodup_cons] using unique
      rcases List.mem_cons.mp ha with aHead | aTail
      · rcases List.mem_cons.mp hb with bHead | bTail
        · exact aHead.trans bHead.symm
        · exact False.elim (nodup.1 (List.mem_map.mpr
            ⟨b, bTail, same.symm.trans (congrArg Capability.name aHead)⟩))
      · rcases List.mem_cons.mp hb with bHead | bTail
        · exact False.elim (nodup.1 (List.mem_map.mpr
            ⟨a, aTail, same.trans (congrArg Capability.name bHead)⟩))
        · exact ih nodup.2 aTail bTail

theorem path_mono {before after : List Capability} {a b : Nat}
    (subset : ∀ c ∈ before, c ∈ after) (path : ParentPath before a b) : ParentPath after a b := by
  induction path with
  | edge hc hp relation => exact ParentPath.edge (subset _ hc) (subset _ hp) relation
  | trans _ _ ih₁ ih₂ => exact ParentPath.trans ih₁ ih₂

theorem path_endpoints {caps : List Capability} {a b : Nat} (path : ParentPath caps a b) :
    (∃ child ∈ caps, child.name = a) ∧ (∃ parent ∈ caps, parent.name = b) := by
  induction path with
  | edge hc hp relation => exact ⟨⟨_, hc, rfl⟩, ⟨_, hp, rfl⟩⟩
  | trans _ _ ih₁ ih₂ => exact ⟨ih₁.1, ih₂.2⟩

/- Closed subgraphs retain every ancestor of a retained node. Unique names
are necessary to identify the retained record with the original parent. -/
theorem path_retained {before after : List Capability} {a b : Nat}
    (unique : Unique before) (subset : ∀ c ∈ after, c ∈ before) (closed : Closed after)
    (path : ParentPath before a b) (retained : ∃ c ∈ after, c.name = a) :
    ParentPath after a b := by
  induction path with
  | @edge child parent hc hp relation =>
      obtain ⟨kept, hk, same⟩ := retained
      have equal := unique_same_name before unique kept child (subset _ hk) hc same
      subst kept
      obtain ⟨keptParent, hkp, parentName⟩ := (closed child hk).2 parent.name relation
      have equal := unique_same_name before unique keptParent parent (subset _ hkp) hp parentName
      subst keptParent
      exact ParentPath.edge hk hkp relation
  | trans first second ih₁ ih₂ =>
      have firstKept := ih₁ retained
      exact ParentPath.trans firstKept (ih₂ (path_endpoints firstKept).2)

theorem path_rename {caps : List Capability} {a b : Nat}
    (f : Nat → Nat) (path : ParentPath caps a b) :
    ParentPath (caps.map (rename f)) (f a) (f b) := by
  induction path with
  | @edge child parent hc hp relation =>
      apply ParentPath.edge (child := rename f child) (parent := rename f parent)
      · exact List.mem_map.mpr ⟨child, hc, rfl⟩
      · exact List.mem_map.mpr ⟨parent, hp, rfl⟩
      · simp only [ChildOf, rename]
        exact congrArg (Option.map f) relation
  | trans _ _ ih₁ ih₂ => exact ParentPath.trans ih₁ ih₂

theorem comparable_mono {before after : List Capability} {a b : Nat}
    (subset : ∀ c ∈ before, c ∈ after) (related : Comparable before a b) :
    Comparable after a b := by
  rcases related with same | path | path
  · exact Or.inl same
  · exact Or.inr (Or.inl (path_mono subset path))
  · exact Or.inr (Or.inr (path_mono subset path))

theorem comparable_symm {caps : List Capability} {a b : Nat}
    (related : Comparable caps a b) : Comparable caps b a := by
  rcases related with same | path | path
  · exact Or.inl same.symm
  · exact Or.inr (Or.inr path)
  · exact Or.inr (Or.inl path)

theorem compatible_owner (caps : List Capability) (name kind : Nat)
    (closed : Closed caps) (fresh : Fresh caps name) (compatible : Compatible caps) :
    Compatible (owner name kind :: caps) := by
  intro a ha b hb roots mutable
  rcases List.mem_cons.mp ha with rfl | ha
  · rcases List.mem_cons.mp hb with rfl | hb
    · exact Or.inl rfl
    · obtain ⟨root, hr, rootName⟩ := (closed b hb).1
      exact False.elim (fresh root hr (rootName.trans roots.symm))
  · rcases List.mem_cons.mp hb with rfl | hb
    · obtain ⟨root, hr, rootName⟩ := (closed a ha).1
      exact False.elim (fresh root hr (rootName.trans roots))
    · exact comparable_mono (fun _ h => List.mem_cons_of_mem _ h) (compatible a ha b hb roots mutable)

theorem loan_ancestor_path (caps : List Capability) (source : Capability) (name kind other : Nat)
    (member : source ∈ caps) (ancestor : Ancestor caps source.name other) :
    ParentPath (loan source name kind :: caps) name other := by
  have parentPath : ParentPath (loan source name kind :: caps) name source.name :=
    ParentPath.edge (child := loan source name kind) (parent := source)
      (by simp) (List.mem_cons_of_mem _ member) rfl
  rcases ancestor with same | path
  · exact same ▸ parentPath
  · exact ParentPath.trans parentPath (path_mono (fun _ h => List.mem_cons_of_mem _ h) path)

theorem compatible_loan (caps : List Capability) (source : Capability) (name kind : Nat)
    (member : source ∈ caps) (guard : BorrowGuard caps source kind) (compatible : Compatible caps) :
    Compatible (loan source name kind :: caps) := by
  intro a ha b hb roots mutable
  rcases List.mem_cons.mp ha with rfl | ha
  · rcases List.mem_cons.mp hb with rfl | hb
    · exact Or.inl rfl
    · exact Or.inr (Or.inl (loan_ancestor_path caps source name kind b.name member
        (guard b hb roots.symm mutable)))
  · rcases List.mem_cons.mp hb with rfl | hb
    · exact Or.inr (Or.inr (loan_ancestor_path caps source name kind a.name member
        (guard a ha roots mutable.symm)))
    · exact comparable_mono (fun _ h => List.mem_cons_of_mem _ h) (compatible a ha b hb roots mutable)

theorem compatible_subgraph {before after : List Capability}
    (unique : Unique before) (subset : ∀ c ∈ after, c ∈ before) (closed : Closed after)
    (compatible : Compatible before) : Compatible after := by
  intro a ha b hb roots mutable
  rcases compatible a (subset _ ha) b (subset _ hb) roots mutable with same | path | path
  · exact Or.inl same
  · exact Or.inr (Or.inl (path_retained unique subset closed path ⟨a, ha, rfl⟩))
  · exact Or.inr (Or.inr (path_retained unique subset closed path ⟨b, hb, rfl⟩))

theorem compatible_erase (caps : List Capability) (name : Nat)
    (closed : Closed caps) (unique : Unique caps) (free : Unreferenced caps name)
    (compatible : Compatible caps) : Compatible (erase name caps) :=
  compatible_subgraph unique (fun c h => ((erased_member caps name c).mp h).1)
    (erase_closed caps name closed free) compatible

theorem compatible_projection (caps : List Capability) (keep : Nat → Bool)
    (unique : Unique caps) (closed : Closed (project keep caps)) (compatible : Compatible caps) :
    Compatible (project keep caps) :=
  compatible_subgraph unique (fun c h => ((projected_member caps keep c).mp h).1) closed compatible

theorem compatible_rename (caps : List Capability) (f : Nat → Nat) (inj : Injective f)
    (compatible : Compatible caps) : Compatible (caps.map (rename f)) := by
  intro a ha b hb roots mutable
  obtain ⟨originalA, memberA, rfl⟩ := List.mem_map.mp ha
  obtain ⟨originalB, memberB, rfl⟩ := List.mem_map.mp hb
  rcases compatible originalA memberA originalB memberB (inj _ _ roots) mutable with same | path | path
  · exact Or.inl (congrArg f same)
  · exact Or.inr (Or.inl (path_rename f path))
  · exact Or.inr (Or.inr (path_rename f path))

theorem transfer_compatible {before after : List Capability} (transfer : Transfer before after)
    (unique : Unique before) (compatible : Compatible before) : Compatible after := by
  obtain ⟨keep, f, admitted, inj, rfl⟩ := transfer
  exact compatible_rename _ f inj (compatible_projection before keep unique admitted.2 compatible)

theorem child_blocks_access {caps : List Capability} {parent child : Capability} {write : Bool}
    (member : child ∈ caps) (relation : ChildOf child parent) : ¬ Access caps parent write := by
  intro access
  exact access.2.2 child member relation

theorem path_last_child {caps : List Capability} {a b : Nat} (path : ParentPath caps a b) :
    ∃ child ∈ caps, child.parent = some b := by
  induction path with
  | edge hc hp relation => exact ⟨_, hc, relation⟩
  | trans _ _ ih₁ ih₂ => exact ih₂

theorem ancestor_blocks_access {caps : List Capability} {parent : Capability} {child : Nat} {write : Bool}
    (path : ParentPath caps child parent.name) : ¬ Access caps parent write := by
  obtain ⟨c, member, relation⟩ := path_last_child path
  exact child_blocks_access member relation

theorem accessible_exclusive {caps : List Capability} {a b : Capability} {writeA writeB : Bool}
    (compatible : Compatible caps) (accessA : Access caps a writeA) (accessB : Access caps b writeB)
    (sameRoot : a.root = b.root) (different : a.name ≠ b.name) : a.kind ≠ 3 ∧ b.kind ≠ 3 := by
  have impossible : ¬ (a.kind = 3 ∨ b.kind = 3) := by
    intro mutable
    rcases compatible a accessA.1 b accessB.1 sameRoot mutable with same | path | path
    · exact different same
    · exact ancestor_blocks_access path accessB
    · exact ancestor_blocks_access path accessA
  exact ⟨fun h => impossible (Or.inl h), fun h => impossible (Or.inr h)⟩

theorem borrow_suspends_source (caps : List Capability) (source : Capability) (name kind : Nat)
    (write : Bool) : ¬ Access (loan source name kind :: caps) source write :=
  child_blocks_access (child := loan source name kind) (by simp) rfl

theorem end_restores_access (caps : List Capability) (parent : Capability) (ended : Nat) (write : Bool)
    (member : parent ∈ caps) (different : parent.name ≠ ended)
    (permission : if write then parent.kind = 3 else parent.kind = 2 ∨ parent.kind = 3)
    (lastChild : ∀ child ∈ caps, child.parent = some parent.name → child.name = ended) :
    Access (erase ended caps) parent write := by
  refine ⟨(erased_member caps ended parent).mpr ⟨member, different⟩, permission, ?_⟩
  intro child retained relation
  obtain ⟨old, notEnded⟩ := (erased_member caps ended child).mp retained
  exact notEnded (lastChild child old relation)

/- This selected relation has pre-state guards and no after-state safety
premise. Calls, moves, chains and other instruction effects remain outside. -/
inductive Step : List Capability → List Capability → Prop where
  | allocate {caps name kind} : Fresh caps name → (kind = 0 ∨ kind = 1) →
      Step caps (owner name kind :: caps)
  | borrowRead {caps source name} : source ∈ caps → Fresh caps name →
      (source.kind = 0 ∨ source.kind = 2 ∨ source.kind = 3) → BorrowGuard caps source 2 →
      Step caps (loan source name 2 :: caps)
  | borrowMut {caps source name} : source ∈ caps → Fresh caps name →
      (source.kind = 0 ∨ source.kind = 3) → BorrowGuard caps source 3 →
      Step caps (loan source name 3 :: caps)
  | endLoan {caps c} : c ∈ caps → c.external = false →
      (c.kind = 2 ∨ c.kind = 3) → Unreferenced caps c.name →
      Step caps (erase c.name caps)
  | dropOwner {caps c} : c ∈ caps → c.external = false →
      (c.kind = 0 ∨ c.kind = 1) → c.root = c.name → c.parent = none →
      Unreferenced caps c.name → Step caps (erase c.name caps)
  | access {caps c write} : Access caps c write → Step caps caps

theorem step_structural {before after : List Capability} (step : Step before after) :
    HiaCapabilityLifecycle.Step before after ∨ before = after := by
  cases step with
  | allocate fresh kind => exact Or.inl (.allocate fresh kind)
  | borrowRead member fresh kind guard => exact Or.inl (.borrowRead member fresh kind)
  | borrowMut member fresh kind guard => exact Or.inl (.borrowMut member fresh kind)
  | endLoan member localCap kind free => exact Or.inl (.endLoan member localCap kind free)
  | dropOwner member localCap kind root parent free => exact Or.inl (.dropOwner member localCap kind root parent free)
  | access access => exact Or.inr rfl

theorem step_closed {before after : List Capability} (step : Step before after)
    (closed : Closed before) : Closed after := by
  rcases step_structural step with structural | rfl
  · exact HiaCapabilityLifecycle.step_closed structural closed
  · exact closed

theorem step_ranked {before after : List Capability} (step : Step before after)
    (closed : Closed before) (ranked : Ranked before) : Ranked after := by
  rcases step_structural step with structural | rfl
  · exact HiaCapabilityLifecycle.step_ranked structural closed ranked
  · exact ranked

theorem step_unique {before after : List Capability} (step : Step before after)
    (unique : Unique before) : Unique after := by
  rcases step_structural step with structural | rfl
  · exact HiaCapabilityLifecycle.step_unique structural unique
  · exact unique

theorem step_compatible {before after : List Capability} (step : Step before after)
    (closed : Closed before) (unique : Unique before) (compatible : Compatible before) : Compatible after := by
  cases step with
  | allocate fresh kind => exact compatible_owner _ _ _ closed fresh compatible
  | borrowRead member fresh kind guard => exact compatible_loan _ _ _ _ member guard compatible
  | borrowMut member fresh kind guard => exact compatible_loan _ _ _ _ member guard compatible
  | endLoan member localCap kind free => exact compatible_erase _ _ closed unique free compatible
  | dropOwner member localCap kind root parent free => exact compatible_erase _ _ closed unique free compatible
  | access access => exact compatible

inductive Trace : List Capability → List Capability → Prop where
  | refl (caps) : Trace caps caps
  | instruction {before middle after} : Trace before middle → Step middle after → Trace before after
  | edge {before middle after} : Trace before middle → Transfer middle after → Trace before after

theorem trace_closed {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) : Closed after := by
  induction trace with
  | refl => exact closed
  | instruction _ step ih => exact step_closed step ih
  | edge _ transfer ih => exact transfer_closed transfer

theorem trace_ranked {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) (ranked : Ranked before) : Ranked after := by
  induction trace with
  | refl => exact ranked
  | instruction earlier step ih => exact step_ranked step (trace_closed earlier closed) ih
  | edge _ transfer ih => exact transfer_ranked transfer ih

theorem trace_unique {before after : List Capability} (trace : Trace before after)
    (unique : Unique before) : Unique after := by
  induction trace with
  | refl => exact unique
  | instruction _ step ih => exact step_unique step ih
  | edge _ transfer ih => exact transfer_unique transfer ih

theorem trace_compatible {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) (unique : Unique before) (compatible : Compatible before) : Compatible after := by
  induction trace with
  | refl => exact compatible
  | instruction earlier step ih =>
      exact step_compatible step (trace_closed earlier closed) (trace_unique earlier unique) ih
  | edge earlier transfer ih => exact transfer_compatible transfer (trace_unique earlier unique) ih

theorem trace_no_parent_cycle {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) (ranked : Ranked before) (name : Nat) : ¬ ParentPath after name name :=
  ranked_no_parent_cycle after (trace_ranked trace closed ranked) name

theorem trace_accessible_exclusive {before after : List Capability} (trace : Trace before after)
    (closed : Closed before) (unique : Unique before) (compatible : Compatible before)
    {a b : Capability} {writeA writeB : Bool} (accessA : Access after a writeA) (accessB : Access after b writeB)
    (sameRoot : a.root = b.root) (different : a.name ≠ b.name) : a.kind ≠ 3 ∧ b.kind ≠ 3 :=
  accessible_exclusive (trace_compatible trace closed unique compatible) accessA accessB sameRoot different

end HiaCapabilityBorrow
