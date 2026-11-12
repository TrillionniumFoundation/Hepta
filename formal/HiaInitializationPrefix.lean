import Lean.Elab.Tactic.Omega

/-!
A mathematical byte-memory model for the full-write-before-read optimization.
`none` is an uninitialized byte.  The fill schedule is exactly 0, 1, ..., n-1;
values are an arbitrary function independent of the initial byte contents.

This file does not import a HIA CFG, model an allocator or prove Python/LLVM
refinement.  The separate conservative CFG checker must establish this exact
schedule, common allocation identity, absence of early reads/escapes and that
the completed-fill exit dominates every subsequent byte read.  Native bounds,
allocation success/failure, zero-length and release remain separate obligations.
-/

namespace HiaInitializationPrefix

abbrev Byte := BitVec 8
abbrev Memory := Nat → Option Byte

def empty : Memory := fun _ => none
def zeroed : Memory := fun _ => some (BitVec.ofNat 8 0)

def write (memory : Memory) (index : Nat) (value : Byte) : Memory :=
  fun address => if address = index then some value else memory address

def fillPrefix (initial : Memory) (values : Nat → Byte) : Nat → Memory
  | 0 => initial
  | count + 1 => write (fillPrefix initial values count) count (values count)

def PrefixValues (memory : Memory) (values : Nat → Byte) (count : Nat) : Prop :=
  ∀ address, address < count → memory address = some (values address)

def FullyInitialized (memory : Memory) (length : Nat) : Prop :=
  ∀ address, address < length → ∃ value, memory address = some value

theorem write_at_index (memory : Memory) (index : Nat) (value : Byte) :
    write memory index value index = some value := by
  simp [write]

theorem write_at_other (memory : Memory) (index address : Nat) (value : Byte)
    (different : address ≠ index) :
    write memory index value address = memory address := by
  simp [write, different]

theorem zero_prefix (initial : Memory) (values : Nat → Byte) :
    fillPrefix initial values 0 = initial := rfl

theorem write_extends_prefix (memory : Memory) (values : Nat → Byte) (index : Nat)
    (before : PrefixValues memory values index) :
    PrefixValues (write memory index (values index)) values (index + 1) := by
  intro address below
  by_cases equal : address = index
  · subst address
    exact write_at_index memory index (values index)
  · have earlier : address < index := by omega
    simpa [write, equal] using before address earlier

theorem prefix_value (initial : Memory) (values : Nat → Byte) (count address : Nat)
    (below : address < count) :
    fillPrefix initial values count address = some (values address) := by
  induction count generalizing address with
  | zero => omega
  | succ count previous =>
      by_cases equal : address = count
      · subst address
        simp [fillPrefix, write]
      · have earlier : address < count := by omega
        simpa [fillPrefix, write, equal] using previous address earlier

theorem prefix_outside (initial : Memory) (values : Nat → Byte) (count address : Nat)
    (outside : count ≤ address) :
    fillPrefix initial values count address = initial address := by
  induction count with
  | zero => rfl
  | succ count previous =>
      have different : address ≠ count := by omega
      have before : count ≤ address := by omega
      simpa [fillPrefix, write, different] using previous before

theorem prefix_invariant (initial : Memory) (values : Nat → Byte) (count : Nat) :
    PrefixValues (fillPrefix initial values count) values count := by
  intro address below
  exact prefix_value initial values count address below

theorem completed_fill_initialized (initial : Memory) (values : Nat → Byte) (length : Nat) :
    FullyInitialized (fillPrefix initial values length) length := by
  intro address below
  exact ⟨values address, prefix_value initial values length address below⟩

theorem completed_fill_independent_of_initial (left right : Memory) (values : Nat → Byte)
    (length address : Nat) (below : address < length) :
    fillPrefix left values length address = fillPrefix right values length address := by
  rw [prefix_value left values length address below,
      prefix_value right values length address below]

theorem completed_fill_matches_zeroed (initial : Memory) (values : Nat → Byte)
    (length address : Nat) (below : address < length) :
    fillPrefix initial values length address = fillPrefix zeroed values length address :=
  completed_fill_independent_of_initial initial zeroed values length address below

theorem increment_within_limit (index length maximum : Nat)
    (continues : index < length) (bounded : length ≤ maximum) :
    index + 1 ≤ maximum := by omega

theorem completed_exit_is_exact_bound (index length : Nat)
    (invariant : index ≤ length) (exit : ¬ index < length) :
    index = length := by omega

theorem completed_exit_establishes_initialized (memory : Memory) (values : Nat → Byte)
    (index length : Nat) (initializedPrefix : PrefixValues memory values index)
    (invariant : index ≤ length) (exit : ¬ index < length) :
    FullyInitialized memory length := by
  have finished : index = length := completed_exit_is_exact_bound index length invariant exit
  intro address below
  exact ⟨values address, initializedPrefix address (by omega)⟩

theorem incomplete_prefix_is_not_full (values : Nat → Byte) (written length : Nat)
    (incomplete : written < length) :
    ¬ FullyInitialized (fillPrefix empty values written) length := by
  intro complete
  obtain ⟨value, found⟩ := complete written incomplete
  have absent : fillPrefix empty values written written = none := by
    simpa [empty] using prefix_outside empty values written written (Nat.le_refl written)
  rw [absent] at found
  contradiction

def fillFromOne (values : Nat → Byte) : Nat → Memory
  | 0 => empty
  | count + 1 => write (fillFromOne values count) (count + 1) (values (count + 1))

theorem skipped_zero_stays_uninitialized (values : Nat → Byte) (count : Nat) :
    fillFromOne values count 0 = none := by
  induction count with
  | zero => rfl
  | succ count previous => simpa [fillFromOne, write] using previous

def fillStrideTwo (values : Nat → Byte) : Nat → Memory
  | 0 => empty
  | count + 1 => write (fillStrideTwo values count) (count * 2) (values (count * 2))

theorem stride_two_leaves_a_hole (values : Nat → Byte) (count : Nat) :
    fillStrideTwo values count 1 = none := by
  induction count with
  | zero => rfl
  | succ count previous =>
      have different : 1 ≠ count * 2 := by omega
      simpa [fillStrideTwo, write, different] using previous

#print axioms write_at_index
#print axioms write_at_other
#print axioms zero_prefix
#print axioms write_extends_prefix
#print axioms prefix_value
#print axioms prefix_outside
#print axioms prefix_invariant
#print axioms completed_fill_initialized
#print axioms completed_fill_independent_of_initial
#print axioms completed_fill_matches_zeroed
#print axioms increment_within_limit
#print axioms completed_exit_is_exact_bound
#print axioms completed_exit_establishes_initialized
#print axioms incomplete_prefix_is_not_full
#print axioms skipped_zero_stays_uninitialized
#print axioms stride_two_leaves_a_hole

end HiaInitializationPrefix
