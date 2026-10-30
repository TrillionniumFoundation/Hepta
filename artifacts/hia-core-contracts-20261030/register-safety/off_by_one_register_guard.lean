import Lean.Elab.Tactic.Omega

/- Independent register-machine semantics for the selected standalone HIA
   u32 profile. A register is appended by each instruction; reading a missing
   register fails. The exporter is not part of this formal definition. -/
namespace HiaSelectedCore

abbrev Word := BitVec 32

inductive Operation where
  | literal (value : Word)
  | add (left right : Nat)
  | sub (left right : Nat)

structure Program where
  code : List Operation
  result : Nat

def read (registers : List Word) (index : Nat) : Option Word := registers[index]?

def evaluate : Operation → List Word → Option Word
  | .literal value, _ => some value
  | .add left right, registers => do
      let a ← read registers left
      let b ← read registers right
      pure (a + b)
  | .sub left right, registers => do
      let a ← read registers left
      let b ← read registers right
      pure (a - b)

def executeOne (operation : Operation) (registers : List Word) : Option (List Word) :=
  (evaluate operation registers).map (fun value => registers ++ [value])

def run : List Operation → List Word → Option (List Word)
  | [], registers => some registers
  | operation :: rest, registers => (executeOne operation registers).bind (run rest)

def execute (program : Program) (arguments : List Word) : Option Word :=
  (run program.code arguments).bind (fun registers => read registers program.result)

theorem run_append (a b : List Operation) (registers : List Word) :
    run (a ++ b) registers = (run a registers).bind (run b) := by
  induction a generalizing registers with
  | nil => rfl
  | cons head rest ih =>
    simp only [List.cons_append, run]
    cases h : executeOne head registers <;> simp [h, ih]

/- The external requirement is addition modulo 2^32. It is written separately
   from the generated instruction stream and remains fixed for mutations. -/
def specification (left right : Word) : Word := left + right

end HiaSelectedCore

/-
Appended to the exact HiaSelectedCore.lean model by
tools/qualify_hia_register_safety.py.  The two files form one kernel input.

These are generic theorems about the selected register machine, not a claim
that the production Python verifier or LLVM lowering has been proved sound.
-/
namespace HiaSelectedCore

def ValidOperation (available : Nat) : Operation → Prop
  | .literal _ => True
  | .add left right | .sub left right => left ≤ available ∧ right ≤ available

def ValidCode : List Operation → Nat → Prop
  | [], _ => True
  | operation :: rest, available =>
      ValidOperation available operation ∧ ValidCode rest (available + 1)

def WellFormed (program : Program) (arity : Nat) : Prop :=
  ValidCode program.code arity ∧ program.result < arity + program.code.length

theorem read_defined (registers : List Word) (index : Nat)
    (valid : index < registers.length) :
    ∃ value, read registers index = some value := by
  induction registers generalizing index with
  | nil => simp at valid
  | cons head rest ih =>
      cases index with
      | zero => exact ⟨head, rfl⟩
      | succ index =>
          obtain ⟨value, found⟩ := ih index (by simpa using valid)
          exact ⟨value, by simpa [read] using found⟩

theorem evaluate_total (operation : Operation) (registers : List Word)
    (valid : ValidOperation registers.length operation) :
    ∃ value, evaluate operation registers = some value := by
  cases operation with
  | literal value => exact ⟨value, rfl⟩
  | add left right =>
      obtain ⟨a, leftRead⟩ := read_defined registers left valid.1
      obtain ⟨b, rightRead⟩ := read_defined registers right valid.2
      exact ⟨a + b, by simp [evaluate, leftRead, rightRead]⟩
  | sub left right =>
      obtain ⟨a, leftRead⟩ := read_defined registers left valid.1
      obtain ⟨b, rightRead⟩ := read_defined registers right valid.2
      exact ⟨a - b, by simp [evaluate, leftRead, rightRead]⟩

theorem executeOne_total (operation : Operation) (registers : List Word)
    (valid : ValidOperation registers.length operation) :
    ∃ next, executeOne operation registers = some next ∧
      next.length = registers.length + 1 := by
  obtain ⟨value, evaluated⟩ := evaluate_total operation registers valid
  exact ⟨registers ++ [value], by simp [executeOne, evaluated], by simp⟩

theorem run_total (code : List Operation) (registers : List Word)
    (valid : ValidCode code registers.length) :
    ∃ final, run code registers = some final ∧
      final.length = registers.length + code.length := by
  induction code generalizing registers with
  | nil => exact ⟨registers, rfl, by simp⟩
  | cons operation rest ih =>
      obtain ⟨next, stepped, nextLength⟩ := executeOne_total operation registers valid.1
      have restValid : ValidCode rest next.length := by
        rw [nextLength]
        exact valid.2
      obtain ⟨final, ran, finalLength⟩ := ih next restValid
      refine ⟨final, by simp [run, stepped, ran], ?_⟩
      simp only [List.length_cons]
      omega

theorem execute_total (program : Program) (arguments : List Word)
    (valid : WellFormed program arguments.length) :
    ∃ value, execute program arguments = some value := by
  obtain ⟨final, ran, finalLength⟩ := run_total program.code arguments valid.1
  have resultValid : program.result < final.length := by
    have bound := valid.2
    omega
  obtain ⟨value, found⟩ := read_defined final program.result resultValid
  exact ⟨value, by simp [execute, ran, found]⟩

theorem read_append_existing (registers suffix : List Word) (index : Nat)
    (valid : index < registers.length) :
    read (registers ++ suffix) index = read registers index := by
  induction registers generalizing index with
  | nil => simp at valid
  | cons head rest ih =>
      cases index with
      | zero => rfl
      | succ index =>
          simpa [read] using ih index (by simpa using valid)

def appendDeadLiteral (program : Program) (value : Word) : Program :=
  { code := program.code ++ [.literal value], result := program.result }

theorem dead_literal_preserves (program : Program) (arguments : List Word)
    (value : Word) (valid : WellFormed program arguments.length) :
    execute (appendDeadLiteral program value) arguments = execute program arguments := by
  obtain ⟨final, ran, finalLength⟩ := run_total program.code arguments valid.1
  have resultValid : program.result < final.length := by
    have bound := valid.2
    omega
  have tailRan : run [.literal value] final = some (final ++ [value]) := rfl
  calc
    execute (appendDeadLiteral program value) arguments = read (final ++ [value]) program.result := by
      simp [execute, appendDeadLiteral, run_append, ran, tailRan]
    _ = read final program.result := read_append_existing final [value] program.result resultValid
    _ = execute program arguments := by simp [execute, ran]

end HiaSelectedCore

namespace HiaSelectedCore
def sourceProgram : Program := {
  code := [.add 0 1, .literal (BitVec.ofNat 32 17), .add 2 3, .sub 4 3, .literal (BitVec.ofNat 32 99)],
  result := 5
}
def candidateProgram : Program := {
  code := [.add 0 1, .literal (BitVec.ofNat 32 17), .add 2 3, .sub 4 3],
  result := 5
}
theorem source_well_formed : WellFormed sourceProgram 2 := by
  simp [WellFormed, ValidCode, ValidOperation, sourceProgram]
theorem candidate_well_formed : WellFormed candidateProgram 2 := by
  simp [WellFormed, ValidCode, ValidOperation, candidateProgram]
theorem source_is_dead_extension :
    sourceProgram = appendDeadLiteral candidateProgram (BitVec.ofNat 32 99) := by rfl
theorem selected_source_total (x y : Word) :
    ∃ value, execute sourceProgram [x, y] = some value :=
  execute_total sourceProgram [x, y] source_well_formed
theorem selected_candidate_total (x y : Word) :
    ∃ value, execute candidateProgram [x, y] = some value :=
  execute_total candidateProgram [x, y] candidate_well_formed
theorem selected_rewrite_equivalent (x y : Word) :
    execute sourceProgram [x, y] = execute candidateProgram [x, y] := by
  rw [source_is_dead_extension]
  exact dead_literal_preserves candidateProgram [x, y] _ candidate_well_formed
end HiaSelectedCore
#print axioms HiaSelectedCore.candidate_well_formed
#print axioms HiaSelectedCore.dead_literal_preserves
#print axioms HiaSelectedCore.evaluate_total
#print axioms HiaSelectedCore.executeOne_total
#print axioms HiaSelectedCore.execute_total
#print axioms HiaSelectedCore.read_append_existing
#print axioms HiaSelectedCore.read_defined
#print axioms HiaSelectedCore.run_append
#print axioms HiaSelectedCore.run_total
#print axioms HiaSelectedCore.selected_candidate_total
#print axioms HiaSelectedCore.selected_rewrite_equivalent
#print axioms HiaSelectedCore.selected_source_total
#print axioms HiaSelectedCore.source_is_dead_extension
#print axioms HiaSelectedCore.source_well_formed
