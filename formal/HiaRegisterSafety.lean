/-
Appended to the exact HiaSelectedCore.lean model by
tools/qualify_hia_register_safety.py.  The two files form one kernel input.

These are generic theorems about the selected register machine, not a claim
that the production Python verifier or LLVM lowering has been proved sound.
-/
namespace HiaSelectedCore

def ValidOperation (available : Nat) : Operation → Prop
  | .literal _ => True
  | .add left right | .sub left right => left < available ∧ right < available

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
