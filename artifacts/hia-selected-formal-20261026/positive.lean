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

namespace HiaSelectedCore
def selectedProgram : Program := {
  code := [.add 0 1, .literal (BitVec.ofNat 32 17), .add 2 3, .sub 4 3],
  result := 5
}
theorem selected_program_correct (x y : Word) :
    execute selectedProgram [x, y] = some (specification x y) := by
  simp [selectedProgram, execute, run, executeOne, evaluate, read, specification, BitVec.add_sub_cancel]
end HiaSelectedCore
#print axioms HiaSelectedCore.run_append
#print axioms HiaSelectedCore.selected_program_correct
