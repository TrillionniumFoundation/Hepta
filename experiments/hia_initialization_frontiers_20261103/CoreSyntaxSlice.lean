/-!
UNCHECKED Lean 4.19 proof text. Append after the existing
Lean.Elab.Tactic.Omega import; no additional import is required.

Restricted, compact canonical JSON transport for an inert whole-document tree.
The decoder is independent of the serializer. checkedEncode accepts only after
an actual decode equality check, so determinacy below is a checked round-trip
result, not an assumed serializer-injectivity theorem. No claim of completeness
for all JSON, all Core, or every input within the resource limits is made.
File-to-byte provenance is outside this kernel statement.
-/

namespace HiaCoreSyntaxSlice

inductive Raw where
  | str (bytes : List Nat)
  | num (value : Nat)
  | arr (items : List Raw)
  | obj (fields : List (List Nat × Raw))
  deriving Repr

/- Lean 4.19 does not derive DecidableEq for this nested datatype. These
    explicit mutual decisions produce equality proofs by constructor congruence
    and reject unequal constructor arguments by constructor injectivity. -/
mutual
  def rawDecEq : (a b : Raw) → Decidable (a = b)
    | .str left, .str right =>
      if same : left = right then isTrue (congrArg Raw.str same)
      else isFalse (fun equal => same (Raw.str.inj equal))
    | .num left, .num right =>
      if same : left = right then isTrue (congrArg Raw.num same)
      else isFalse (fun equal => same (Raw.num.inj equal))
    | .arr left, .arr right =>
      match rawListDecEq left right with
      | isTrue same => isTrue (congrArg Raw.arr same)
      | isFalse different => isFalse (fun equal => different (Raw.arr.inj equal))
    | .obj left, .obj right =>
      match rawFieldsDecEq left right with
      | isTrue same => isTrue (congrArg Raw.obj same)
      | isFalse different => isFalse (fun equal => different (Raw.obj.inj equal))
    | .str _, .num _ => isFalse (by intro equal; cases equal)
    | .str _, .arr _ => isFalse (by intro equal; cases equal)
    | .str _, .obj _ => isFalse (by intro equal; cases equal)
    | .num _, .str _ => isFalse (by intro equal; cases equal)
    | .num _, .arr _ => isFalse (by intro equal; cases equal)
    | .num _, .obj _ => isFalse (by intro equal; cases equal)
    | .arr _, .str _ => isFalse (by intro equal; cases equal)
    | .arr _, .num _ => isFalse (by intro equal; cases equal)
    | .arr _, .obj _ => isFalse (by intro equal; cases equal)
    | .obj _, .str _ => isFalse (by intro equal; cases equal)
    | .obj _, .num _ => isFalse (by intro equal; cases equal)
    | .obj _, .arr _ => isFalse (by intro equal; cases equal)

  def rawListDecEq : (a b : List Raw) → Decidable (a = b)
    | [], [] => isTrue rfl
    | [], _ :: _ => isFalse (by intro equal; cases equal)
    | _ :: _, [] => isFalse (by intro equal; cases equal)
    | left :: leftRest, right :: rightRest =>
      match rawDecEq left right with
      | isFalse different =>
        isFalse (fun equal => different (List.cons.inj equal).1)
      | isTrue same =>
        match rawListDecEq leftRest rightRest with
        | isFalse different =>
          isFalse (fun equal => different (List.cons.inj equal).2)
        | isTrue sameRest => isTrue (by cases same; cases sameRest; rfl)

  def rawFieldDecEq : (a b : List Nat × Raw) → Decidable (a = b)
    | (leftKey, left), (rightKey, right) =>
      if sameKey : leftKey = rightKey then
        match rawDecEq left right with
        | isTrue same => isTrue (by cases sameKey; cases same; rfl)
        | isFalse different =>
          isFalse (fun equal => different (congrArg Prod.snd equal))
      else isFalse (fun equal => sameKey (congrArg Prod.fst equal))

  def rawFieldsDecEq : (a b : List (List Nat × Raw)) → Decidable (a = b)
    | [], [] => isTrue rfl
    | [], _ :: _ => isFalse (by intro equal; cases equal)
    | _ :: _, [] => isFalse (by intro equal; cases equal)
    | left :: leftRest, right :: rightRest =>
      match rawFieldDecEq left right with
      | isFalse different =>
        isFalse (fun equal => different (List.cons.inj equal).1)
      | isTrue same =>
        match rawFieldsDecEq leftRest rightRest with
        | isFalse different =>
          isFalse (fun equal => different (List.cons.inj equal).2)
        | isTrue sameRest => isTrue (by cases same; cases sameRest; rfl)
end

instance : DecidableEq Raw := rawDecEq

def transportFuel : Nat := 4096
def transportDepth : Nat := 32
def transportByteLimit : Nat := 32768

/-- Printable ASCII without JSON's quote or escape character. -/
def stringByte (byte : Nat) : Bool :=
  decide (32 ≤ byte ∧ byte ≤ 126 ∧ byte ≠ 34 ∧ byte ≠ 92)

def stringBytes : List Nat → Bool
  | [] => true
  | byte :: rest => stringByte byte && stringBytes rest

/-- Strict lexicographic comparison of byte lists, including prefix ordering. -/
def keyLess : List Nat → List Nat → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: left, b :: right =>
    if a < b then true else if a = b then keyLess left right else false

/-- Strict order rejects both duplicates and noncanonical field order. -/
def orderedFields : List (List Nat × Raw) → Bool
  | [] => true
  | (key, _) :: rest =>
    match rest with
    | [] => true
    | (nextKey, _) :: _ => keyLess key nextKey && orderedFields rest

/-- Count all value nodes, including unselected subtrees, without recursion on
    the nested datatype. This is separate from parser/serializer call fuel. -/
def nodeBudget : Nat → List Raw → Bool
  | _, [] => true
  | 0, _ :: _ => false
  | fuel + 1, .str _ :: rest => nodeBudget fuel rest
  | fuel + 1, .num _ :: rest => nodeBudget fuel rest
  | fuel + 1, .arr items :: rest => nodeBudget fuel (items ++ rest)
  | fuel + 1, .obj fields :: rest =>
    nodeBudget fuel (fields.map (fun entry => entry.2) ++ rest)

/-- A separate cheap whole-tree budget check for syntax extraction. Each
    pending item carries the number of value levels still allowed at that item. -/
def depthNodeBudget : Nat → List (Nat × Raw) → Bool
  | _, [] => true
  | 0, _ :: _ => false
  | _ + 1, (0, _) :: _ => false
  | fuel + 1, (_ + 1, .str _) :: rest => depthNodeBudget fuel rest
  | fuel + 1, (_ + 1, .num _) :: rest => depthNodeBudget fuel rest
  | fuel + 1, (depth + 1, .arr items) :: rest =>
    depthNodeBudget fuel (items.map (fun item => (depth, item)) ++ rest)
  | fuel + 1, (depth + 1, .obj fields) :: rest =>
    depthNodeBudget fuel (fields.map (fun entry => (depth, entry.2)) ++ rest)

def withinBounds (raw : Raw) : Bool :=
  depthNodeBudget transportFuel [(transportDepth, raw)]

/-- Explicit base-ten conversion. Zero emits exactly one digit. The only
    leading digit emitted is 1..9 unless the entire numeral is zero. -/
def decimalAux : Nat → Nat → List Nat → Option (List Nat)
  | 0, _, _ => none
  | fuel + 1, value, suffix =>
    if value < 10 then some ((48 + value) :: suffix)
    else decimalAux fuel (value / 10) ((48 + value % 10) :: suffix)

def decimal (value : Nat) : Option (List Nat) :=
  decimalAux transportByteLimit value []

mutual
  /-- A compact serializer with no escape or raw-fragment constructor. -/
  def serializeRaw : Nat → Nat → Raw → Option (List Nat)
    | 0, _, _ => none
    | _ + 1, 0, _ => none
    | _ + 1, _ + 1, .str bytes =>
      if stringBytes bytes then some (34 :: (bytes ++ [34])) else none
    | _ + 1, _ + 1, .num value => decimal value
    | fuel + 1, depth + 1, .arr items => do
      let bytes ← serializeItems fuel depth items
      pure (91 :: (bytes ++ [93]))
    | fuel + 1, depth + 1, .obj fields =>
      if orderedFields fields then do
        let bytes ← serializeFields fuel depth fields
        pure (123 :: (bytes ++ [125]))
      else none

  def serializeItems : Nat → Nat → List Raw → Option (List Nat)
    | _, _, [] => some []
    | 0, _, _ :: _ => none
    | fuel + 1, depth, value :: rest => do
      let bytes ← serializeRaw fuel depth value
      match rest with
      | [] => pure bytes
      | _ :: _ =>
        let suffix ← serializeItems fuel depth rest
        pure (bytes ++ (44 :: suffix))

  def serializeFields : Nat → Nat → List (List Nat × Raw) → Option (List Nat)
    | _, _, [] => some []
    | 0, _, _ :: _ => none
    | fuel + 1, depth, (key, value) :: rest =>
      if stringBytes key then do
        let bytes ← serializeRaw fuel depth value
        let field := 34 :: (key ++ (34 :: 58 :: bytes))
        match rest with
        | [] => pure field
        | _ :: _ =>
          let suffix ← serializeFields fuel depth rest
          pure (field ++ (44 :: suffix))
      else none
end

/-- The byte and node checks are part of the accepted transport domain. -/
def serializeChecked (raw : Raw) : Option (List Nat) :=
  if withinBounds raw then
    match serializeRaw transportFuel transportDepth raw with
    | none => none
    | some bytes => if bytes.length ≤ transportByteLimit then some bytes else none
  else none

def digitByte (byte : Nat) : Bool := decide (48 ≤ byte ∧ byte ≤ 57)

/-- Called after an opening quote. It consumes its closing quote, never escapes. -/
def parseStringTail : List Nat → List Nat → Option (List Nat × List Nat)
  | [], _ => none
  | byte :: rest, reversed =>
    if byte = 34 then some (reversed.reverse, rest)
    else if stringByte byte then parseStringTail rest (byte :: reversed)
    else none

def parseDigits : List Nat → Nat → Nat × List Nat
  | [], value => (value, [])
  | byte :: rest, value =>
    if digitByte byte then parseDigits rest (value * 10 + (byte - 48))
    else (value, byte :: rest)

/-- A zero cannot be followed by another decimal digit. A separator is checked
    by the enclosing parser or by decode's full-consumption check. -/
def parseNumber : List Nat → Option (Nat × List Nat)
  | [] => none
  | byte :: rest =>
    if byte = 48 then
      match rest with
      | next :: _ => if digitByte next then none else some (0, rest)
      | [] => some (0, [])
    else if decide (49 ≤ byte ∧ byte ≤ 57) then
      some (parseDigits rest (byte - 48))
    else none

mutual
  /-- Independent, fuelled parser. Whitespace, escape sequences, signs,
      decimals, bool and null have no admitting parser case. -/
  def parseRaw : Nat → Nat → List Nat → Option (Raw × List Nat)
    | 0, _, _ => none
    | _ + 1, 0, _ => none
    | _ + 1, _ + 1, 34 :: rest => do
      let (bytes, suffix) ← parseStringTail rest []
      pure (.str bytes, suffix)
    | _ + 1, _ + 1, 91 :: 93 :: rest => some (.arr [], rest)
    | fuel + 1, depth + 1, 91 :: rest => do
      let (items, suffix) ← parseItems fuel depth rest
      pure (.arr items, suffix)
    | _ + 1, _ + 1, 123 :: 125 :: rest => some (.obj [], rest)
    | fuel + 1, depth + 1, 123 :: rest => do
      let (fields, suffix) ← parseFields fuel depth rest
      if orderedFields fields then pure (.obj fields, suffix) else none
    | _ + 1, _ + 1, bytes => do
      let (value, suffix) ← parseNumber bytes
      pure (.num value, suffix)

  /-- Nonempty array contents only. A trailing comma therefore cannot pass. -/
  def parseItems : Nat → Nat → List Nat → Option (List Raw × List Nat)
    | 0, _, _ => none
    | fuel + 1, depth, bytes => do
      let (value, suffix) ← parseRaw fuel depth bytes
      match suffix with
      | 93 :: rest => pure ([value], rest)
      | 44 :: rest =>
        let (values, suffix) ← parseItems fuel depth rest
        pure (value :: values, suffix)
      | _ => none

  /-- Nonempty object contents only. Keys must be unescaped strings. -/
  def parseFields : Nat → Nat → List Nat → Option (List (List Nat × Raw) × List Nat)
    | 0, _, _ => none
    | fuel + 1, depth, 34 :: rest => do
      let (key, suffix) ← parseStringTail rest []
      match suffix with
      | 58 :: rest =>
        let (value, suffix) ← parseRaw fuel depth rest
        match suffix with
        | 125 :: rest => pure ([(key, value)], rest)
        | 44 :: rest =>
          let (fields, suffix) ← parseFields fuel depth rest
          pure ((key, value) :: fields, suffix)
        | _ => none
      | _ => none
    | _ + 1, _, _ => none
end

/-- Full consumption, exact byte limit, and whole-tree node limit are mandatory.
    Parser recursion is bounded independently of the value-node counter. -/
def decode (bytes : List Nat) : Option Raw :=
  if bytes.length ≤ transportByteLimit ∧
      bytes.all (fun byte => decide (byte ≤ 255)) = true then
    match parseRaw transportFuel transportDepth bytes with
    | some (raw, []) => if withinBounds raw then some raw else none
    | _ => none
  else none

/-- Successful encoding includes a decoder equality check, not an assumption
    that structurally different inputs cannot happen to emit equal bytes. -/
def checkedEncode (raw : Raw) : Option (List Nat) :=
  match serializeChecked raw with
  | none => none
  | some bytes => if decode bytes = some raw then some bytes else none

/-- Generic checked round trip. This says nothing about unaccepted inputs. -/
theorem checkedEncode_roundtrip (raw : Raw) (bytes : List Nat)
    (accepted : checkedEncode raw = some bytes) : decode bytes = some raw := by
  unfold checkedEncode at accepted
  cases encoded : serializeChecked raw with
  | none => simp [encoded] at accepted
  | some candidate =>
    by_cases parsed : decode candidate = some raw
    · have same : candidate = bytes := by simpa [encoded, parsed] using accepted
      simpa [same] using parsed
    · simp [encoded, parsed] at accepted

/-- Equal accepted bytes identify one inert whole-document Raw tree. The proof
    uses decoder equality and does not postulate serializer injectivity. -/
theorem checkedEncode_determinate (a b : Raw) (bytes : List Nat)
    (left : checkedEncode a = some bytes)
    (right : checkedEncode b = some bytes) : a = b := by
  have decodedLeft := checkedEncode_roundtrip a bytes left
  have decodedRight := checkedEncode_roundtrip b bytes right
  exact Option.some.inj (decodedLeft.symm.trans decodedRight)


end HiaCoreSyntaxSlice


namespace HiaCoreSyntaxSlice

open HiaGuardedUsizeSlice

/-- Names are exact ASCII byte sequences, never hashes or normalized names. -/
def ascii (s : String) : List Nat := s.toList.map Char.toNat

def field (raw : Raw) (key : String) : Raw :=
  match raw with
  | .obj fields => ((fields.find? (fun pair => pair.1 == ascii key)).map Prod.snd).getD (.obj [])
  | _ => .obj []

def array (raw : Raw) : List Raw :=
  match raw with
  | .arr items => items
  | _ => []

def bytes (raw : Raw) : List Nat :=
  match raw with
  | .str value => value
  | _ => []

def number (raw : Raw) : Nat :=
  match raw with
  | .num value => value
  | _ => 0

def isString : Raw → Bool
  | .str _ => true
  | _ => false

def isObject : Raw → Bool
  | .obj _ => true
  | _ => false

def isArray : Raw → Bool
  | .arr _ => true
  | _ => false

def keysAre (raw : Raw) (keys : List String) : Bool :=
  match raw with
  | .obj fields => decide (fields.map Prod.fst = keys.map ascii)
  | _ => false

def rawAt (items : List Raw) (index : Nat) : Raw := items[index]?.getD (.obj [])

def position (name : List Nat) : List (List Nat) → Nat
  | [] => 0
  | first :: rest => if name = first then 0 else position name rest + 1

def names (items : List Raw) : List (List Nat) :=
  items.map (fun item => bytes (field item "name"))

def goodParam (raw : Raw) : Bool :=
  keysAre raw ["name", "type"] && isString (field raw "name") &&
    isString (field raw "type")

def goodParams (raw : Raw) : Bool :=
  isArray raw && (array raw).all goodParam

def goodStrings (raw : Raw) : Bool :=
  isArray raw && (array raw).all isString

def goodOp (raw : Raw) : Bool :=
  keysAre raw ["args", "attrs", "op", "out"] &&
    goodStrings (field raw "args") && isObject (field raw "attrs") &&
    isString (field raw "op") && goodParams (field raw "out")

def blockBinders (raw : Raw) : List Raw :=
  array (field raw "params") ++
    (array (field raw "ops")).flatMap (fun op => array (field op "out"))

/-- Unknown operations remain inert syntax. Their envelope and binders, not
    their execution behavior, are checked. -/
def goodBlock (raw : Raw) : Bool :=
  keysAre raw ["id", "ops", "params", "term"] &&
    isString (field raw "id") && goodParams (field raw "params") &&
    isArray (field raw "ops") && (array (field raw "ops")).all goodOp &&
    isObject (field raw "term") &&
    decide ((names (blockBinders raw)).Nodup) -- MUTATION_SITE_BINDER_UNIQUENESS

def goodFunction (raw : Raw) : Bool :=
  keysAre raw ["blocks", "effects", "entry", "name", "params", "returns"] &&
    isString (field raw "name") && isString (field raw "entry") &&
    goodStrings (field raw "effects") && goodParams (field raw "params") &&
    decide ((names (array (field raw "params"))).Nodup) &&
    goodStrings (field raw "returns") && isArray (field raw "blocks") &&
    decide ((array (field raw "blocks")).length ≤ 128) &&
    (array (field raw "blocks")).all goodBlock &&
    decide (((array (field raw "blocks")).map (fun b => bytes (field b "id"))).Nodup)

def goodProgram (raw : Raw) : Bool :=
  keysAre raw ["exports", "functions", "module", "schema"] &&
    goodStrings (field raw "exports") && isString (field raw "module") &&
    decide (field raw "schema" = .str (ascii "hepta.hia.program.v1")) &&
    isArray (field raw "functions") &&
    (array (field raw "functions")).all goodFunction &&
    decide ((names (array (field raw "functions"))).Nodup)

structure Hint where
  functionIndex : Nat
  headerIndex : Nat
  targetIndex : Nat
  addOrdinal : Nat
  bodyIndex : List Nat
  bodyExtent : List Nat
  deriving DecidableEq, Repr

abbrev Locator := Hint

def selectedFunction (raw : Raw) (hint : Hint) : Raw :=
  rawAt (array (field raw "functions")) hint.functionIndex

def selectedHeader (raw : Raw) (hint : Hint) : Raw :=
  rawAt (array (field (selectedFunction raw hint) "blocks")) hint.headerIndex

def selectedTarget (raw : Raw) (hint : Hint) : Raw :=
  rawAt (array (field (selectedFunction raw hint) "blocks")) hint.targetIndex

def definitionOrdinal (name : List Nat) : List Raw → Nat
  | [] => 0
  | op :: rest =>
    if name ∈ names (array (field op "out")) then 0
    else definitionOrdinal name rest + 1

def addTag (raw : Raw) : AddOp :=
  if raw = .str (ascii "int.add.checked") then .checked
  else if raw = .str (ascii "int.add.wrap") then .wrapping else .other

/-- This proposal function reads syntax, not an expected descriptor. Its defaults
    are rejected by the independent relation's shape, bounds and scope checks. -/
def reconstruct (raw : Raw) (hint : Hint) : Descriptor :=
  let header := selectedHeader raw hint
  let target := selectedTarget raw hint
  let compare := rawAt (array (field header "ops")) 0
  let sourceNames := names (blockBinders header)
  let compareArgs := (array (field compare "args")).map bytes
  let edge := field (field header "term") "then" -- MUTATION_SITE_SELECT_THEN
  let targetParams := array (field target "params")
  let targetNames := names targetParams
  let ops := array (field target "ops")
  let add := rawAt ops hint.addOrdinal
  let args := (array (field add "args")).map bytes
  let literalOrdinal := definitionOrdinal (args[1]?.getD []) ops
  let literal := rawAt ops literalOrdinal
  { sourceIndex := position (compareArgs[0]?.getD []) sourceNames -- MUTATION_SITE_SOURCE_POSITION
    sourceExtent := position (compareArgs[1]?.getD []) sourceNames
    compareOutput := position (bytes (field (rawAt (array (field compare "out")) 0) "name")) sourceNames
    branchCondition := position (bytes (field (field header "term") "cond")) sourceNames
    indexType := if field (rawAt (blockBinders header) (position (compareArgs[0]?.getD []) sourceNames)) "type" = .str (ascii "usize") then .usize else .other
    extentType := if field (rawAt (blockBinders header) (position (compareArgs[1]?.getD []) sourceNames)) "type" = .str (ascii "usize") then .usize else .other
    compareOp := if field compare "op" = .str (ascii "compare.lt") then .lt else .other
    selectedArm := .thenArm
    incoming := (array (field edge "args")).map (fun arg => position (bytes arg) sourceNames)
    indexSlot := position hint.bodyIndex targetNames
    extentSlot := position hint.bodyExtent targetNames
    addIndexSlot := position (args[0]?.getD []) targetNames
    addOp := addTag (field add "op")
    addType := if field (rawAt (array (field add "out")) 0) "type" = .str (ascii "usize") then .usize else .other
    literalType := if field (rawAt (array (field literal "out")) 0) "type" = .str (ascii "usize") then .usize else .other
    literalValue := number (field (field literal "attrs") "value")
    literalOrdinal := literalOrdinal
    addOrdinal := hint.addOrdinal }

/-- Declarative raw syntax contract, independent of `extract` and `reconstruct`.
    Every ordered edge argument is retained, including opaque/resource values.
    No condition below claims normal arrival through the target body. -/
def SliceSyntaxRelation (raw : Raw) (hint : Hint) (d : Descriptor) : Prop :=
  let functions := array (field raw "functions")
  let fn := rawAt functions hint.functionIndex
  let blocks := array (field fn "blocks")
  let header := rawAt blocks hint.headerIndex
  let target := rawAt blocks hint.targetIndex
  let headerParams := array (field header "params")
  let compare := rawAt (array (field header "ops")) 0
  let sourceBinders := blockBinders header
  let sourceNames := names sourceBinders
  let targetParams := array (field target "params")
  let targetNames := names targetParams
  let term := field header "term"
  let thenEdge := field term "then"
  let elseEdge := field term "else"
  let edgeArgs := array (field thenEdge "args")
  let ops := array (field target "ops")
  let add := rawAt ops d.addOrdinal
  let literal := rawAt ops d.literalOrdinal
  withinBounds raw = true ∧
  goodProgram raw = true ∧
  hint.functionIndex < functions.length ∧
  hint.headerIndex < blocks.length ∧ hint.targetIndex < blocks.length ∧
  array (field header "ops") = [compare] ∧
  field compare "op" = .str (ascii "compare.lt") ∧
  field compare "attrs" = .obj [] ∧
  field compare "args" = .arr [.str (sourceNames[d.sourceIndex]?.getD []),
    .str (sourceNames[d.sourceExtent]?.getD [])] ∧
  d.sourceIndex < headerParams.length ∧ d.sourceExtent < headerParams.length ∧
  field (rawAt sourceBinders d.sourceIndex) "type" = .str (ascii "usize") ∧
  field (rawAt sourceBinders d.sourceExtent) "type" = .str (ascii "usize") ∧
  d.compareOutput = headerParams.length ∧
  field compare "out" = .arr [.obj [(ascii "name", .str (sourceNames[d.compareOutput]?.getD [])),
    (ascii "type", .str (ascii "bool"))]] ∧
  keysAre term ["cond", "else", "op", "then"] = true ∧
  field term "op" = .str (ascii "branch") ∧
  field term "cond" = .str (sourceNames[d.compareOutput]?.getD []) ∧
  keysAre thenEdge ["args", "target"] = true ∧
  keysAre elseEdge ["args", "target"] = true ∧
  goodStrings (field elseEdge "args") = true ∧ isString (field elseEdge "target") = true ∧
  field thenEdge "target" = field target "id" ∧
  goodStrings (field thenEdge "args") = true ∧
  edgeArgs.length = targetParams.length ∧
  d.incoming.length = edgeArgs.length ∧
  d.incoming.all (fun i => decide (i < sourceNames.length)) = true ∧
  edgeArgs = d.incoming.map (fun i => Raw.str (sourceNames[i]?.getD [])) ∧
  hint.bodyIndex ∈ targetNames ∧ hint.bodyExtent ∈ targetNames ∧
  targetNames[d.indexSlot]? = some hint.bodyIndex ∧
  targetNames[d.extentSlot]? = some hint.bodyExtent ∧
  field (rawAt targetParams d.indexSlot) "type" = .str (ascii "usize") ∧
  field (rawAt targetParams d.extentSlot) "type" = .str (ascii "usize") ∧
  d.incoming[d.indexSlot]? = some d.sourceIndex ∧
  d.incoming[d.extentSlot]? = some d.sourceExtent ∧
  d.addOrdinal = hint.addOrdinal ∧ d.addOrdinal < ops.length ∧
  d.literalOrdinal < d.addOrdinal ∧
  field add "args" = .arr [.str hint.bodyIndex,
    .str (bytes (field (rawAt (array (field literal "out")) 0) "name"))] ∧
  field add "attrs" = .obj [] ∧
  (field add "op" = .str (ascii "int.add.checked") ∧ d.addOp = .checked ∨
   field add "op" = .str (ascii "int.add.wrap") ∧ d.addOp = .wrapping) ∧
  (array (field add "out")).length = 1 ∧
  field (rawAt (array (field add "out")) 0) "type" = .str (ascii "usize") ∧
  field literal "op" = .str (ascii "const") ∧
  field literal "args" = .arr [] ∧
  field literal "attrs" = .obj [(ascii "value", .num 1)] ∧
  (array (field literal "out")).length = 1 ∧
  field (rawAt (array (field literal "out")) 0) "type" = .str (ascii "usize") ∧
  d.branchCondition = d.compareOutput ∧ d.indexType = .usize ∧ d.extentType = .usize ∧
  d.compareOp = .lt ∧ d.selectedArm = .thenArm ∧ d.addIndexSlot = d.indexSlot ∧
  d.addType = .usize ∧ d.literalType = .usize ∧ d.literalValue = 1

instance (raw : Raw) (hint : Hint) (d : Descriptor) : Decidable (SliceSyntaxRelation raw hint d) := by
  unfold SliceSyntaxRelation
  infer_instance

/-- Successful reconstruction requires the independently specified contract. -/
def extract (raw : Raw) (hint : Hint) : Option Descriptor :=
  let proposed := reconstruct raw hint
  if SliceSyntaxRelation raw hint proposed then some proposed else none

theorem extract_sound (raw : Raw) (hint : Hint) (d : Descriptor)
    (extracted : extract raw hint = some d) : SliceSyntaxRelation raw hint d := by
  by_cases accepted : SliceSyntaxRelation raw hint (reconstruct raw hint)
  · have same : reconstruct raw hint = d := by
      simpa [extract, accepted] using extracted
    rw [← same]
    exact accepted
  · simp [extract, accepted] at extracted

/-- Composition with the existing projection theorem. Exact byte binding and
    transport determinacy are separate certificate obligations. -/
theorem extracted_successor (raw : Raw) (hint : Hint) (d : Descriptor)
    (maximum : Nat) (env : Env)
    (extracted : extract raw hint = some d)
    (valid : Valid d) (guard : evalGuard maximum d env = some true) :
    SliceSyntaxRelation raw hint d ∧
    ∃ index extent,
      readUsize maximum env d.sourceIndex = some index ∧
      readUsize maximum env d.sourceExtent = some extent ∧
      evalSelectedStep maximum d env = some (index + 1) ∧
      index + 1 ≤ extent ∧ extent ≤ maximum ∧ index + 1 ≤ maximum := by
  exact ⟨extract_sound raw hint d extracted,
    selected_successor maximum d env valid guard⟩


end HiaCoreSyntaxSlice
