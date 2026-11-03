/-!
UNCHECKED helper proof text until the pinned Lean 4.19 kernel accepts it.
Append after the exact transport portion of CoreSyntaxSlice.lean. No imports.

These are one-step equalities for the existing functions, not replacement
semantics. The f/d parameters are the precise child call arguments. No rule
resets fuel, drops a suffix, admits a numeric boundary, or supplies a fact from
Python. Concrete leaf certificates and all byte/source bindings remain required.
-/

namespace HiaCoreSyntaxSlice.Structured

/-- The child list call uses exactly f and d. -/
theorem serialize_array (f d : Nat) (items : List Raw) (output : List Nat)
    (children : serializeItems f d items = some output) :
    serializeRaw (f + 1) (d + 1) (.arr items) =
      some (91 :: (output ++ [93])) := by
  simp [serializeRaw, children]

theorem serialize_object (f d : Nat) (fields : List (List Nat × Raw))
    (output : List Nat) (ordered : orderedFields fields = true)
    (children : serializeFields f d fields = some output) :
    serializeRaw (f + 1) (d + 1) (.obj fields) =
      some (123 :: (output ++ [125])) := by
  simp [serializeRaw, ordered, children]

theorem serialize_items_nil (f d : Nat) :
    serializeItems f d [] = some [] := by
  cases f <;> rfl

theorem serialize_items_single (f d : Nat) (value : Raw) (output : List Nat)
    (child : serializeRaw f d value = some output) :
    serializeItems (f + 1) d [value] = some output := by
  simp [serializeItems, child]

theorem serialize_items_cons (f d : Nat) (value next : Raw) (rest : List Raw)
    (output suffix : List Nat)
    (child : serializeRaw f d value = some output)
    (children : serializeItems f d (next :: rest) = some suffix) :
    serializeItems (f + 1) d (value :: next :: rest) =
      some (output ++ (44 :: suffix)) := by
  simp [serializeItems, child, children]

theorem serialize_fields_nil (f d : Nat) :
    serializeFields f d [] = some [] := by
  cases f <;> rfl

theorem serialize_fields_single (f d : Nat) (key : List Nat) (value : Raw)
    (output : List Nat) (keyDomain : stringBytes key = true)
    (child : serializeRaw f d value = some output) :
    serializeFields (f + 1) d [(key, value)] =
      some (34 :: (key ++ (34 :: 58 :: output))) := by
  simp [serializeFields, keyDomain, child]

theorem serialize_fields_cons (f d : Nat) (key : List Nat) (value : Raw)
    (next : List Nat × Raw) (rest : List (List Nat × Raw))
    (output suffix : List Nat) (keyDomain : stringBytes key = true)
    (child : serializeRaw f d value = some output)
    (children : serializeFields f d (next :: rest) = some suffix) :
    serializeFields (f + 1) d ((key, value) :: next :: rest) =
      some ((34 :: (key ++ (34 :: 58 :: output))) ++ (44 :: suffix)) := by
  simp [serializeFields, keyDomain, child, children]

theorem serialize_string (f d : Nat) (value : List Nat)
    (domain : stringBytes value = true) :
    serializeRaw (f + 1) (d + 1) (.str value) =
      some (34 :: (value ++ [34])) := by
  simp [serializeRaw, domain]

theorem serialize_number (f d value : Nat) (output : List Nat)
    (digits : decimal value = some output) :
    serializeRaw (f + 1) (d + 1) (.num value) = some output := by
  simp [serializeRaw, digits]

/-- Exclude the earlier empty-array pattern before applying the list rule. -/
theorem parse_array (f d : Nat) (input tail : List Nat) (items : List Raw)
    (notEmptyClose : input.head? ≠ some 93)
    (children : parseItems f d input = some (items, tail)) :
    parseRaw (f + 1) (d + 1) (91 :: input) = some (.arr items, tail) := by
  cases input with
  | nil => simp [parseRaw, children]
  | cons first rest =>
    by_cases same : first = 93
    · subst first
      exact False.elim (notEmptyClose rfl)
    · simp [parseRaw, same, children]

/-- The explicit opening quote excludes the earlier empty-object pattern. -/
theorem parse_object (f d : Nat) (input tail : List Nat)
    (fields : List (List Nat × Raw))
    (ordered : orderedFields fields = true)
    (children : parseFields f d (34 :: input) = some (fields, tail)) :
    parseRaw (f + 1) (d + 1) (123 :: 34 :: input) =
      some (.obj fields, tail) := by
  simp [parseRaw, children, ordered]

theorem parse_items_last (f d : Nat) (input tail : List Nat) (value : Raw)
    (child : parseRaw f d input = some (value, 93 :: tail)) :
    parseItems (f + 1) d input = some ([value], tail) := by
  simp [parseItems, child]

theorem parse_items_cons (f d : Nat) (input middle tail : List Nat)
    (value : Raw) (rest : List Raw)
    (child : parseRaw f d input = some (value, 44 :: middle))
    (children : parseItems f d middle = some (rest, tail)) :
    parseItems (f + 1) d input = some (value :: rest, tail) := by
  simp [parseItems, child, children]

theorem parse_fields_last (f d : Nat) (keyInput key valueInput tail : List Nat)
    (value : Raw)
    (keyRead : parseStringTail keyInput [] = some (key, 58 :: valueInput))
    (child : parseRaw f d valueInput = some (value, 125 :: tail)) :
    parseFields (f + 1) d (34 :: keyInput) = some ([(key, value)], tail) := by
  simp [parseFields, keyRead, child]

theorem parse_fields_cons (f d : Nat)
    (keyInput key valueInput middle tail : List Nat)
    (value : Raw) (rest : List (List Nat × Raw))
    (keyRead : parseStringTail keyInput [] = some (key, 58 :: valueInput))
    (child : parseRaw f d valueInput = some (value, 44 :: middle))
    (children : parseFields f d middle = some (rest, tail)) :
    parseFields (f + 1) d (34 :: keyInput) = some ((key, value) :: rest, tail) := by
  simp [parseFields, keyRead, child, children]

theorem parse_empty_array (f d : Nat) (tail : List Nat) :
    parseRaw (f + 1) (d + 1) (91 :: 93 :: tail) = some (.arr [], tail) := by
  rfl

theorem parse_empty_object (f d : Nat) (tail : List Nat) :
    parseRaw (f + 1) (d + 1) (123 :: 125 :: tail) = some (.obj [], tail) := by
  rfl

theorem parse_string (f d : Nat) (input value tail : List Nat)
    (characters : parseStringTail input [] = some (value, tail)) :
    parseRaw (f + 1) (d + 1) (34 :: input) = some (.str value, tail) := by
  simp [parseRaw, characters]

/-- Reading a valid quoted prefix does not inspect the suffix after its quote.
    The accumulator form supports induction without assumptions about that suffix. -/
theorem parse_string_tail_prefix (segment suffix acc : List Nat) :
    stringBytes segment = true →
    parseStringTail (segment ++ (34 :: suffix)) acc =
      some (acc.reverse ++ segment, suffix) := by
  induction segment generalizing acc with
  | nil =>
    intro _domain
    simp [parseStringTail]
  | cons first rest previous =>
    intro domain
    have parts : stringByte first = true ∧ stringBytes rest = true := by
      simpa only [stringBytes, Bool.and_eq_true] using domain
    have allowed : 32 ≤ first ∧ first ≤ 126 ∧ first ≠ 34 ∧ first ≠ 92 := by
      simpa [stringByte] using parts.1
    have notQuote : first ≠ 34 := allowed.2.2.1
    have remaining := previous (first :: acc) parts.2
    simpa [parseStringTail, notQuote, parts.1, List.reverse_cons, List.append_assoc]
      using remaining

/-- A key packet supplies its checked domain and this symbolic-tail equation. -/
theorem parse_key_prefix (key tail : List Nat) (domain : stringBytes key = true) :
    parseStringTail (key ++ (34 :: 58 :: tail)) [] = some (key, 58 :: tail) := by
  simpa using parse_string_tail_prefix key (58 :: tail) [] domain

/-
Leaf-generation contract (not an extra theorem or assumed fact):

For nonnumeric complete leaf bytes b and Raw r at exact F,D, prove
  ∀ tail, parseRaw F D (b ++ tail) = some (r, tail).
For a numeric leaf use its actual structural delimiter c ∈ {44,93,125}:
  ∀ tail, parseRaw F D (b ++ (c :: tail)) = some (r, c :: tail).
For a key k, prove stringBytes k = true and
  ∀ tail, parseStringTail (k ++ (34 :: 58 :: tail)) [] = some (k, 58 :: tail).

These are closed small-prefix proofs after introducing the symbolic tail.
Unfold only the local leaf/key definitions. Never replace the numeric form with
an arbitrary-suffix extension rule: decimal bytes [49] followed by [50] parse
as 12. Root composition must still return the exact empty suffix.
-/

/-- Decimal digits cannot be split by an arbitrary suffix-extension rule. -/
theorem reject_numeric_split :
    ¬ (parseRaw 2 2 [49, 50] = some (.num 1, [50])) := by
  intro claim
  change some (Raw.num 12, ([] : List Nat)) = some (Raw.num 1, [50]) at claim
  have tails : ([] : List Nat) = [50] := congrArg Prod.snd (Option.some.inj claim)
  cases tails

/-- A colon cannot replace the comma between two array items. -/
theorem reject_wrong_separator :
    ¬ (parseRaw 8 4 [91, 49, 58, 50, 93] =
      some (.arr [.num 1, .num 2], [])) := by
  decide +kernel

/-- An object close cannot terminate an array. -/
theorem reject_wrong_closing :
    ¬ (parseRaw 8 4 [91, 49, 125] = some (.arr [.num 1], [])) := by
  decide +kernel

/-- A successful prefix parse does not authorize dropping remaining bytes. -/
theorem reject_trailing_bytes :
    ¬ (parseRaw 2 2 [91, 93, 48] = some (.arr [], [])) ∧
    ¬ (decode [91, 93, 48] = some (.arr [])) := by
  constructor
  · intro claim
    change some (Raw.arr [], [48]) = some (Raw.arr [], ([] : List Nat)) at claim
    have tails : [48] = ([] : List Nat) := congrArg Prod.snd (Option.some.inj claim)
    cases tails
  · intro claim
    change none = some (Raw.arr []) at claim
    cases claim

theorem reject_insufficient_fuel :
    ¬ (parseRaw 0 2 [48] = some (.num 0, [])) := by
  decide +kernel

theorem reject_insufficient_depth :
    ¬ (parseRaw 2 0 [48] = some (.num 0, [])) := by
  decide +kernel

/-- Fixed Raw cannot justify a different literal byte inside its encoding. -/
theorem reject_changed_leaf_byte :
    ¬ (serializeRaw 2 2 (.str [97]) = some [34, 98, 34]) := by
  decide +kernel

/-- Both distinct sufficient fuel values succeed. Fuel inequality alone is
    not a sound negative-control criterion. -/
theorem reject_distinct_sufficient_fuel_failure :
    ¬ (parseRaw 1 1 [48] ≠ some (.num 0, []) ∨
       parseRaw 2 1 [48] ≠ some (.num 0, [])) := by
  intro failure
  cases failure with
  | inl rejected => exact rejected rfl
  | inr rejected => exact rejected rfl

end HiaCoreSyntaxSlice.Structured
