/-!
Symbolic composition equalities for the existing transport functions.
Append after StructuredTransport.lean; no imports or new axioms.
The list rewrites are checked once with abstract byte lists, before concrete
whole-document terms are substituted. Every concrete child certificate remains
an explicit premise. These declarations do not evaluate or trust Python data.
-/
namespace HiaCoreSyntaxSlice.Shared

theorem serialize_fields_single_packet (f d : Nat) (key : List Nat) (value : Raw)
    (output packet : List Nat)
    (packetShape : packet = 34 :: (key ++ [34, 58]))
    (keyDomain : stringBytes key = true)
    (child : serializeRaw f d value = some output) :
    serializeFields (f + 1) d [(key, value)] = some (packet ++ output) := by
  simpa only [packetShape, List.append_assoc, List.cons_append, List.nil_append,
    List.append_nil] using
    (Structured.serialize_fields_single f d key value output keyDomain child)

theorem serialize_fields_cons_packet (f d : Nat) (key : List Nat) (value : Raw)
    (next : List Nat × Raw) (rest : List (List Nat × Raw))
    (output suffix packet : List Nat)
    (packetShape : packet = 34 :: (key ++ [34, 58]))
    (keyDomain : stringBytes key = true)
    (child : serializeRaw f d value = some output)
    (children : serializeFields f d (next :: rest) = some suffix) :
    serializeFields (f + 1) d ((key, value) :: next :: rest) =
      some ((packet ++ output) ++ (44 :: suffix)) := by
  simpa only [packetShape, List.append_assoc, List.cons_append, List.nil_append,
    List.append_nil] using
    (Structured.serialize_fields_cons f d key value next rest output suffix
      keyDomain child children)

theorem parse_fields_last_packet (f d : Nat) (key : List Nat) (value : Raw)
    (output packet tail : List Nat)
    (packetShape : packet = 34 :: (key ++ [34, 58]))
    (keyRead : parseStringTail (key ++ (34 :: 58 :: (output ++ (125 :: tail)))) [] =
      some (key, 58 :: (output ++ (125 :: tail))))
    (child : parseRaw f d (output ++ (125 :: tail)) = some (value, 125 :: tail)) :
    parseFields (f + 1) d ((packet ++ output) ++ (125 :: tail)) =
      some ([(key, value)], tail) := by
  simpa only [packetShape, List.append_assoc, List.cons_append, List.nil_append,
    List.append_nil] using
    (Structured.parse_fields_last f d
      (key ++ (34 :: 58 :: (output ++ (125 :: tail)))) key
      (output ++ (125 :: tail)) tail value keyRead child)

theorem parse_fields_cons_packet (f d : Nat) (key : List Nat) (value : Raw)
    (rest : List (List Nat × Raw)) (output suffix packet tail : List Nat)
    (packetShape : packet = 34 :: (key ++ [34, 58]))
    (keyRead : parseStringTail
      (key ++ (34 :: 58 :: (output ++ (44 :: (suffix ++ (125 :: tail)))))) [] =
      some (key, 58 :: (output ++ (44 :: (suffix ++ (125 :: tail))))))
    (child : parseRaw f d (output ++ (44 :: (suffix ++ (125 :: tail)))) =
      some (value, 44 :: (suffix ++ (125 :: tail))))
    (children : parseFields f d (suffix ++ (125 :: tail)) = some (rest, tail)) :
    parseFields (f + 1) d (((packet ++ output) ++ (44 :: suffix)) ++ (125 :: tail)) =
      some ((key, value) :: rest, tail) := by
  simpa only [packetShape, List.append_assoc, List.cons_append, List.nil_append,
    List.append_nil] using
    (Structured.parse_fields_cons f d
      (key ++ (34 :: 58 :: (output ++ (44 :: (suffix ++ (125 :: tail)))))) key
      (output ++ (44 :: (suffix ++ (125 :: tail)))) (suffix ++ (125 :: tail))
      tail value rest keyRead child children)

theorem parse_items_cons_bytes (f d : Nat) (value : Raw) (rest : List Raw)
    (output suffix tail : List Nat)
    (child : parseRaw f d (output ++ (44 :: (suffix ++ (93 :: tail)))) =
      some (value, 44 :: (suffix ++ (93 :: tail))))
    (children : parseItems f d (suffix ++ (93 :: tail)) = some (rest, tail)) :
    parseItems (f + 1) d ((output ++ (44 :: suffix)) ++ (93 :: tail)) =
      some (value :: rest, tail) := by
  simpa only [List.append_assoc, List.cons_append] using
    (Structured.parse_items_cons f d (output ++ (44 :: (suffix ++ (93 :: tail))))
      (suffix ++ (93 :: tail)) tail value rest child children)

theorem parse_array_bytes (f d : Nat) (items : List Raw) (body tail : List Nat)
    (notEmptyClose : (body ++ (93 :: tail)).head? ≠ some 93)
    (children : parseItems f d (body ++ (93 :: tail)) = some (items, tail)) :
    parseRaw (f + 1) (d + 1) ((91 :: (body ++ [93])) ++ tail) =
      some (.arr items, tail) := by
  simpa only [List.append_assoc, List.cons_append, List.nil_append] using
    (Structured.parse_array f d (body ++ (93 :: tail)) tail items notEmptyClose children)

theorem parse_object_bytes (f d : Nat) (fields : List (List Nat × Raw))
    (body tail : List Nat) (head : body.head? = some 34)
    (ordered : orderedFields fields = true)
    (children : parseFields f d (body ++ (125 :: tail)) = some (fields, tail)) :
    parseRaw (f + 1) (d + 1) ((123 :: (body ++ [125])) ++ tail) =
      some (.obj fields, tail) := by
  cases body with
  | nil => cases head
  | cons first rest =>
    have same : first = 34 := Option.some.inj head
    subst first
    simpa only [List.append_assoc, List.cons_append, List.nil_append] using
      (Structured.parse_object f d (rest ++ (125 :: tail)) tail fields ordered
        (by simpa only [List.cons_append] using children))

theorem parse_root (f d : Nat) (raw : Raw) (bytes : List Nat)
    (parsed : ∀ tail, parseRaw f d (bytes ++ tail) = some (raw, tail)) :
    parseRaw f d bytes = some (raw, []) := by
  simpa only [List.append_nil] using parsed []

theorem serialize_string_rebase (f d g e : Nat) (value output : List Nat)
    (first : serializeRaw (f + 1) (d + 1) (.str value) = some output) :
    serializeRaw (g + 1) (e + 1) (.str value) = some output := by
  exact first

theorem parse_string_rebase (f d g e : Nat) (value input : List Nat)
    (first : ∀ tail, parseRaw (f + 1) (d + 1) (34 :: (input ++ tail)) =
      some (.str value, tail)) :
    ∀ tail, parseRaw (g + 1) (e + 1) (34 :: (input ++ tail)) =
      some (.str value, tail) := by
  exact first

theorem parse_string_rebase_bound (f d g e : Nat) (raw nextRaw : Raw)
    (bytes nextBytes input : List Nat)
    (shape : bytes = 34 :: input) (sameBytes : nextBytes = bytes)
    (sameRaw : nextRaw = raw)
    (first : ∀ tail, parseRaw (f + 1) (d + 1) (bytes ++ tail) = some (raw, tail)) :
    ∀ tail, parseRaw (g + 1) (e + 1) (nextBytes ++ tail) = some (nextRaw, tail) := by
  subst nextRaw
  subst nextBytes
  subst bytes
  exact first

end HiaCoreSyntaxSlice.Shared
