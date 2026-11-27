# Native integer-token agreement

The development reader previously decoded JSON `-0` to the ordinary integer zero.
The native HIA `integer_value` reader rejects that signed spelling in unsigned
resource counters and phase return codes. This allowed 62 mutated control reports
through the development gate: cleanup elapsed time, the pending-archive peak, and
each of the 60 phase return codes.

The repair preserves the spelling only during native-v2 admission. Those unsigned
fields reject it. The top-level return code retains the original HIA `zero_integer`
behavior accepting both `0` and `-0`. Unused JSON extensions and the default hosted
JSON reader retain their existing behavior. Floating-point zero, booleans, null,
and quoted zero remain invalid integer results.

The complete component, release-contract and native-authority scopes pass the
strict unittest gate: **31 methods, zero failures, errors or skips**. The retained
before log contains the 62 reproduced failed rejection controls.

The exact original `integer_value`, `zero_integer` and five access helpers were
independently compiled by the four pinned native seed roots. Twelve actual machine
code calls confirmed zero, signed zero, negative, fractional/exponent, empty and
u64 overflow boundaries. The extracted functions' AST commitment is identical to
the publication parent's functions. The observer source, flat image, construction
records and full observations are retained here; `observe_native_integers.py`
reproduces the bounded component observation.

These results qualify the admission repair and the stated token-reader component.
Full cold execution, native release, installation and old-stack retirement remain
separate requirements. The original 60 phases and 180+3 second limits are unchanged.
