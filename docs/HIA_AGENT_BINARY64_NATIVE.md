# Agent finite binary64 conversion

`HEPTA_HIA_AGENT_BINARY64_MANIFEST` selects trusted source-bound HIA decimal
conversion. The selection is independent of the ordinary-data JSON grammar
image. Default conversion remains unchanged, and an invalid selected image
never falls back to the hosted decimal converter. This is not service activation.

The HIA program uses integer arithmetic and three private, length-delimited
128-limb base-2^32 values. It validates complete JSON number grammar and computes
round-to-nearest, ties-to-even IEEE-754 binary64 bits. It retains the first 800
significant decimal digits and a nonzero discarded-digit bit. Every finite
binary64 rounding boundary, including the zero/subnormal and overflow boundary,
has at most 768 significant decimal digits: its exact value is a bounded odd
integer times a power of two, and a negative power becomes a power of five with
exponent at most 1075. Thus an 800-digit truncation cannot cross a rounding
boundary; a nonzero tail disambiguates an exact tie. Exponent saturation exceeds
the entire 8 MiB input digit range before range classification. No original
JSON byte ceiling, Agent node ceiling, cold deadline or Core safety gate changes.

Python still allocates buffers, loads pinned trusted code, validates custody,
and boxes returned bits as a foreign Python float. It does not calculate decimal
conversion or rounding on the selected path. General Python object graphs,
arbitrary integer values, canonical/shortest floating printing, SQLite state,
request identity and recovery remain hosted. This is not whole-native delivery
or an all-input formal refinement proof.
