# Privilege profile function-shape validation: fail closed

The experimental HIA Core `kernel-tlb.v1` profile previously checked
`fn["effects"]` **before** `_function_shape` had validated the container.
Replacing one function with a JSON array or scalar escaped as a raw Python
`TypeError` instead of the stable `HIAProgramRejected` failure class. This
was observed independently in the original Core-only CI for the exact
parent `23ecee88474169539dcb655bf38ecabc9488a7af` (run 45239696846; native job 137920688414).

The change moves the existing complete function-shape validation before the
profile-specific atomic and privilege admission. No effects, syntax,
resources or privilege operations are widened, and the historical Core v1-v8
and other negative controls retain their original meaning.

Independent targeted tests include adversarial function containers, effects
of incorrect types, repeated effects, v8 privilege refusal, existing complete
wrong-container fuzz and the native Core INVLPG tests. The attack must be
rejected as HIAProgramRejected; generic interpreter errors cannot count as
successful kernel admission. The full Core-only run on the parent also showed
six unrelated closed-source/reference equivalence assertions (source job
137920688771), which remain **OPEN** and are not suppressed or reclassified.

This is a verifier error-path repair, not CPL0 authority, resource ownership,
`selfhost_elf` privilege lowering, a Linux kernel implementation or full
acceptance. Do not merge to upstream main while the remaining Core-only
controls and kernel hardware obligations are open.
