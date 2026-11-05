# Current baseline status

The detailed result and reproduction instructions are in `BASELINE.md`.

- Official OpenVPN v2.7.8 source archive and all 545 regular source files verified.
- Clang20 original application, separate `-pg` original profile build, and exact final2 HIA object application links completed.
- Six actual C/HIA application crypto self-tests passed.
- Nine null-device loopback session verdicts passed after independent observer correction; current authority: `baseline-application/integration-run-final2/baseline-reviewed-v2.json`.
- Positive mixed sessions prove all four HIA exports execute and ABI failures are zero.
- Actual encrypted UDP replay/tag-corruption probes passed in both mixed orientations.
- Original raw logs, prior reports, corrected derived reports and exact original observer are retained.
- Real TUN/DCO and end-to-end fair performance remain unqualified; actual read-only preflight receipts record absent capabilities/TUN and disabled kernel CONFIG_OVPN.
- Private test keys and certificates remain only in scratch; repository evidence contains logs and receipts.
