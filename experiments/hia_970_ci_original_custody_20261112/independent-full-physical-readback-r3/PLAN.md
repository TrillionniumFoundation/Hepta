# Physical readback revision 3: explicit host observation join

This new read-only revision retains both earlier actual reader HOLD results.
Revision 2 completed six phase archives and then refused a chain receipt whose
Python host had appended shared_output_observation after reading child stdout.
The old result is an audit implementation refusal, not a new product result.

A single subsequent read-only scan covered all 38 original archives and all
6,000 receipt/stdout pairs to which the original comparison applies. Exactly
204 pairs have this one additional host field; there are no other differences
after projecting it. The original producer in tools/qualify_hia_selfhost.py
adds this field after parsing and saving stdout when observe_trap_writes is set.
The complete scan source, observation, stdout and stderr are retained here.

Revision 3 removes that field from the stdout comparison only for the retained
Python child path, only after checking the actual request flag and independently
recomputing the complete observation from the actual retained output bytes and
the original request preimage (or the original 0xa5 default). The native observer
path keeps its original complete stdout comparison. All 204 host observations
must be accounted for. No other receipt keys or values are ignored.

The prior revision-2 full physical checks and the explicit 46 missing earlier
names compilation histories remain. The final status must continue to state
that complete historical invocation custody is false. Every still-retained
outer and nested physical member is read. No Hepta code is imported, no native
image is executed, and neither the original cold result nor the retained
5,400-second full-suite status is changed by this audit.

The intended exact command is:

```sh
python3 full_original_physical_audit_r3.py --archive full-zip-two-parts-r1/actual-local-readback-r1/artifact-13911977275.original.zip --selected-root container-readback-r1/inner-originals --semantic-report semantic-readback-r2/SEMANTIC-READBACK.json --difference-report phase-receipt-difference-r1.original.json --output full-physical-readback-r3 > full-physical-readback-r3.stdout.original.log 2> full-physical-readback-r3.stderr.original.log
```

The output directory is create-only. The source is parsed and published before
this invocation. The earlier 354 extracted raw copies have been released only
after independent byte equality against the unchanged original selected ZIP,
under the parent's explicit permission and confirmed absence of other readers.
Both complete original ZIPs, DIRECTORY, SELECTED, and every prior report remain.
The exact release intent and completion ledger preserve that separate action.
