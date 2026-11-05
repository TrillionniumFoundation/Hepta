# Iteration 39 — prospective local protocol, content-supported memory

Written before the full three-seed experiment. This is a local exploratory
protocol, not an externally registered or independent acceptance study.

Base: `2140decfb47163aa93a5922795318e11f2f952bc` (Draft #512).
All scientific gates remain OPEN; production activation remains false.

## Fixed choices

- Four keys, two possible values; observed signed payload supplies key routing.
  There is no auxiliary event-time, write-flag or reset-label loss. Requested
  last-value answers are the only training labels. Exact routing and zero
  blank support are architectural assumptions, not learned perception.
- Three models, each with exactly four learned write-rate parameters:
  `protected_ctmc`, `ordinary_exponential`, `leaky_ctmc`.
- Protected rates are `x^2 * ((1-x)/2 * rates_minus + (1+x)/2 * rates_plus)`.
  The leaky control adds 0.04/s in each direction. The ordinary control has the
  same protected generator and the coordinate change `h=2p-1`.
- Model seeds 11, 23, 37. Adam 240 updates, learning rate 0.065; 64 fixed
  training streams of 28 segments; write durations 0.75–1.5s, blank durations
  0.05–2s. Same initialization, data and optimizer budget within each seed.
- Held-out ID, 128-segment overwrite and requested-key recall; irregular long
  blanks; one-key last-write recall; very short unseen writes (0.02–0.2s).
- Opposite-order two-write histories, shared blank of 1/16/64/256/4096 seconds.
  Persistent shared input noise amplitudes 0.001/0.01/0.05 for 4096 seconds.
  Opposite unseen final writes producing identical observations must remain
  at the 50% balanced information limit.
- Report **expected correctness of one sampled binary memory-state readout**.
  Hard classification of an exact floating probability is separately marked
  as a diagnostic and cannot stand in for event-state accuracy.
- Independent SciPy matrix exponential, physical segment refinement, streaming,
  causal prefix, read-only query and signed finite-difference checks; independent
  Gillespie endpoint samples for the two CTMC controls.

## Interpretation fixed before evaluation

A gain shared with the mapped ordinary control establishes only the value of
protected holding under this task grammar. It cannot establish an HX/free-
boundary advantage. Exact-zero blanks do not imply robustness to persistent
noise. Missing observations cannot be recreated. This is neither raw-token
MQAR nor a learned autonomous boundary detector, and closes no full P2 gate.
