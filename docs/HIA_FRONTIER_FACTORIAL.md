# External capable-model 2x2 coding observations

`tools/qualify_hia_agent_frontier_factorial.py` connects fresh external model
responses to the existing assembly-v4 public tasks and native evaluator. It
does not change the earlier local-model protocol, results, reference answers,
mathematical oracle, matched public information, or full/patch materializer.

The registration fixes four existing authored two-file tasks and all sixteen
language/interface cells: HIA assembly and Rust, each with complete source and
exact structured edits. Every cell gets one response, the same initial public
problem and files, a 65,536-byte response limit and a 240-second observed
delivery limit. Cell order uses the existing rotation. A previous cell must
have a terminal observation before the next begins. A cell cannot be restarted
or rescored in place; missing, rejected and infrastructure outcomes remain in
the original denominator. Public acceptance precedes one terminal hidden
evaluation, whose inputs and results are not sent back to the model.

## Trust and cost scope

This adapter is deliberately distinct from the existing attested CLI/local
engine adapters. A delegated model is instructed to read only its registered
`PUBLIC_PROMPT.txt` and write only its `RESPONSE.json`. This is an instruction
boundary, not a hardened filesystem sandbox. Requested inherited-model
identity is not independent attestation of provider routing or model weights.
The adapter retains exact raw responses, source and tool hashes, input hashes,
native builds, actual public and hidden executions, and host-observed delivery
and validation wall time. It has no provider token or money receipt. Those
costs and human review time remain null, never zero.

Consequently a successful cell establishes only a finite, actually executed
coding observation. Even sixteen successful cells do not establish lower total
development cost, representative maintenance success, a reduced human review
burden, a language productivity advantage or generalization to real upstream
projects. The separate complete-module migration and cost experiments are not
quietly relabeled as model-authored work.

## Reproduction

Commit implementation changes before preparing a new cohort. Keep all outputs
outside the source checkout. Use the actual current tool paths:

```sh
python -B tools/qualify_hia_agent_frontier_factorial.py prepare \
  --output /new/outside-source/cohort --clang /actual/clang-20 --rustc /actual/rustc

python -B tools/qualify_hia_agent_frontier_factorial.py begin \
  --output /new/outside-source/cohort --cell 0
# Send only cell-00/PUBLIC_PROMPT.txt to one fresh model session.
# Retain the model's exact JSON bytes at cell-00/RESPONSE.json.
python -B tools/qualify_hia_agent_frontier_factorial.py evaluate \
  --output /new/outside-source/cohort --cell 0
# Repeat the originally registered order through cell 15, then:
python -B tools/qualify_hia_agent_frontier_factorial.py summary \
  --output /new/outside-source/cohort
```

Preparation runs the inherited positive, unchanged-source and partial-upgrade
controls using real compilers. This remains zero model requests. All admitted
native scoring uses the existing sealed executable snapshot. The evaluator
now uses the same Linux UAPI fallback values as other HIA observers when a
Python build omits its `fcntl` constant names; the actual sealing syscall and
seal readback remain mandatory, and missing or partial seals refuse execution.
An actual kernel regression checks that writes, shrinking and growth fail.

The provider catalog probe separately preserves typed `configWarning`
notifications while waiting for the actual `model/list` response. It retains
the initialization ACK, strict response inventory, bounded metadata and raw
stream. A warning cannot substitute for a catalog response or establish model
entitlement; unknown events and task/tool messages still refuse.

An independent review found and reproduced a provisional scorer bug where
source drift after a hidden pass could leave a stale `correct=true`. Every
exception now clears correctness, and summary admission additionally requires
a successful terminal status and complete positive native/public/hidden
evidence. The regression preserves both late-drift and rejected-terminal
negative controls.
