# Installed Agent resource custody

The development Python wheel and source distribution carry the eleven explicit
Agent discovery documents and the HIA scalar identity application source under
`hepta/_data/`. `setup.py` copies only the literal discovery list and the one
application source, without importing product modules. `MANIFEST.in` retains
those exact resources for an actual sdist-to-wheel build.

A source checkout uses its explicit project resource root. Installed code uses
only its package-owned resource root, never cwd, HOME, sys.prefix or a different
checkout. Missing individual or complete installed resource trees do not fall
back to a source directory. Native manifests continue to bind exact HIA source,
image and compiler identities. The native executable remains an explicitly
installed separate trusted artifact; no default manifest is selected by the
wheel build.

Worker identity includes the actual HIA scalar identity source as well as all
Python and discovery bytes. Logical identity keys are identical across source
and installation. Discovery-document drift invalidates an administrator worker
pin before service entry. Native source drift is rejected before the selected
application runs, including a warm image cache. This does not replace request
correlation, schema validation, SHA computation, authorization or persistence.

Tests build a real source distribution, then a wheel, install it outside the
checkout, compare all twelve resource payloads, and execute a real native-selected
worker under `-I -S` and an empty PATH. The removed language and foreign comparison
backends are blocked and former scalar predicates disabled. Missing/tampered
native resources, altered discovery pins and a missing complete data tree must
fail before state creation. An actual native compiler chain supplies the image;
complete interpreted result bytes precede native seed compilation.

These are scoped development and component controls. The worker, setuptools,
filesystem journal, JSON objects and operating-system transport remain host
owned. No native-only Agent delivery, general clean-machine/real-project closure,
production activation, legacy retirement or default service switch follows.

This Core-only integration restores no high-level source files, old projection
gates or compatibility distribution. The old mixed-tree qualification is not
a pass for this tree; new source/cold/installed controls are required.
