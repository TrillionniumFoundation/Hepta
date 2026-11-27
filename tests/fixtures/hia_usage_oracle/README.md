# Original Runtime usage and large diagnostic observations

Original source: ae1c7ea593da45f7299c692a2acd44605c35be09. The complete unmodified production source/project is retained in the sibling history and archive oracle fixtures. The usage extension runs that same original archive observer; the schema-only observer imports the same production MCP module.

`extended-cases.json` and `extended-observations.json` preserve five unique-name projection boundary fixtures, ten queries repeated in two fresh original processes. `diagnostics.json` and `usage-diagnostic.json` pin full original diagnostic output, with no shortened expected message. `usage-schema.json` is the observed original schema. `retained-fixture-failure.json` retains the initial invalid fixture failure instead of counting it as success.

`raw-observations-v1.tar.gz` contains the complete compressed original inputs/stdout/error objects, distinct-boundary stdout/stderr, and original schema observer Cargo files/source/build log. `raw-observations-v1.manifest.json` pins all 45 archive members and the archive bytes. Empty original stdout in the rejected initial fixture is retained as an observation, not a passing usage result.
