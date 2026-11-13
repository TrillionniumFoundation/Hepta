# Actual CPython 3.14 parser-construction observations

This isolated diagnostic imports three exact complete files from the frozen R11 authored source: hepta/__init__.py, hepta/cli.py and hepta/hia_schema.py. It invokes the original CLI construction prefix and stops at the actual parse_args boundary. It records every reachable ordinary graph node, cycles, aliases, real color-theme identity and cached formatter fields on CPython 3.14.4, with the complete interpreter argparse and _colorize source bytes.

This is explicitly a partial source diagnostic. It does not reconstruct the product checkout, compile or execute HIA, run the original 43 CLI tests or the ten new Source controls, or supply any cold, Source, Native or whole-product qualification. Those independent controls remain required for the repaired successor.

The original R11 failure is preserved: run 43468679071/job 132034512598, unsupported authoring graph value _colorize.Argparse, before any product tests. The exact original CLI and schema bytes are checked before and after all observations. No color setting, graph field or original behavior is disabled to make this diagnostic pass. Alternate environment cases expose actual construction differences.

Only this independent harness branch is created. Product, main, audit and PR refs are unchanged.

R2 preserves the R1 actual unknown-set failure. It records that real set and exports the exact Actions interpreter as a development-tool input. Exported tool bytes are not product qualification.
