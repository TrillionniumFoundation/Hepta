"""Bounded child frontend; only compiler sources and public candidate are copied."""
import json
from pathlib import Path
from hepta.ast import HeptaError
from hepta.pipeline import analyze_project

try:
    result = analyze_project(Path('candidate/main.hepta'), native=False, crate_type='rlib')
    task = next((fn for fn in result.program.functions if fn.name == 'task'), None) if result.program else None
    print(json.dumps({'ok': result.report['ok'], 'diagnostics': result.report['diagnostics'], 'rust': result.rust,
                      'entry_unsafe': bool(task and task.effects.intersection({'unsafe', 'ffi'}))}))
except (HeptaError, ValueError, OSError, RecursionError) as exc:
    print(json.dumps({'ok': False, 'diagnostics': str(exc), 'rust': None}))
