"""Copied into a per-build capsule; no private test material is copied with it."""
import json
from pathlib import Path

from hepta.pipeline import analyze


def main():
    checked = analyze(Path('candidate.hepta').read_text(), '<candidate>',
                      native=False, crate_type='staticlib')
    print(json.dumps({'ok': checked.report['ok'], 'diagnostics': checked.report['diagnostics'],
                      'rust': checked.rust}))


if __name__ == '__main__':
    main()
