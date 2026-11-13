"""Verify the new harness against full independent Git tree readbacks."""
from hashlib import sha1, sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORK = HERE.parent


def read(path):
    return json.loads(path.read_bytes())


def main():
    observed = read(HERE / 'NEW-HARNESS-TREE.json')
    previous = read(HERE / 'OLD-HARNESS-TREE.json')
    commit = read(HERE / 'NEW-HARNESS-COMMIT.json')
    frozen = read(WORK / 'v83-native-receipt-joint-publication-r1/HARNESS-FINAL-MAP.json')
    rows = {row['path']: row for row in observed['tree'] if row['type'] == 'blob'}
    old = {row['path']: row for row in previous['tree'] if row['type'] == 'blob'}
    assert not observed.get('truncated') and not previous.get('truncated')
    assert len(rows) == len(frozen) == 25
    assert set(rows) == set(frozen)
    for name, row in frozen.items():
        actual = rows[name]
        assert (actual['sha'], actual['size'], actual['mode']) == (row['blob'], row['bytes'], row['mode'])
    python = sorted(name for name in rows if name.endswith('.py'))
    assert python
    assert all(name in old and (rows[name]['sha'], rows[name]['mode']) ==
               (old[name]['sha'], old[name]['mode']) for name in python)
    assert commit['sha'] == 'eb39aaaeeb8cb55d478e7c7045ccf67d4a4ca22a'
    assert commit['tree']['sha'] == observed['sha'] == 'a703dbaa603666f503a70bda395077d8409c7274'
    assert [p['sha'] for p in commit['parents']] == ['dd5357a85e4f8812d1d16ad50c5d771da9d2d68a']
    result = {
        'schema': 'hia.root-independent-harness-readback.v83.r1',
        'commit': commit['sha'], 'tree': observed['sha'],
        'parent': commit['parents'][0]['sha'], 'source_files': len(rows),
        'all_paths_modes_sizes_git_identities_equal_frozen_map': True,
        'unchanged_python_harness_paths': python,
        'all_python_harness_bytes_unchanged_from_previous': True,
        'changed_or_added_paths': sorted(n for n in rows if n not in old or rows[n]['sha'] != old[n]['sha']),
        'removed_paths': sorted(set(old) - set(rows)),
        'source_commit': '4925e72d9f51f4dc3e8f4d1d2a7b24cce2f5772b',
        'source_tree': 'bc276bc832a7d6f04a21d63f55645859b75a01ee',
        'compile_child_seconds': 20, 'group_seconds': 1800,
        'all_973_source_methods_executed_by_this_readback': False,
        'current_source_cold': False, 'whole_native': False,
    }
    (HERE / 'NEW-HARNESS-ROOT-VERIFIED.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
