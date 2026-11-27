"""Fixed complete caller revisions for scoped source admissions.

Only physical whole-file identities listed here can enter an existing source
relation. The ordinary, Journal, context and direct method inventories remain
the caller's immutable authority.
"""
from hashlib import sha256
import json
from pathlib import Path

TOOLS = 'tests/test_hia_agent_native_tools.py'
MACHINE = 'tests/test_hia_agent_native_machine_validation.py'
PROOF = 'tests/test_hia_agent_native_proof_contract.py'
JOURNAL = 'tests/test_hia_agent_journal_native.py'
CONTEXT = 'tests/test_hia_service_context_native.py'
CURRENT = {
    TOOLS: (
        {'bytes': 47052, 'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70'},
        {'bytes': 47052, 'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'}),
    MACHINE: ({'bytes': 23623, 'sha256': '0c03b958462d2d2b8f7304b52bf419a9832037c3db4e51fa940053176fad0cbb'},),
    PROOF: ({'bytes': 24953, 'sha256': 'cb958dfdac9ae83b421a55c34109247dbda64af85171525969da55ad3a6d1f03'},),
    JOURNAL: ({'bytes': 48904, 'sha256': '97dec702780d755cc5c2ffa59e5a798c98dc48a17735f9b8983bfdb610d2f263'},),
    CONTEXT: ({'bytes': 35403, 'sha256': '94bba1ba99cfeb29baa9eb34072514803af288a11d964f950c46bea431e92c1b'},),
}
ORIGINAL = {
    TOOLS: {'bytes': 45385, 'sha256': 'c7a3b2b486e55a600ddd5e691729e8cddc6acd5935e5aad337e27c1f20be856a'},
    MACHINE: {'bytes': 22171, 'sha256': 'f8e60f923d5b462c3a98f11cb00b0e5a65fb9bc1db2a17a03d55933eb944aada'},
    PROOF: {'bytes': 23396, 'sha256': '0a9a3feb8444d33ec97afb4259a847cd6b738fc3a77cf07980b4772096c112a6'},
    JOURNAL: {'bytes': 48482, 'sha256': 'a0a6e63291eb76ee84787b432c56eaa32bd1181b762f9593532c059d4a665077'},
    CONTEXT: {'bytes': 35307, 'sha256': 'db7651b17a26b2606cb4c8c556b222a89f9d42b1e21b9bc97380b6f1dfdb3f9c'},
}
REVIEWED = {**ORIGINAL,
    TOOLS: {'bytes': 46518, 'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355'},
    JOURNAL: {'bytes': 48798, 'sha256': '7d5cebde72523ade809346a30916a48611e18a157230b4f2f6129c0d16b8715c'},
}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
RELATIONS = 'tests/fixtures/hia_frozen_component_source_relations.json'
RELATIONS_PIN = {'bytes': 18122, 'sha256': 'acd25ffa7c6bea270fcb56cde74a60d7993899cb2e77173b97a814a3bcce14b9'}
INSTALLED = 'tests/fixtures/hia_installed_distribution_sources.json'
INSTALLED_PIN = {'bytes': 104444, 'sha256': '6b81c5c6f611e4b75fc3228936a32b1753ca33649706cda37bbae6007f69001d'}
RESULT_HELPER = 'tools/hia_current_caller_source_history.py'
RESULT_HELPER_PIN = {'bytes': 3838, 'sha256': '9f773647bacc0a59f8ddff7b45e27f9d5474bb96a7f2368fa7e18a2a98141558'}


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('scoped caller history requires exact physical bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def predecessor(root, name, raw, expected, *, take=Path.read_bytes):
    if pin(raw) not in CURRENT.get(name, ()):
        return raw, None
    if expected != ORIGINAL[name]:
        raise ValueError('scoped caller expected identity is not the fixed original')
    root, saved = Path(root), {}
    def capture(path):
        path = Path(path)
        relative = path.relative_to(root).as_posix()
        if any(part in ('', '.', '..', '.git') for part in relative.split('/')):
            raise ValueError('scoped caller history escaped its selected root')
        value = take(path)
        if relative in saved and saved[relative] != value:
            raise ValueError('scoped caller history input changed')
        saved[relative] = value
        return value
    if capture(root / name) != raw:
        raise ValueError('scoped caller history input is not the physical source')
    engine = capture(root / ENGINE)
    if pin(engine) != ENGINE_PIN:
        raise ValueError('scoped caller inverse engine differs')
    from tools import hia_frozen_component_sources as history
    if Path(history.__file__).read_bytes() != engine:
        raise ValueError('scoped caller imported another inverse engine')
    result_review = None
    selected = raw
    if name == TOOLS and pin(raw) == CURRENT[TOOLS][1]:
        helper = capture(root / RESULT_HELPER)
        if pin(helper) != RESULT_HELPER_PIN:
            raise ValueError('scoped six-result source helper differs')
        from tools import hia_current_caller_source_history as result_history
        if Path(result_history.__file__).read_bytes() != helper:
            raise ValueError('scoped caller imported another result history helper')
        selected, result_review = result_history.result_predecessor(
            root, name, raw, take=capture)
    if name in (JOURNAL, CONTEXT):
        frozen = capture(root / INSTALLED)
        if pin(frozen) != INSTALLED_PIN:
            raise ValueError('scoped installed source relation changed')
        record = json.loads(frozen)['files'][name]
        if record['current'] != pin(raw) or record['original'] != REVIEWED[name]:
            raise ValueError('scoped installed whole source identity differs')
        hunks, displacement = [], 0
        for change in record['splices']:
            if type(change['offset']) is not int:
                raise ValueError('scoped installed splice offset is not an integer')
            old, new = change['before'].encode(), change['after'].encode()
            hunks.append({'old_offset': change['offset'],
                'new_offset': change['offset'] + displacement,
                'old_hex': old.hex(), 'new_hex': new.hex()})
            displacement += len(new) - len(old)
        reviewed = history.history_inverse(raw, {
            'old_bytes': record['original']['bytes'],
            'old_sha256': record['original']['sha256'],
            'new_bytes': record['current']['bytes'],
            'new_sha256': record['current']['sha256'], 'hunks': hunks}, REVIEWED[name])
    else:
        frozen = capture(root / RELATIONS)
        if pin(frozen) != RELATIONS_PIN:
            raise ValueError('scoped caller complete source relation changed')
        reviewed = history.reviewed_source(root, name, selected, take=capture)
    if pin(reviewed) != REVIEWED[name]:
        raise ValueError('scoped caller did not restore its whole reviewed source')
    for path, data in saved.items():
        if take(root / path) != data:
            raise ValueError('scoped caller physical source changed at terminal reread')
    return reviewed, {
        'schema': 'hepta.hia.scoped-caller-source-review.v1',
        'path': name, 'physical': pin(raw), 'reviewed_predecessor': pin(reviewed),
        'original': dict(expected), 'captured_files': {
            path: pin(data) for path, data in saved.items()},
        **({'native_result_source_history': result_review} if result_review is not None else {}),
        'complete_source_inverse_verified': True,
        'physical_capture_rewritten': False, 'prior_projection_is_physical_source': False,
        'terminal_reread_identical': True, 'whole_native_delivery_qualified': False,
    }
