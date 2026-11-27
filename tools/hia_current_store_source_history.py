"""Compose current physical Store inputs with the retained frozen source reader.

The original reader and both prior fixtures remain immutable. Its predecessor
view is explicit data; captures and complete_current always describe actual
files from the selected repository.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tools import hia_frozen_component_sources as frozen

ROOT = Path(__file__).resolve().parents[1]
SELF = 'tools/hia_current_store_source_history.py'
WINDOW_HELPER = 'tools/hia_evaluation_window_history.py'
WINDOW_HELPER_PIN = {
    'bytes': 8876, 'sha256': '08054cf59af6e93453fc370d08c64d1b14e9072012f69652cfae747083346cfa',
}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {
    'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774',
}
WINDOW_CURRENT = {
    'hepta/hia_agent_service.py': {
        'bytes': 268730, 'sha256': '353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1'},
    'hepta/hia_evaluation_native.py': {
        'bytes': 47978, 'sha256': 'f9b25023b393f7b621b515b9b7f481a992715f15a386bf8c2457e2eb3136a73d'},
    'tests/test_hia_evaluation_native.py': {
        'bytes': 50437, 'sha256': '333abf8107aec87e42002c0a2f0218aeacdf9837642e443563f64272d6dc5083'},
}
UNCHANGED = {
    name: dict(identity) for name, identity in frozen.CURRENT.items()
    if name not in WINDOW_CURRENT
}
COLD_HELPER = 'tools/hia_evaluation_cold_source_history.py'
COLD_HELPER_PIN = {
    'bytes': 8539, 'sha256': 'd3d1375b2fcd4ab670cb7a2611d36077c9a31acd9b0d2290c8bc482d6077d91c',
}
COLD_FIXTURE = 'tests/fixtures/hia_evaluation_native_cold_history_v1.json'
COLD_CURRENT = {**deepcopy(WINDOW_CURRENT), 'tests/test_hia_evaluation_native.py': {
    'bytes': 50368, 'sha256': '8e55e6c0adda8629c5c484173262b63f726c727b2eeefbaf4926622e59a6cec0'}}
WINDOW_PHYSICAL_CURRENT = {**deepcopy(frozen.CURRENT), **deepcopy(WINDOW_CURRENT)}
PHYSICAL_CURRENT = {**deepcopy(frozen.CURRENT), **deepcopy(COLD_CURRENT)}
NATIVE_TOOLS = 'tests/test_hia_agent_native_tools.py'
NATIVE_TOOLS_CURRENT = {
    'bytes': 47052, 'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2',
}
CALLER_HELPER = 'tools/hia_current_caller_source_history.py'
CALLER_HELPER_PIN = {
    'bytes': 3838, 'sha256': '9f773647bacc0a59f8ddff7b45e27f9d5474bb96a7f2368fa7e18a2a98141558',
}
SCHEMA = 'hepta.hia.current-store-source-composition-review.v1'


def pin(raw):
    return frozen.history_pin(raw)


def _view(captured, root, take):
    root = ROOT if root is None else Path(root)
    source, saved = dict(captured), {}

    def capture(path):
        path = Path(path)
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('current Store source read escaped the selected root') from error
        if name in ('', '.') or any(part in ('', '.', '..', '.git') for part in name.split('/')):
            raise ValueError('current Store source path is not canonical')
        raw = take(path)
        pin(raw)
        if name in saved and saved[name] != raw:
            raise ValueError('current Store physical source changed between reads: ' + name)
        saved[name] = raw
        return raw

    use_window = any(name in source and pin(source[name]) == identity
                     for name, identity in (*WINDOW_CURRENT.items(), *COLD_CURRENT.items()))
    if not use_window and any(name in source and pin(source[name]) == identity
                              for name, identity in UNCHANGED.items()):
        # The older reader also requires the complete group for these members.
        # Reading this existing production member adds no new fixture authority.
        service = capture(root / 'hepta/hia_agent_service.py')
        use_window = pin(service) == WINDOW_CURRENT['hepta/hia_agent_service.py']
    if not use_window:
        return source, None, saved, capture, root

    self_raw = capture(root / SELF)
    helper = capture(root / WINDOW_HELPER)
    engine = capture(root / ENGINE)
    if (Path(__file__).read_bytes() != self_raw or pin(helper) != WINDOW_HELPER_PIN
            or pin(engine) != ENGINE_PIN or Path(frozen.__file__).read_bytes() != engine):
        raise ValueError('current Store source-history readers differ')
    from tools import hia_evaluation_window_history as window
    if Path(window.__file__).read_bytes() != helper:
        raise ValueError('current Store imported another evaluation source reader')
    affected = {name: raw for name, raw in source.items() if name in frozen.CURRENT}
    cold_history = None
    try:
        selected_take = capture
        evaluation = capture(root / frozen.EVALUATION_TEST)
        if pin(evaluation) == COLD_CURRENT[frozen.EVALUATION_TEST]:
            cold_raw = capture(root / COLD_HELPER)
            if pin(cold_raw) != COLD_HELPER_PIN:
                raise ValueError('current Store evaluation cold reader differs')
            from tools import hia_evaluation_cold_source_history as cold
            if Path(cold.__file__).read_bytes() != cold_raw:
                raise ValueError('current Store imported another evaluation cold reader')
            affected, cold_history = cold.prepare(root, affected, take=capture)
            selected_take = cold_history['prior_take']
        projected, history = window.prepare(root, affected, take=selected_take)
        if cold_history is not None:
            history['evaluation_cold_history'] = cold_history
    except ValueError as error:
        raise ValueError('Store history partially reverted or unreviewed composition: '
                         + str(error)) from error
    if history['review']['successor_applied'] is not True:
        raise ValueError('current Store successor did not bind the current complete group')
    source.update(projected)
    return source, history, saved, capture, root


def _reread(root, take, saved, window_history=None):
    if window_history is not None:
        from tools import hia_evaluation_window_history as window
        window.verify_unchanged(window_history)
        cold_history = window_history.get('evaluation_cold_history')
        if cold_history is not None:
            from tools import hia_evaluation_cold_source_history as cold
            cold.verify_unchanged(cold_history)
    for name, raw in saved.items():
        if take(root / name) != raw:
            raise ValueError('current Store physical source changed at terminal: ' + name)


def restore(captured, *, root=None, take=Path.read_bytes):
    source, window_history, saved, capture, root = _view(captured, root, take)
    prior_history = None
    try:
        prior_take = window_history['prior_take'] if window_history is not None else capture
        restored, prior_history = frozen.restore(source, root=root, take=prior_take)
        if window_history is None:
            return restored, prior_history
        if prior_history is None:
            raise ValueError('current Store lost its retained complete predecessor admission')
        review = deepcopy(prior_history['review'])
        review.update(
            schema=SCHEMA,
            complete_current={name: pin(saved[name]) for name in frozen.CURRENT},
            prior_source_history_review=deepcopy(prior_history['review']),
            evaluation_window_review=deepcopy(window_history['review']),
            physical_capture_rewritten=False,
            prior_projection_is_physical_source=False,
            current_source_reader={'path': SELF, **pin(saved[SELF])},
            terminal_reread_identical=False,
        )
        if window_history.get('evaluation_cold_history') is not None:
            review['evaluation_cold_review'] = deepcopy(
                window_history['evaluation_cold_history']['review'])
        history = {'review': review, 'root': root, 'take': take, 'captures': saved,
                   'window_history': window_history, 'prior_history': prior_history}
        verify_unchanged(history)
        return restored, history
    finally:
        frozen.verify_unchanged(prior_history)
        _reread(root, take, saved, window_history)


def verify_unchanged(history):
    if history is None:
        return
    if 'window_history' not in history and 'prior_history' not in history:
        frozen.verify_unchanged(history)
        return
    review = history['review']
    physical = {name: pin(history['captures'][name]) for name in frozen.CURRENT}
    cold_history = history['window_history'].get('evaluation_cold_history')
    expected = PHYSICAL_CURRENT if cold_history is not None else WINDOW_PHYSICAL_CURRENT
    if cold_history is not None and (
            cold_history['review'].get('physical') != COLD_CURRENT
            or cold_history['review'].get('prior_projection') != WINDOW_CURRENT
            or review.get('evaluation_cold_review') != cold_history['review']):
        raise ValueError('current Store lost its actual evaluation cold source review')
    if (review.get('schema') != SCHEMA or physical != expected
            or review.get('complete_current') != physical
            or review.get('complete_predecessors') != frozen.PREDECESSORS
            or review.get('physical_capture_rewritten') is not False
            or review.get('prior_projection_is_physical_source') is not False
            or review.get('current_source_reader') != {
                'path': SELF, **pin(history['captures'][SELF])}
            or history['prior_history']['review'].get('complete_current') != frozen.CURRENT
            or history['prior_history']['review'].get('complete_predecessors') != frozen.PREDECESSORS):
        raise ValueError('current Store review lost its complete physical source identity')
    frozen.verify_unchanged(history['prior_history'])
    _reread(history['root'], history['take'], history['captures'], history['window_history'])
    history['review']['prior_source_history_review'] = deepcopy(history['prior_history']['review'])
    history['review']['evaluation_window_review'] = deepcopy(history['window_history']['review'])
    if cold_history is not None:
        history['review']['evaluation_cold_review'] = deepcopy(cold_history['review'])
    history['review']['terminal_reread_identical'] = True


def restore_service(raw, *, root=None, take=Path.read_bytes):
    source, history = restore({'hepta/hia_agent_service.py': raw}, root=root, take=take)
    verify_unchanged(history)
    return source['hepta/hia_agent_service.py']


def restore_evaluation_test(raw, *, root=None, take=Path.read_bytes):
    source, history = restore({frozen.EVALUATION_TEST: raw}, root=root, take=take)
    verify_unchanged(history)
    return source[frozen.EVALUATION_TEST]


def _read_one(root, name, raw, take, reader):
    source, history, saved, capture, root = _view({name: raw}, root, take)
    try:
        selected = history['prior_take'] if history is not None else capture
        return reader(root, name, source[name], selected)
    finally:
        _reread(root, take, saved, history)


def restore_reader_evaluation_test(raw, *, root, take=Path.read_bytes):
    return _read_one(root, frozen.EVALUATION_TEST, raw, take,
        lambda selected_root, name, data, selected_take:
            frozen.restore_reader_evaluation_test(data, root=selected_root, take=selected_take))


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    def read(selected_root, selected_name, data, selected_take):
        if selected_name == NATIVE_TOOLS and pin(data) == NATIVE_TOOLS_CURRENT:
            helper = selected_take(selected_root / CALLER_HELPER)
            if pin(helper) != CALLER_HELPER_PIN:
                raise ValueError('current Store native-result source reader differs')
            from tools import hia_current_caller_source_history as caller
            if Path(caller.__file__).read_bytes() != helper:
                raise ValueError('current Store imported another native-result source reader')
            return caller.reviewed_source(selected_root, selected_name, data, take=selected_take)
        return frozen.reviewed_source(selected_root, selected_name, data, take=selected_take)
    return _read_one(root, name, raw, take, read)
