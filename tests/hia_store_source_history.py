"""Qualification access to data-only complete Store source history."""
from tools.hia_frozen_component_sources import (
    CURRENT, EVALUATION_QUALIFIER, EVALUATION_TEST, HOST_CURRENT, HOST_SUPPORT,
    PREDECESSORS, PRODUCTION_PATHS, SOURCE_HISTORY_FIXTURE,
    SOURCE_HISTORY_FIXTURE_SHA256, history_inverse, history_pin,
)
from tools.hia_current_store_source_history import (
    restore, restore_evaluation_test, restore_reader_evaluation_test,
    restore_service, verify_unchanged,
)

SOURCE_HISTORY_INPUTS = (
    'tools/hia_frozen_component_sources.py',
    'tests/hia_store_source_history.py',
    'tests/fixtures/store_source_history_v2.json',
    'tests/test_hia_store_source_history.py',
    'hepta/hia_native_host_support.py',
    'tests/hia_evaluation_capture_successor.py',
    'tools/hia_current_store_source_history.py',
    'tools/hia_evaluation_window_history.py',
    'tests/fixtures/hia_evaluation_window_history_v1.json',
    'tests/test_hia_current_store_source_history.py',
    'tests/fixtures/hia_current_store_consumers_v1.json',
)
