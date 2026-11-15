"""Author the complete fifteen-method Slot SQL control graph in HIA.

The host supplies literal Python/SQLite/decision observations only. HIA selects
all branches, cursor continuation, exception handler continuation and final ACK.
No retained Slot method is called by a selected controller.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_slot_operations_protocol import (
    PORT, PORTS, REQUEST_MAGIC, RESULT_MAGIC, STATE_MAGIC, SOURCE_NAME,
)
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_service_context import ContextBuilder


PROTOCOL = r'''
def slot_operations(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 96 or length(w) != 192:
        return 4294967293
    if read_word(s, 0) != @REQUEST_MAGIC@:
        return 4294967293
    i = 64
    while i < 128:
        if read_word(s, i) != 0:
            return 4294967293
        i = i + 8
    event = read_word(s, 8)
    if event == 0:
        return initialize(s, o, w)
    if valid_state(w) == 0:
        return 4294967293
    if read_word(s, 40) != get(w, 2) or read_word(s, 48) != get(w, 6) or read_word(s, 56) != get(w, 7):
        return refuse(o, w)
    if read_word(s, 16) != get(w, 4) or read_word(s, 24) != get(w, 3):
        return refuse(o, w)
    observed = read_word(s, 32)
    phase = get(w, 5)
    port = get(w, 3)
    if event == 1:
        if phase != 1 or observed != 0:
            return refuse(o, w)
        set(w, 5, 2)
        seal(w)
        return answer(o, w, 0)
    if event == 2:
        if phase != 2:
            return refuse(o, w)
        if boolean_port(port) == 1:
            if observed > 1:
                return refuse(o, w)
        elif observed != 0:
            return refuse(o, w)
        return succeeded(o, w, observed)
    if event == 3:
        if phase != 2 or observed != 0:
            return refuse(o, w)
        set(w, 12, 1)
        if port == @conditional_call@:
            return advance(o, w, @conditional_error_matches@, 1)
        if get(w, 2) == 6 and get(w, 9) == 1 and port != @conditional_expression_unwind@:
            return advance(o, w, @conditional_expression_unwind@, 1)
        if get(w, 2) == 6 and error_port(port) == 1 and port != @conditional_error_forget@ and port != @conditional_expression_unwind@:
            return advance(o, w, @conditional_error_forget@, 1)
        if get(w, 2) == 10 and get(w, 8) == 1 and port != @adopt_iterator_error_release@:
            return advance(o, w, @adopt_iterator_error_release@, 1)
        if get(w, 2) == 14 and port != @lease_call_unwind@ and (get(w, 9) == 1 or port == @lease_call_open@):
            return advance(o, w, @lease_call_unwind@, 1)
        return advance(o, w, 0, 7)
    if event == 4:
        if port != 0 or observed != 0:
            return refuse(o, w)
        if phase == 6:
            return advance(o, w, 0, 4)
        if phase == 7:
            return advance(o, w, 0, 5)
        return refuse(o, w)
    return refuse(o, w)

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = read_word(s, 40)
    first = first_port(mode)
    if first == 0 or read_word(s, 16) != 0 or read_word(s, 24) != 0 or read_word(s, 32) != 0:
        return 4294967293
    if read_word(s, 48) == 0 and read_word(s, 56) == 0:
        return 4294967293
    i = 0
    while i < 192:
        if byte(w, i) != 0:
            return 4294967293
        i = i + 1
    set(w, 0, @STATE_MAGIC@)
    set(w, 1, 1)
    set(w, 2, mode)
    set(w, 3, first)
    set(w, 4, 1)
    set(w, 5, 1)
    set(w, 6, read_word(s, 48))
    set(w, 7, read_word(s, 56))
    seal(w)
    return answer(o, w, 0)

def first_port(mode:u64) -> u64:
    if mode == 1:
        return @init_assign@
    if mode == 2:
        return @execute_connection_same@
    if mode == 3:
        return @call_transition@
    if mode == 4:
        return @snapshot_import@
    if mode == 5:
        return @validate_flag@
    if mode == 6:
        return @conditional_import@
    if mode == 7:
        return @begin_workspace@
    if mode == 8:
        return @evaluation_import@
    if mode == 9:
        return @benefit_import@
    if mode == 10:
        return @adopt_import@
    if mode == 11:
        return @rollback_import@
    if mode == 12:
        return @lease_value_import@
    if mode == 13:
        return @acquire_import@
    if mode == 14:
        return @lease_import@
    if mode == 15:
        return @release_db@
    return 0

def boolean_port(port:u64) -> u64:
    if port == @execute_connection_same@:
        return 1
    if port == @snapshot_row_none@:
        return 1
    if port == @snapshot_action_zero@:
        return 1
    if port == @conditional_is_dict@:
        return 1
    if port == @conditional_error_matches@:
        return 1
    if port == @conditional_error_stale@:
        return 1
    if port == @begin_target_none@:
        return 1
    if port == @evaluation_unhashable@:
        return 1
    if port == @evaluation_allow_truth@:
        return 1
    if port == @adopt_initial@:
        return 1
    if port == @adopt_next@:
        return 1
    if port == @lease_connection_none@:
        return 1
    if port == @lease_row_none@:
        return 1
    if port == @lease_active_type@:
        return 1
    if port == @lease_release_truth@:
        return 1
    return 0

def error_port(port:u64) -> u64:
    if port == @conditional_error_matches@:
        return 1
    if port == @conditional_error_stale@:
        return 1
    if port == @conditional_error_attach@:
        return 1
    if port == @conditional_error_forget@:
        return 1
    if port == @adopt_iterator_error_release@:
        return 1
    if port == @lease_call_unwind@:
        return 1
    if port == @conditional_expression_unwind@:
        return 1
    return 0

def owned_port(mode:u64, port:u64) -> u64:
    if mode == 1:
        if port >= @init_assign@ and port <= @init_assign@:
            return 1
        return 0
    if mode == 2:
        if port >= @execute_connection_same@ and port <= @execute_call@:
            return 1
        return 0
    if mode == 3:
        if port >= @call_transition@ and port <= @call_raise@:
            return 1
        return 0
    if mode == 4:
        if port >= @snapshot_import@ and port <= @snapshot_present_result@:
            return 1
        return 0
    if mode == 5:
        if port >= @validate_flag@ and port <= @validate_result@:
            return 1
        return 0
    if mode == 6:
        if port >= @conditional_import@ and port <= @conditional_expression_unwind@:
            return 1
        return 0
    if mode == 7:
        if port >= @begin_workspace@ and port <= @begin_result@:
            return 1
        return 0
    if mode == 8:
        if port >= @evaluation_import@ and port <= @evaluation_raise@:
            return 1
        return 0
    if mode == 9:
        if port >= @benefit_import@ and port <= @benefit_call@:
            return 1
        return 0
    if mode == 10:
        if port >= @adopt_import@ and port <= @adopt_iterator_error_release@:
            return 1
        return 0
    if mode == 11:
        if port >= @rollback_import@ and port <= @rollback_result@:
            return 1
        return 0
    if mode == 12:
        if port >= @lease_value_import@ and port <= @lease_value_result@:
            return 1
        return 0
    if mode == 13:
        if port >= @acquire_import@ and port <= @acquire_result@:
            return 1
        return 0
    if mode == 14:
        if port >= @lease_import@ and port <= @lease_call_unwind@:
            return 1
        return 0
    if mode == 15:
        if port >= @release_db@ and port <= @release_result@:
            return 1
        return 0
    return 0

def succeeded(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    mode = get(w, 2)
    port = get(w, 3)
    if port == @adopt_iterator@:
        set(w, 8, 1)
    if port == @adopt_iterator_done@ or port == @adopt_iterator_error_release@:
        set(w, 8, 0)
    if port == @conditional_is_dict@:
        set(w, 9, observed)
    if port == @conditional_exact_keys@ or port == @conditional_exact_false@ or port == @conditional_expression_unwind@:
        set(w, 9, 0)
    if port == @lease_call_open@:
        set(w, 9, 1)
    if port == @lease_call_release@ or port == @lease_call_check@ or port == @lease_call_unwind@:
        set(w, 9, 0)
    if mode == 1:
        return mode_1(o, w, observed)
    if mode == 2:
        return mode_2(o, w, observed)
    if mode == 3:
        return mode_3(o, w, observed)
    if mode == 4:
        return mode_4(o, w, observed)
    if mode == 5:
        return mode_5(o, w, observed)
    if mode == 6:
        return mode_6(o, w, observed)
    if mode == 7:
        return mode_7(o, w, observed)
    if mode == 8:
        return mode_8(o, w, observed)
    if mode == 9:
        return mode_9(o, w, observed)
    if mode == 10:
        return mode_10(o, w, observed)
    if mode == 11:
        return mode_11(o, w, observed)
    if mode == 12:
        return mode_12(o, w, observed)
    if mode == 13:
        return mode_13(o, w, observed)
    if mode == 14:
        return mode_14(o, w, observed)
    if mode == 15:
        return mode_15(o, w, observed)
    return refuse(o, w)

def mode_1(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @init_assign@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_2(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @execute_connection_same@:
        if observed == 1:
            return advance(o, w, @execute_call@, 1)
        return advance(o, w, @execute_refuse@, 1)
    if port == @execute_refuse@:
        return advance(o, w, @execute_call@, 1)
    if port == @execute_call@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_3(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @call_transition@:
        return advance(o, w, @call_raise@, 1)
    if port == @call_raise@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_4(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @snapshot_import@:
        return advance(o, w, @snapshot_db@, 1)
    if port == @snapshot_db@:
        return advance(o, w, @snapshot_row@, 1)
    if port == @snapshot_row@:
        return advance(o, w, @snapshot_row_none@, 1)
    if port == @snapshot_row_none@:
        if observed == 1:
            return advance(o, w, @snapshot_absent_call@, 1)
        return advance(o, w, @snapshot_version@, 1)
    if port == @snapshot_absent_call@:
        return advance(o, w, @snapshot_action_zero@, 1)
    if port == @snapshot_version@:
        return advance(o, w, @snapshot_count@, 1)
    if port == @snapshot_count@:
        return advance(o, w, @snapshot_artifact@, 1)
    if port == @snapshot_artifact@:
        return advance(o, w, @snapshot_present_call@, 1)
    if port == @snapshot_present_call@:
        return advance(o, w, @snapshot_action_zero@, 1)
    if port == @snapshot_action_zero@:
        if observed == 1:
            return advance(o, w, @snapshot_absent_result@, 1)
        return advance(o, w, @snapshot_fields@, 1)
    if port == @snapshot_absent_result@:
        return advance(o, w, 0, 6)
    if port == @snapshot_fields@:
        return advance(o, w, @snapshot_present_result@, 1)
    if port == @snapshot_present_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_5(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @validate_flag@:
        return advance(o, w, @validate_result@, 1)
    if port == @validate_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_6(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @conditional_import@:
        return advance(o, w, @conditional_expected@, 1)
    if port == @conditional_expected@:
        return advance(o, w, @conditional_generation@, 1)
    if port == @conditional_generation@:
        return advance(o, w, @conditional_epoch@, 1)
    if port == @conditional_epoch@:
        return advance(o, w, @conditional_snapshot@, 1)
    if port == @conditional_snapshot@:
        return advance(o, w, @conditional_fields@, 1)
    if port == @conditional_fields@:
        return advance(o, w, @conditional_is_dict@, 1)
    if port == @conditional_is_dict@:
        if observed == 1:
            return advance(o, w, @conditional_exact_keys@, 1)
        return advance(o, w, @conditional_exact_false@, 1)
    if port == @conditional_exact_keys@:
        return advance(o, w, @conditional_call@, 1)
    if port == @conditional_exact_false@:
        return advance(o, w, @conditional_call@, 1)
    if port == @conditional_call@:
        return advance(o, w, @conditional_result@, 1)
    if port == @conditional_result@:
        return advance(o, w, 0, 6)
    if port == @conditional_error_matches@:
        if observed == 1:
            return advance(o, w, @conditional_error_stale@, 1)
        return advance(o, w, 0, 7)
    if port == @conditional_error_stale@:
        if observed == 1:
            return advance(o, w, @conditional_error_attach@, 1)
        return advance(o, w, @conditional_error_forget@, 1)
    if port == @conditional_error_attach@:
        return advance(o, w, @conditional_error_forget@, 1)
    if port == @conditional_error_forget@:
        return advance(o, w, 0, 7)
    if port == @conditional_expression_unwind@:
        return advance(o, w, 0, 7)
    return refuse(o, w)

def mode_7(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @begin_workspace@:
        return advance(o, w, @begin_token@, 1)
    if port == @begin_token@:
        return advance(o, w, @begin_target_none@, 1)
    if port == @begin_target_none@:
        if observed == 1:
            return advance(o, w, @begin_fields_one@, 1)
        return advance(o, w, @begin_fields_two@, 1)
    if port == @begin_fields_one@:
        return advance(o, w, @begin_call_one@, 1)
    if port == @begin_fields_two@:
        return advance(o, w, @begin_call_two@, 1)
    if port == @begin_call_one@:
        return advance(o, w, @begin_result@, 1)
    if port == @begin_call_two@:
        return advance(o, w, @begin_result@, 1)
    if port == @begin_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_8(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @evaluation_import@:
        return advance(o, w, @evaluation_first@, 1)
    if port == @evaluation_first@:
        return advance(o, w, @evaluation_second@, 1)
    if port == @evaluation_second@:
        return advance(o, w, @evaluation_third@, 1)
    if port == @evaluation_third@:
        return advance(o, w, @evaluation_outcome@, 1)
    if port == @evaluation_outcome@:
        return advance(o, w, @evaluation_allow@, 1)
    if port == @evaluation_allow@:
        return advance(o, w, @evaluation_transition@, 1)
    if port == @evaluation_transition@:
        return advance(o, w, @evaluation_unhashable@, 1)
    if port == @evaluation_unhashable@:
        if observed == 1:
            return advance(o, w, @evaluation_allow_truth@, 1)
        return advance(o, w, @evaluation_raise@, 1)
    if port == @evaluation_allow_truth@:
        if observed == 1:
            return advance(o, w, @evaluation_membership_allow@, 1)
        return advance(o, w, @evaluation_membership_improved@, 1)
    if port == @evaluation_membership_allow@:
        return advance(o, w, @evaluation_refuse@, 1)
    if port == @evaluation_membership_improved@:
        return advance(o, w, @evaluation_refuse@, 1)
    if port == @evaluation_refuse@:
        return advance(o, w, @evaluation_raise@, 1)
    if port == @evaluation_raise@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_9(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @benefit_import@:
        return advance(o, w, @benefit_call@, 1)
    if port == @benefit_call@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_10(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @adopt_import@:
        return advance(o, w, @adopt_db@, 1)
    if port == @adopt_db@:
        return advance(o, w, @adopt_active@, 1)
    if port == @adopt_active@:
        return advance(o, w, @adopt_plan@, 1)
    if port == @adopt_plan@:
        return advance(o, w, @adopt_initial@, 1)
    if port == @adopt_initial@:
        if observed == 1:
            return advance(o, w, @adopt_insert_slot@, 1)
        return advance(o, w, @adopt_current@, 1)
    if port == @adopt_insert_slot@:
        return advance(o, w, @adopt_insert_baseline@, 1)
    if port == @adopt_insert_baseline@:
        return advance(o, w, @adopt_begin@, 1)
    if port == @adopt_current@:
        return advance(o, w, @adopt_abi@, 1)
    if port == @adopt_abi@:
        return advance(o, w, @adopt_native@, 1)
    if port == @adopt_native@:
        return advance(o, w, @adopt_baseline@, 1)
    if port == @adopt_baseline@:
        return advance(o, w, @adopt_begin@, 1)
    if port == @adopt_begin@:
        return advance(o, w, @adopt_cursor@, 1)
    if port == @adopt_cursor@:
        return advance(o, w, @adopt_iterator@, 1)
    if port == @adopt_iterator@:
        return advance(o, w, @adopt_next@, 1)
    if port == @adopt_next@:
        if observed == 1:
            return advance(o, w, @adopt_iterator_done@, 1)
        return advance(o, w, @adopt_fold@, 1)
    if port == @adopt_fold@:
        return advance(o, w, @adopt_next@, 1)
    if port == @adopt_iterator_done@:
        return advance(o, w, @adopt_final@, 1)
    if port == @adopt_final@:
        return advance(o, w, @adopt_result_fields@, 1)
    if port == @adopt_result_fields@:
        return advance(o, w, @adopt_insert_candidate@, 1)
    if port == @adopt_insert_candidate@:
        return advance(o, w, @adopt_update@, 1)
    if port == @adopt_update@:
        return advance(o, w, @adopt_result@, 1)
    if port == @adopt_result@:
        return advance(o, w, 0, 6)
    if port == @adopt_iterator_error_release@:
        return advance(o, w, 0, 7)
    return refuse(o, w)

def mode_11(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @rollback_import@:
        return advance(o, w, @rollback_db@, 1)
    if port == @rollback_db@:
        return advance(o, w, @rollback_active@, 1)
    if port == @rollback_active@:
        return advance(o, w, @rollback_retained@, 1)
    if port == @rollback_retained@:
        return advance(o, w, @rollback_row_check@, 1)
    if port == @rollback_row_check@:
        return advance(o, w, @rollback_artifact@, 1)
    if port == @rollback_artifact@:
        return advance(o, w, @rollback_native@, 1)
    if port == @rollback_native@:
        return advance(o, w, @rollback_current@, 1)
    if port == @rollback_current@:
        return advance(o, w, @rollback_abi@, 1)
    if port == @rollback_abi@:
        return advance(o, w, @rollback_begin@, 1)
    if port == @rollback_begin@:
        return advance(o, w, @rollback_final@, 1)
    if port == @rollback_final@:
        return advance(o, w, @rollback_result_fields@, 1)
    if port == @rollback_result_fields@:
        return advance(o, w, @rollback_update@, 1)
    if port == @rollback_update@:
        return advance(o, w, @rollback_result@, 1)
    if port == @rollback_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_12(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @lease_value_import@:
        return advance(o, w, @lease_value_fields@, 1)
    if port == @lease_value_fields@:
        return advance(o, w, @lease_value_result@, 1)
    if port == @lease_value_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_13(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @acquire_import@:
        return advance(o, w, @acquire_db@, 1)
    if port == @acquire_db@:
        return advance(o, w, @acquire_snapshot@, 1)
    if port == @acquire_snapshot@:
        return advance(o, w, @acquire_active@, 1)
    if port == @acquire_active@:
        return advance(o, w, @acquire_native@, 1)
    if port == @acquire_native@:
        return advance(o, w, @acquire_fields@, 1)
    if port == @acquire_fields@:
        return advance(o, w, @acquire_call@, 1)
    if port == @acquire_call@:
        return advance(o, w, @acquire_lease@, 1)
    if port == @acquire_lease@:
        return advance(o, w, @acquire_insert@, 1)
    if port == @acquire_insert@:
        return advance(o, w, @acquire_result@, 1)
    if port == @acquire_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def mode_14(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @lease_import@:
        return advance(o, w, @lease_keys@, 1)
    if port == @lease_keys@:
        return advance(o, w, @lease_connection_none@, 1)
    if port == @lease_connection_none@:
        if observed == 1:
            return advance(o, w, @lease_db_store@, 1)
        return advance(o, w, @lease_db_connection@, 1)
    if port == @lease_db_store@:
        return advance(o, w, @lease_row@, 1)
    if port == @lease_db_connection@:
        return advance(o, w, @lease_row@, 1)
    if port == @lease_row@:
        return advance(o, w, @lease_row_none@, 1)
    if port == @lease_row_none@:
        if observed == 1:
            return advance(o, w, @lease_raw_empty@, 1)
        return advance(o, w, @lease_raw_fields@, 1)
    if port == @lease_raw_empty@:
        return advance(o, w, @lease_active_other@, 1)
    if port == @lease_raw_fields@:
        return advance(o, w, @lease_active_type@, 1)
    if port == @lease_active_type@:
        if observed == 1:
            return advance(o, w, @lease_active_int@, 1)
        return advance(o, w, @lease_active_other@, 1)
    if port == @lease_active_int@:
        return advance(o, w, @lease_keys_call@, 1)
    if port == @lease_active_other@:
        return advance(o, w, @lease_keys_call@, 1)
    if port == @lease_keys_call@:
        return advance(o, w, @lease_checked_fields@, 1)
    if port == @lease_checked_fields@:
        return advance(o, w, @lease_artifact@, 1)
    if port == @lease_artifact@:
        return advance(o, w, @lease_claimed@, 1)
    if port == @lease_claimed@:
        return advance(o, w, @lease_call_open@, 1)
    if port == @lease_call_open@:
        return advance(o, w, @lease_release_truth@, 1)
    if port == @lease_release_truth@:
        if observed == 1:
            return advance(o, w, @lease_call_release@, 1)
        return advance(o, w, @lease_call_check@, 1)
    if port == @lease_call_release@:
        return advance(o, w, @lease_result@, 1)
    if port == @lease_call_check@:
        return advance(o, w, @lease_result@, 1)
    if port == @lease_result@:
        return advance(o, w, 0, 6)
    if port == @lease_call_unwind@:
        return advance(o, w, 0, 7)
    return refuse(o, w)

def mode_15(o:mutbuf, w:mutbuf, observed:u64) -> u32:
    port = get(w, 3)
    if port == @release_db@:
        return advance(o, w, @release_lease@, 1)
    if port == @release_lease@:
        return advance(o, w, @release_update@, 1)
    if port == @release_update@:
        return advance(o, w, @release_result@, 1)
    if port == @release_result@:
        return advance(o, w, 0, 6)
    return refuse(o, w)

def valid_state(w:mutbuf) -> u64:
    if get(w, 0) != @STATE_MAGIC@ or get(w, 1) != 1 or first_port(get(w, 2)) == 0:
        return 0
    phase = get(w, 5)
    port = get(w, 3)
    if get(w, 4) == 0 or phase == 0 or phase == 3 or phase > 8:
        return 0
    if get(w, 8) > 1 or get(w, 9) > 1 or get(w, 11) != 0 or get(w, 12) > 1:
        return 0
    if get(w, 2) != 10 and get(w, 8) != 0:
        return 0
    if get(w, 2) != 6 and get(w, 2) != 14 and get(w, 9) != 0:
        return 0
    i = 13
    while i < 24:
        if get(w, i) != 0:
            return 0
        i = i + 1
    if checksum(w) != get(w, 10):
        return 0
    if phase == 1 or phase == 2:
        if owned_port(get(w, 2), port) == 0 or error_port(port) != get(w, 12):
            return 0
    elif port != 0:
        return 0
    if phase == 4 or phase == 6:
        if get(w, 12) != 0:
            return 0
    if phase == 5 or phase == 7:
        if get(w, 12) != 1:
            return 0
    return 1

def advance(o:mutbuf, w:mutbuf, port:u64, phase:u64) -> u32:
    if get(w, 4) == 18446744073709551615:
        return refuse(o, w)
    set(w, 3, port)
    set(w, 4, get(w, 4) + 1)
    set(w, 5, phase)
    seal(w)
    return answer(o, w, 0)

def refuse(o:mutbuf, w:mutbuf) -> u32:
    set(w, 3, 0)
    set(w, 5, 8)
    seal(w)
    return answer(o, w, 1)

def answer(o:mutbuf, w:mutbuf, status:u64) -> u32:
    set(o, 0, @RESULT_MAGIC@)
    set(o, 1, status)
    set(o, 2, get(w, 3))
    set(o, 3, get(w, 4))
    set(o, 4, get(w, 5))
    set(o, 5, get(w, 2))
    set(o, 6, get(w, 12))
    set(o, 7, 0)
    set(o, 8, get(w, 6))
    set(o, 9, get(w, 7))
    set(o, 10, 0)
    set(o, 11, 0)
    return 96

def checksum(w:mutbuf) -> u64:
    value = 1469598103934665603
    i = 0
    while i < 24:
        if i != 10:
            value = ((value << 7) | (value >> 57)) ^ get(w, i)
        i = i + 1
    return value

def seal(w:mutbuf) -> u64:
    value = checksum(w)
    set(w, 10, value)
    return value

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, index * 8 + i) << (i * 8))
        i = i + 1
    return value

def set(w:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, index * 8 + i, value >> (i * 8))
        i = i + 1
    return value
'''

def source_program():
    values = {**PORT, 'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC,
              'STATE_MAGIC': STATE_MAGIC, 'MAX_PORT': len(PORTS)}
    return re.sub(r'@([A-Za-z_][A-Za-z_0-9]*)@', lambda match: str(values[match[1]]), PROTOCOL)


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ContextBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'slot_operations', 'functions': functions})


if __name__ == '__main__':
    path = ROOT / SOURCE_NAME
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)
