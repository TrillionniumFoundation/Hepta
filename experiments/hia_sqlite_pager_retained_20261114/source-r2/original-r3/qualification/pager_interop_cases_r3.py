"""Four fixed real-file Pager concurrency scenarios. Static draft, never run.

Two original SQLite runtimes each supply a writer, checkpointer and independent
read oracle. HIA owns every tested read transaction and page decision. Python
only sends fixed IPC frames and compares complete replies. It performs no DB
pread, SQLite lock operation, WAL lookup, SQL, or HIA fallback.

These cases are NOT a complete SQLite / AgentStore qualification. They require
Root's original outer 180+3 owner, frozen executable inputs and full raw audit.
"""
from __future__ import annotations
import os
from pathlib import Path
import struct

from pager_audit_stream_r3 import PhysicalBudget, require
from pager_ipc_session_r2 import (
    CommandJournal, Process, NATIVE_PROFILE, C_PROFILE,
)
from pager_raw_readback_r3 import inspect_all
from pager_elf_readback_r1 import observe_native_mapping

SQLITE_OK = 0
SQLITE_BUSY = 5
PAGE_SIZE = 4096
C_COMMANDS = 98
NATIVE_CLIENT_COMMANDS = 40
NATIVE_OWNERS = 8
C_PROCESSES = 16
CASE_IDS = (
    'sqlite34600_wal_readmark_isolation',
    'sqlite34600_readlock0_reset',
    'sqlite35302_wal_readmark_isolation',
    'sqlite35302_readlock0_reset',
)


def word(raw, offset):
    return struct.unpack_from('<Q', raw, offset)[0]


def signed(value):
    return value if value < 2**63 else value - 2**64


def original_rows(value):
    return (struct.pack('<QQ', 1, 64) + bytes([value])*64 +
            struct.pack('<QQ', 2, 64) + bytes(64))


class Case:
    def __init__(self, configuration, output, case_id, version, mode,
                 journal, budget, deadline, nonces):
        self.q = configuration
        self.case_id, self.version, self.mode = case_id, version, mode
        self.root = Path(output) / case_id
        self.root.mkdir(mode=0o700)
        self.files = self.root/'database'
        self.files.mkdir(mode=0o700)
        self.database = self.files/'probe.db'
        self.directory = os.open(self.files, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.journal, self.budget, self.deadline = journal, budget, deadline
        self.nonces = nonces
        self.processes = []
        self.child_results = []
        self.native_mappings = []
        self.assertions = []
        self.c_count = 0
        self.hia_count = 0

    def check(self, value, label):
        self.journal.append({'kind': 'assertion', 'case': self.case_id,
                             'label': label, 'passed': bool(value)})
        require(bool(value), self.case_id+': '+label)
        self.assertions.append(label)

    def start(self, label, role, *, commands=0):
        name = self.case_id+'-'+label
        require(name in self.nonces, 'frozen session nonce missing')
        if role == 'hia':
            supplied = self.q['hia_elf']
            argv = [self.database.name]
            profile = NATIVE_PROFILE
        else:
            supplied = self.q['sqlite_runtimes'][self.version]
            argv = [str(self.database), role]
            profile = C_PROFILE
        process = Process(
            executable=supplied['path'], executable_identity=supplied,
            argv=argv, directory_fd=self.directory, nonce=self.nonces[name],
            profile=profile, name=name, root=self.root, budget=self.budget,
            journal=self.journal, deadline=self.deadline, c_commands=commands)
        self.processes.append(process)
        if role == 'hia':
            self.native_mappings.append(observe_native_mapping(
                process.pid, supplied, self.q['hia_elf_layout'],
                process.root/'native-load'))
        return process

    def c(self, process, operation, argument=0, expected_rc=SQLITE_OK):
        result = process.command(operation, argument)
        self.c_count += 1
        # Full raw reply/snapshot/body already journalled and independently on
        # fd4. An assertion failure cannot erase the original C rc or tail.
        expected_version = 3046000 if self.version == '3.46.0' else 3053002
        self.check(result['words'][8] == expected_version, 'exact C engine version')
        self.check(result['words'][5] == expected_rc,
                   'C command %d raw rc %d' % (operation, expected_rc))
        return result

    def hia(self, process, operation, argument=0, expected_status=128):
        result = process.command(operation, argument)
        self.hia_count += 1
        self.check(result['words'][3] == expected_status, 'HIA command status')
        self.check(result['words'][4:7] == (0, 0, 0), 'no first HIA failure')
        self.check(word(result['state'], 368) == 0 and
                   word(result['state'], 376) == 0 and
                   word(result['state'], 392) == 0, 'no cleanup error ledger')
        self.check(result['words'][9] == PAGE_SIZE and result['words'][10] == 2,
                   'snapshot page geometry')
        return result

    def close_c(self, process):
        self.c(process, 10)
        self.child_results.append(process.finish())

    def close_hia(self, process):
        result = self.hia(process, 4, expected_status=130)
        self.check(result['words'][7:9] == (0, 0), 'HIA released all resource/lock bits')
        self.child_results.append(process.finish())

    def open_reference(self, label):
        process = self.start(label, 'r', commands=7)
        self.c(process, 1)
        started = self.c(process, 3)
        self.check(started['words'][7] == 1, 'reference has active original WAL snapshot')
        return process, started

    def read_reference(self, process, started, expected_byte):
        pages = {}
        for pgno in (1, 2):
            result = self.c(process, 4, pgno)
            self.check(result['words'][7] == 1, 'reference page still in original read txn')
            self.check(result['snapshot'] == started['snapshot'],
                       'reference complete snapshot header stable')
            self.check(len(result['payload']) == PAGE_SIZE, 'reference complete page')
            pages[pgno] = result['payload']
        rows = self.c(process, 5)
        self.check(rows['payload'] == original_rows(expected_byte),
                   'original SQL engine complete two-row value')
        self.c(process, 6)
        self.close_c(process)
        # No original C reference reader survives this point. The ordinary
        # writer/checkpointer have no active SQL read transaction.
        return pages

    def bind_snapshot(self, native, reference):
        self.check(native['state'][512:560] == reference['snapshot'],
                   'HIA endmark is complete original visible header')
        self.check(native['words'][9:12] ==
                   (reference['words'][9], reference['words'][10], reference['words'][11]),
                   'HIA page size/nPage/mxFrame equals original snapshot')
        # minFrame and reader slot numbers are raw observables, not normalized
        # into a cross-process equality. Their lock/path meaning is checked.
        self.check(native['words'][11] > 0, 'initialized nonempty live WAL profile')

    def page(self, process, pgno, expected, *, database_only=False):
        result = self.hia(process, 3, pgno, expected_status=129)
        self.check(result['words'][13] == pgno, 'HIA selected page identity')
        self.check(result['payload'] == expected, 'whole HIA page equals original C page')
        if database_only:
            self.check(result['words'][14] == 0 and word(result['state'], 240) == 0,
                       'READ_LOCK0 page came from DB, without WAL-frame fallback')
        return result

    def checkpoint(self, process, mode, expected_rc=SQLITE_OK):
        result = self.c(process, 8, mode, expected_rc=expected_rc)
        self.check(len(result['payload']) == 16, 'raw checkpoint counters retained')
        nlog, done = struct.unpack('<2Q', result['payload'])
        return signed(nlog), signed(done)

    def run(self):
        writer = self.start('writer', 'w', commands=4)
        checkpointer = self.start('checkpointer', 'w',
                                  commands=6 if self.mode == 'wal' else 7)
        self.c(writer, 1)
        self.c(writer, 2, PAGE_SIZE)
        self.c(checkpointer, 1)
        if self.mode == 'db':
            nlog, done = self.checkpoint(checkpointer, 1)
            self.check(nlog > 0 and done == nlog, 'prepare fully backfilled READ_LOCK0')
        ref_a, ref_a_start = self.open_reference('reference-a')
        old = self.start('old-reader', 'hia')
        profile = 34600 if self.version == '3.46.0' else 35302
        old_start = self.hia(old, 1, profile)
        self.bind_snapshot(old_start, ref_a_start)
        old_lock = word(old_start['state'], 160)
        self.check(old_lock == 0 if self.mode == 'db' else 1 <= old_lock <= 4,
                   'selected original read-lock branch')
        pages_a = self.read_reference(ref_a, ref_a_start, 0)
        self.page(old, 1, pages_a[1], database_only=self.mode == 'db')
        self.page(old, 2, pages_a[2], database_only=self.mode == 'db')

        # Only HIA read locks remain before the real writer commits B.
        self.c(writer, 7, 0x42)
        self.page(old, 2, pages_a[2], database_only=self.mode == 'db')
        ref_b, ref_b_start = self.open_reference('reference-b')
        new = self.start('new-reader', 'hia')
        new_start = self.hia(new, 1, profile)
        self.bind_snapshot(new_start, ref_b_start)
        self.check(1 <= word(new_start['state'], 160) <= 4,
                   'new committed B uses a WAL reader lock')
        if self.mode == 'db':
            self.check(old_start['state'][544:552] != new_start['state'][544:552],
                       'writer reset WAL salts while old READ_LOCK0 remained held')
        else:
            self.check(new_start['words'][11] > old_start['words'][11],
                       'new endmark advances beyond retained old endmark')
        pages_b = self.read_reference(ref_b, ref_b_start, 0x42)
        self.check(pages_b[2] != pages_a[2], 'real writer changed complete table page')
        self.page(new, 2, pages_b[2])

        # Both C reference connections are now CLOSED/reaped. Any constraint on
        # checkpoint/reset must come from the HIA sessions, not the oracle.
        nlog, done = self.checkpoint(checkpointer, 0)
        self.check(nlog == new_start['words'][11], 'checkpoint observes new endmark')
        if self.mode == 'db':
            self.check(done == 0, 'live READ_LOCK0 prevents DB backfill after WAL reset')
        else:
            self.check(0 <= done <= old_start['words'][11] < nlog,
                       'partial checkpoint cannot cross retained old snapshot')
        self.page(old, 2, pages_a[2], database_only=self.mode == 'db')
        self.close_hia(old)

        nlog, done = self.checkpoint(checkpointer, 1)
        self.check(done == nlog == new_start['words'][11],
                   'checkpoint may reach B while B reader remains live')
        self.checkpoint(checkpointer, 2, expected_rc=SQLITE_BUSY)
        self.page(new, 2, pages_b[2])
        self.close_hia(new)
        nlog, done = self.checkpoint(checkpointer, 3)
        self.check(nlog == 0 and done == 0, 'reset/truncate succeeds after final reader closes')
        self.close_c(writer)
        self.close_c(checkpointer)
        self.check(self.c_count == (24 if self.mode == 'wal' else 25),
                   'complete finite C command population')
        self.check(self.hia_count == 10, 'complete finite native command population')
        os.close(self.directory)
        self.directory = None
        return {'id': self.case_id, 'version': self.version, 'mode': self.mode,
                'status': 'SCENARIO_COMMANDS_COMPLETE_PENDING_RAW_AUDIT',
                'C_commands': self.c_count, 'HIA_client_commands': self.hia_count,
                'assertions': self.assertions, 'children': self.child_results,
                'native_mappings': self.native_mappings}


def run_cases(configuration, output, *, deadline, budget):
    """Root-only future call INSIDE the original 180+3 owner; never auto-runs."""
    require(configuration['owner_seconds'] == 180 and
            configuration['owner_grace_seconds'] == 3, 'original owner limits')
    require(configuration['case_ids'] == list(CASE_IDS), 'all four fixed scenarios')
    require(set(configuration['sqlite_runtimes']) == {'3.46.0', '3.53.2'},
            'complete independent original versions')
    nonces = configuration['session_nonces']
    expected_names = {
        case_id+'-'+label
        for case_id in CASE_IDS
        for label in ('writer', 'checkpointer', 'reference-a', 'reference-b',
                      'old-reader', 'new-reader')
    }
    require(set(nonces) == expected_names and len(set(nonces.values())) == 24,
            'one unique fixed nonce per process')
    require(all(type(value) is int and 0 < value < 2**64 for value in nonces.values()),
            'exact nonce types')
    output = Path(output)
    output.mkdir(mode=0o700)
    require(type(budget) is PhysicalBudget and budget.token ==
            configuration['trace_budget_token'] and budget.reserved == 0,
            'same completed-linker/native/C physical budget')
    prior_trace_bytes = budget.used
    journal = CommandJournal(output/'ipc', budget)
    cases, results, error = [], [], None
    try:
        for index, case_id in enumerate(CASE_IDS):
            version = '3.46.0' if index < 2 else '3.53.2'
            mode = 'wal' if index % 2 == 0 else 'db'
            case = Case(configuration, output, case_id, version, mode,
                        journal, budget, deadline, nonces)
            cases.append(case)
            results.append(case.run())
        require(sum(item['C_commands'] for item in results) == C_COMMANDS,
                'all 98 C API commands retained')
        require(sum(item['HIA_client_commands'] for item in results) ==
                NATIVE_CLIENT_COMMANDS, 'all 40 native client commands retained')
        journal_result = journal.close('CLOSED')
    except BaseException as exc:
        error = {'type': type(exc).__name__, 'message': str(exc)}
        # Preserve every actual prefix. No retry, recreated child, SQL repair,
        # manufactured native CLOSE, or replacement successful trace is allowed.
        for case in cases:
            for process in case.processes:
                if not process.reaped:
                    process.abort_input()
        try:
            journal.append({'kind': 'scenario_failure', 'error': error})
            journal_result = journal.close('HOLD')
        except BaseException:
            # Existing raw files remain owned by the original outer supervisor.
            raise
        raise
    # Every process has been waitpid-closed and every capture thread joined.
    # Reopen/decompress ALL physical parts before the finite success result.
    raw_readback = inspect_all(output, configuration, scenarios=results)
    require(raw_readback['physical_trace_bytes'] == budget.used-prior_trace_bytes and
            budget.reserved == 0, 'complete shared physical budget identity')
    return {'schema': 'hia.sqlite-pager.four-real-file-scenarios.v3',
            'status': 'FINITE_FOUR_PROCESS_INTEROP_PASS_ONLY',
            'raw_readback': raw_readback,
            'whole_SQLite_or_AgentStore_qualification': False,
            'cases': results, 'journal': journal_result,
            'physical_trace_bytes_charged': budget.used-prior_trace_bytes,
            'prior_linker_trace_bytes_charged': prior_trace_bytes,
            'aggregate_physical_trace_bytes_charged': budget.used,
            'shared_index_bytes_still_reserved': budget.reserved,
            'error': error}
