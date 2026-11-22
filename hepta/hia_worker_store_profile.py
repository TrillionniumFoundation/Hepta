"""Bind an installed HIA Store to the existing worker helper pin."""

from hashlib import sha256
from pathlib import Path

from . import hia_native_helpers as authority
from .hia_agent_store_native import RELEASE_IMAGES, capture_release_image, release_identity

SCHEMA = 'hepta.hia.native-helpers.v4'
EDIT_QUERY_SCHEMA = 'hepta.hia.native-helpers.v5'
IMPORT_SCHEMA = 'hepta.hia.native-helpers.v6'
REFERENCE_SCHEMA = 'hepta.hia.native-helpers.v7'
OWNED_REFERENCE_SCHEMA = 'hepta.hia.native-helpers.v8'
DIRECT_CALL_SCHEMA = 'hepta.hia.native-helpers.v9'
DIRECT_REPEAT_SCHEMA = 'hepta.hia.native-helpers.v10'
DIRECT_BATCH_SCHEMA = 'hepta.hia.native-helpers.v11'
SEALED_PAGE_SCHEMA = 'hepta.hia.native-helpers.v12'
TERMINAL_SCHEMA = 'hepta.hia.native-helpers.v13'
ADMISSION_SCHEMA = 'hepta.hia.native-helpers.v14'
STARTUP_SCHEMA = 'hepta.hia.native-helpers.v15'
JOURNAL_SCHEMA = 'hepta.hia.native-helpers.v16'
DIRECT_OWNER_SCHEMA = 'hepta.hia.native-helpers.v17'
REFERENCE_OWNER_SCHEMA = 'hepta.hia.native-helpers.v18'
STORE_UNIQUE_SCHEMA = 'hepta.hia.native-helpers.v19'
WORKER_DATA_SCHEMA = 'hepta.hia.native-helpers.v20'
WORKER_COST_SCHEMA = 'hepta.hia.native-helpers.v21'
WORKER_EVALUATE_SCHEMA = 'hepta.hia.native-helpers.v22'
WORKER_COST_SCHEMAS = (WORKER_COST_SCHEMA, WORKER_EVALUATE_SCHEMA)
WORKER_DATA_SCHEMAS = (WORKER_DATA_SCHEMA, *WORKER_COST_SCHEMAS)
STORE_UNIQUE_SCHEMAS = (STORE_UNIQUE_SCHEMA, *WORKER_DATA_SCHEMAS)
JOURNAL_SCHEMAS = (JOURNAL_SCHEMA, DIRECT_OWNER_SCHEMA, REFERENCE_OWNER_SCHEMA, *STORE_UNIQUE_SCHEMAS)
STARTUP_SCHEMAS = (STARTUP_SCHEMA, *JOURNAL_SCHEMAS)
ADMISSION_SCHEMAS = (ADMISSION_SCHEMA, *STARTUP_SCHEMAS)
TERMINAL_SCHEMAS = (TERMINAL_SCHEMA, *ADMISSION_SCHEMAS)
PAGE_SCHEMAS = (SEALED_PAGE_SCHEMA, *TERMINAL_SCHEMAS)
DIRECT_CALL_SCHEMAS = (DIRECT_CALL_SCHEMA, DIRECT_REPEAT_SCHEMA, DIRECT_BATCH_SCHEMA, *PAGE_SCHEMAS)
OWNED_REFERENCE_SCHEMAS = (OWNED_REFERENCE_SCHEMA, *DIRECT_CALL_SCHEMAS)
REFERENCE_SCHEMAS = (REFERENCE_SCHEMA, *OWNED_REFERENCE_SCHEMAS)
SCHEMAS = (SCHEMA, EDIT_QUERY_SCHEMA, IMPORT_SCHEMA, *REFERENCE_SCHEMAS)
PIN_FIELDS = ('store_sha256', 'artifact_sha256', 'capture_sha256')


def profile_images(schema):
    if schema not in SCHEMAS:
        raise ValueError('unsupported pinned native Store profile')
    result = dict(zip(PIN_FIELDS, RELEASE_IMAGES, strict=True))
    if schema != SCHEMA:
        from .hia_agent_edit_query_native import EXECUTABLE
        result['edit_query_sha256'] = EXECUTABLE
    if schema in (IMPORT_SCHEMA, *REFERENCE_SCHEMAS):
        from .hia_agent_candidate_native import IMPORT_EXECUTABLES
        result.update(IMPORT_EXECUTABLES)
    if schema in TERMINAL_SCHEMAS:
        result['terminal_sha256'] = ('hia-worker-terminal', authority.MAX_IMAGE_BYTES)
    if schema in WORKER_DATA_SCHEMAS:
        result['worker_data_sha256'] = ('hia-worker-data', authority.MAX_IMAGE_BYTES)
    if schema == WORKER_EVALUATE_SCHEMA:
        result['evaluate_case_sha256'] = ('hia-agent-worker-evaluate-case', authority.MAX_IMAGE_BYTES)
    if schema in STARTUP_SCHEMAS:
        result['initializer_sha256'] = ('hia-agent-store-init', authority.MAX_IMAGE_BYTES)
    return result


class NativeWorkerStoreBinding:
    def __init__(self, snapshot, expected_sha256, record):
        schema = record.get('schema')
        images = profile_images(schema)
        reference_fields = {'reference_path', 'reference_sha256'} if schema in REFERENCE_SCHEMAS else set()
        if schema in OWNED_REFERENCE_SCHEMAS:
            reference_fields.update({'owned_reference_path', 'owned_reference_sha256'})
        if schema in DIRECT_CALL_SCHEMAS:
            reference_fields.update({'direct_call_path', 'direct_call_sha256'})
        if schema in PAGE_SCHEMAS:
            reference_fields.update({'read_page_path', 'read_page_sha256'})
        if schema in JOURNAL_SCHEMAS:
            reference_fields.update({'journal_path', 'journal_sha256'})
        if schema in STORE_UNIQUE_SCHEMAS:
            reference_fields.update({'store_unique_path', 'store_unique_sha256'})
        if schema in WORKER_COST_SCHEMAS:
            reference_fields.update({'journal_cost_path', 'journal_cost_sha256'})
        if (set(record) != {'schema', 'target', 'abi', 'base_bundle', 'base_bundle_sha256',
                            'release_path', *images, *reference_fields}
                or record['target'] != authority.TARGET
                or record['abi'] != authority.ABI
                or not all(authority._digest(record[key]) for key in (*images, 'base_bundle_sha256'))):
            raise ValueError('unsupported pinned native Store profile')
        if not authority._digest(expected_sha256) or sha256(snapshot.raw).hexdigest() != expected_sha256:
            raise ValueError('native Store profile identity mismatch')
        release = authority._path(record['release_path'], snapshot.path.parent)
        self.directory_identity = release_identity(release)
        pins = tuple(record[key] for key in PIN_FIELDS)
        self.native_store = (release, *pins)
        self.sha256 = expected_sha256
        self.snapshots = [(snapshot, authority.MAX_BUNDLE_BYTES)]
        captures = {}
        for field, (name, limit) in images.items():
            captured = capture_release_image(release, name, limit, record[field])
            self.snapshots.append((captured, limit))
            captures[field] = captured
        initializer = captures.get('initializer_sha256')
        self.native_store_initializer = initializer.raw if initializer is not None else None
        evaluate = captures.get('evaluate_case_sha256')
        self.native_evaluate_case_executable = evaluate.raw if evaluate is not None else None
        if evaluate is not None and not evaluate.raw.startswith(b'\x7fELF'):
            raise ValueError('standalone Evaluate planner must be a pinned ELF executable')
        self.native_edit_query = None
        if 'edit_query_sha256' in captures:
            from .hia_agent_edit_query_native import NativeAgentEditQuery
            self.native_edit_query = NativeAgentEditQuery(captures['edit_query_sha256'])
        base = authority._read(authority._path(record['base_bundle'], snapshot.path.parent),
                               authority.MAX_BUNDLE_BYTES)
        if sha256(base.raw).hexdigest() != record['base_bundle_sha256']:
            raise ValueError('native Store base helper identity mismatch')
        self.base_binding = authority._base_binding(
            base, record['base_bundle_sha256'], authority._decode(base.raw))
        self.selections = self.base_binding.selections
        self.images = self.base_binding.images
        self.bundles = getattr(self.base_binding, 'bundles', {})
        self.native_candidate_import = None
        if schema in (IMPORT_SCHEMA, *REFERENCE_SCHEMAS):
            from .hia_agent_candidate_native import NativeAgentCandidateImport
            from .hia_agent_inspection_native import SELECTOR
            if SELECTOR not in self.selections:
                raise ValueError('native candidate import requires pinned Agent inspection')
            self.native_candidate_import = NativeAgentCandidateImport(
                captures['assembly_import_sha256'], captures['json_admission_sha256'], self.selections[SELECTOR])
        self.native_reference_executable = None
        if schema in REFERENCE_SCHEMAS:
            from .hia_scalar_reference_native import MAX_IMAGE_BYTES, SELECTOR, NativeScalarReference
            if SELECTOR not in self.selections or not authority._digest(record['reference_sha256']):
                raise ValueError('standalone reference requires its pinned scalar image and executable')
            selected = authority._path(record['reference_path'], snapshot.path.parent)
            reference = capture_release_image(
                selected.parent, selected.name, MAX_IMAGE_BYTES, record['reference_sha256'])
            manifest = str(Path(self.selections[SELECTOR]).resolve(strict=True))
            owners = [image for key, image in self.images.items()
                      if key[0] == manifest and key[3] is NativeScalarReference]
            if len(owners) != 1 or not owners[0].matches_standalone(reference.raw):
                raise ValueError('standalone reference omits its exact pinned HIA image')
            self.snapshots.append((reference, MAX_IMAGE_BYTES))
            self.native_reference_executable = (reference.raw, record['reference_sha256'])
        self.native_owned_reference_executable = None
        if schema in OWNED_REFERENCE_SCHEMAS:
            pin = record['owned_reference_sha256']
            selected = authority._path(record['owned_reference_path'], snapshot.path.parent)
            owned = capture_release_image(selected.parent, selected.name, MAX_IMAGE_BYTES, pin)
            if not owned.raw.startswith(b'\x7fELF') or owned.raw == self.native_reference_executable[0]:
                raise ValueError('standalone owned reference requires its separate pinned executable')
            self.snapshots.append((owned, MAX_IMAGE_BYTES))
            self.native_owned_reference_executable = (owned.raw, pin)
        self.native_direct_call_executable = None
        self.native_direct_call_protocol = {
            DIRECT_REPEAT_SCHEMA: 2, **dict.fromkeys((DIRECT_BATCH_SCHEMA, *PAGE_SCHEMAS), 3),
            DIRECT_OWNER_SCHEMA: 4,
            REFERENCE_OWNER_SCHEMA: 5, **dict.fromkeys(STORE_UNIQUE_SCHEMAS, 5),
        }.get(schema, 1)
        if schema in DIRECT_CALL_SCHEMAS:
            from .hia_elf_shared_linker_native import SELECTOR as LINKER_SELECTOR
            if LINKER_SELECTOR not in self.selections:
                raise ValueError('standalone direct call requires the pinned HIA shared linker')
            pin = record['direct_call_sha256']
            selected = authority._path(record['direct_call_path'], snapshot.path.parent)
            direct_call = capture_release_image(selected.parent, selected.name, MAX_IMAGE_BYTES, pin)
            if (not direct_call.raw.startswith(b'\x7fELF')
                    or direct_call.raw in (self.native_reference_executable[0], self.native_owned_reference_executable[0])):
                raise ValueError('standalone direct call requires its separate pinned executable')
            self.snapshots.append((direct_call, MAX_IMAGE_BYTES))
            self.native_direct_call_executable = (direct_call.raw, pin)
        self.native_agent_read_page_executable = None
        if schema in PAGE_SCHEMAS:
            from .hia_agent_read_page_native import NativeAgentReadPage, SELECTOR

            if SELECTOR not in self.selections or not authority._digest(record['read_page_sha256']):
                raise ValueError('standalone read page requires its pinned HIA page image and executable')
            selected = authority._path(record['read_page_path'], snapshot.path.parent)
            page = capture_release_image(selected.parent, selected.name, MAX_IMAGE_BYTES, record['read_page_sha256'])
            manifest = str(Path(self.selections[SELECTOR]).resolve(strict=True))
            owners = [image for key, image in self.images.items() if key[0] == manifest and key[3] is NativeAgentReadPage]
            if len(owners) != 1 or not owners[0].matches_standalone(page.raw):
                raise ValueError('standalone read page omits its exact pinned HIA image')
            self.snapshots.append((page, MAX_IMAGE_BYTES))
            self.native_agent_read_page_executable = page.raw
        self.native_agent_store_unique_executable = None
        if schema in STORE_UNIQUE_SCHEMAS:
            from .hia_agent_store_transport_native import NativeAgentStoreTransport, SELECTOR

            pin = record['store_unique_sha256']
            if SELECTOR not in self.selections or not authority._digest(pin):
                raise ValueError('standalone Store reads require their pinned HIA transport')
            selected = authority._path(record['store_unique_path'], snapshot.path.parent)
            descriptor = capture_release_image(selected.parent, selected.name, MAX_IMAGE_BYTES, pin)
            manifest = str(Path(self.selections[SELECTOR]).resolve(strict=True))
            owners = [image for key, image in self.images.items()
                      if key[0] == manifest and key[3] is NativeAgentStoreTransport]
            if len(owners) != 1 or not owners[0].matches_standalone(descriptor.raw):
                raise ValueError('standalone Store read omits its exact pinned HIA transport')
            self.snapshots.append((descriptor, MAX_IMAGE_BYTES))
            self.native_agent_store_unique_executable = descriptor.raw
        self.native_agent_journal_executable = None
        self.native_worker_journal_cost_executable = None
        if schema in JOURNAL_SCHEMAS:
            from .hia_agent_journal_native import NativeAgentJournal, SELECTOR

            pin = record['journal_sha256']
            if SELECTOR not in self.selections or not authority._digest(pin):
                raise ValueError('standalone journal requires its pinned HIA journal image and executable')
            selected = authority._path(record['journal_path'], snapshot.path.parent)
            journal = capture_release_image(selected.parent, selected.name, MAX_IMAGE_BYTES, pin)
            manifest = str(Path(self.selections[SELECTOR]).resolve(strict=True))
            owners = [image for key, image in self.images.items() if key[0] == manifest and key[3] is NativeAgentJournal]
            if len(owners) != 1 or not owners[0].matches_standalone(journal.raw):
                raise ValueError('standalone journal omits its exact pinned HIA image')
            self.snapshots.append((journal, MAX_IMAGE_BYTES))
            self.native_agent_journal_executable = journal.raw
            if schema in WORKER_COST_SCHEMAS:
                pin = record['journal_cost_sha256']
                selected = authority._path(record['journal_cost_path'], snapshot.path.parent)
                cost = capture_release_image(selected.parent, selected.name, MAX_IMAGE_BYTES, pin)
                if not owners[0].matches_standalone_transport(journal.raw, cost.raw):
                    raise ValueError('standalone cost writer omits its exact pinned HIA journal transport')
                self.snapshots.append((cost, MAX_IMAGE_BYTES))
                self.native_worker_journal_cost_executable = cost.raw
        self.native_worker_terminal_executable = None
        self.native_worker_admission_executable = None
        self.native_worker_data_executable = None
        if schema in TERMINAL_SCHEMAS:
            from .hia_worker_request_native import (
                ADMISSION_INPUT_MAGIC, ADMISSION_OUTPUT_MAGIC, NativeWorkerRequest, SELECTOR,
            )

            if SELECTOR not in self.selections:
                raise ValueError('standalone terminal requires its pinned HIA worker request image and executable')
            terminal = captures['terminal_sha256']
            manifest = str(Path(self.selections[SELECTOR]).resolve(strict=True))
            owners = [image for key, image in self.images.items() if key[0] == manifest and key[3] is NativeWorkerRequest]
            if len(owners) != 1 or not owners[0].matches_standalone(terminal.raw):
                raise ValueError('standalone terminal omits its exact pinned HIA worker request image')
            self.native_worker_terminal_executable = terminal.raw
            if schema in WORKER_DATA_SCHEMAS:
                data = captures['worker_data_sha256']
                if data.raw == terminal.raw or not owners[0].matches_standalone(data.raw):
                    raise ValueError('standalone data validation omits its exact pinned HIA worker request image')
                self.native_worker_data_executable = data.raw
            if schema in ADMISSION_SCHEMAS:
                if ADMISSION_INPUT_MAGIC not in terminal.raw or ADMISSION_OUTPUT_MAGIC not in terminal.raw:
                    raise ValueError('standalone worker omits the required admission arena transport')
                self.native_worker_admission_executable = terminal.raw
        self._check_release()

    def check_owner(self):
        self.base_binding.check_owner()

    def _check_release(self):
        if (release_identity(self.native_store[0]) != self.directory_identity
                or any(authority._read(captured.path, limit) != captured
                       for captured, limit in self.snapshots)):
            raise ValueError('native Store profile inputs changed; observe the original operation')

    def check(self):
        self.base_binding.check()
        self._check_release()
