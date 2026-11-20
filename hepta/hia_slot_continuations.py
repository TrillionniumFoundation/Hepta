"""Real-signature, one-frame Slot continuations selected only by HIA.

These are new mechanical continuations, not retained original bodies.
Every branch on _hia_port dispatches an already claimed native directive.
The original user expressions and business fast locals remain in this frame.
No provider runs in a Python port/helper/generator beneath this frame.
"""
from __future__ import annotations

def __init__(self, store, image):
    _HIA_SLOT_START(1)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 1:
                self.store, self.image = (store, image)
                return _HIA_SLOT_RETURN(None)
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def _execute(self, connection, statement, parameters=()):
    _HIA_SLOT_START(2)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 2:
                _HIA_SLOT_SQL_PREPARE()
                if _HIA_SLOT_SQL_BORROW(self.store).db is connection:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 3:
                _custody('slot operation lost its original SQLite connection')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 4:
                return _HIA_SLOT_RETURN(connection.execute(statement, _HIA_SLOT_SQL_ARGUMENTS(parameters)))
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def _call(self, opcode, fields=(), *, labels=(), state=None, **values):
    _HIA_SLOT_START(3)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 5:
                receipt = self.image.transition(request_packet(opcode, fields, **values), state)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 6:
                return _HIA_SLOT_RETURN(_raise(receipt, labels))
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def snapshot(self, slot):
    _HIA_SLOT_START(4)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 7:
                from .hia_agent_store import decode_data, wire
                _HIA_SLOT_ACK(0)
            elif _hia_port == 8:
                db = self.store.db
                _HIA_SLOT_ACK(0)
            elif _hia_port == 9:
                row = self._execute(db, 'SELECT * FROM slots WHERE name=?', (slot,)).fetchone()
                _HIA_SLOT_ACK(0)
            elif _hia_port == 10:
                if row is None:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 11:
                receipt = self._call(2)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 12:
                version = self._execute(db, 'SELECT artifact FROM versions WHERE slot=? AND generation=?', (slot, row['generation'])).fetchone()
                _HIA_SLOT_ACK(0)
            elif _hia_port == 13:
                count = self._execute(db, 'SELECT COUNT(*) FROM leases WHERE slot=? AND active=1', (slot,)).fetchone()[0]
                _HIA_SLOT_ACK(0)
            elif _hia_port == 14:
                artifact = decode_data(version['artifact'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 15:
                receipt = self._call(2, (_text(row['generation']), _text(row['epoch']), _text(row['context_id']), wire(artifact)), flags=1, a=count)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 16:
                if receipt.action == 0:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 17:
                return _HIA_SLOT_RETURN({'target_slot': slot, 'current': {'generation': '0', 'epoch': '0'}, 'active_artifact': None, 'context': None, 'in_flight_leases': 0, 'snapshot_is_adoption_authority': False})
            elif _hia_port == 18:
                generation, epoch, context, artifact = receipt.fields
                _HIA_SLOT_ACK(0)
            elif _hia_port == 19:
                return _HIA_SLOT_RETURN({'target_slot': slot, 'current': {'generation': _untext(generation), 'epoch': _untext(epoch)}, 'active_artifact': decode_data(artifact), 'context': _untext(context), 'in_flight_leases': receipt.values[0], 'snapshot_is_adoption_authority': False})
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def validate_u64(self, value, label):
    _HIA_SLOT_START(5)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 20:
                flag = {'generation': 1, 'epoch': 2, 'retained_generation': 3}.get(label, 1)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 21:
                return _HIA_SLOT_RETURN(self._call(1, (_decimal(value),), flags=flag, labels=(label,)).values[0])
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def conditional(self, args, snapshot_reader):
    _HIA_SLOT_START(6)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 22:
                from .hia_agent_store import AgentRejected
                _HIA_SLOT_ACK(0)
            elif _hia_port == 23:
                expected = args['expected_current']
                _HIA_SLOT_ACK(0)
            elif _hia_port == 24:
                self.validate_u64(expected['generation'], 'generation')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 25:
                self.validate_u64(expected['epoch'], 'epoch')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 26:
                snapshot = snapshot_reader(args['target_slot'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 27:
                fields = (_text(snapshot['current']['generation']), _text(snapshot['current']['epoch']), _text(expected['generation']), _text(expected['epoch']))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 28:
                # The real AND keeps its false operand and evaluates truth exactly once.
                # HIA must issue/claim the RHS before its literal expression may execute.
                exact = isinstance(expected, dict) and _HIA_SLOT_KEEP_RHS(
                    _HIA_SLOT_AND_TRUE(), set(expected) == {'generation', 'epoch'})
                _HIA_SLOT_AND_DONE()
            elif _hia_port == 31:
                self._call(3, fields, flags=int(exact))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 32:
                return _HIA_SLOT_RETURN(snapshot)
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            try:
                while _HIA_SLOT_PENDING():
                    _hia_port = _HIA_SLOT_BEGIN()
                    if _hia_port == 33:
                        try:
                            raise
                        except AgentRejected as error:
                            _HIA_SLOT_ACK(1)
                            while _HIA_SLOT_PENDING():
                                _hia_port = _HIA_SLOT_BEGIN()
                                if _hia_port == 34:
                                    if error.code == 'E_HIA_GENERATION_STALE':
                                        _HIA_SLOT_ACK(1)
                                    else:
                                        _HIA_SLOT_ACK(0)
                                elif _hia_port == 35:
                                    error.pending_slot_snapshot = snapshot
                                    _HIA_SLOT_ACK(0)
                                elif _hia_port == 36:
                                    # Leave the real except-as alias before its ACK.
                                    break
                                else:
                                    _HIA_SLOT_BAD_PORT(_hia_port)
                        except _HIA_SLOT_EXCEPTION:
                            _HIA_SLOT_ACK(0)
                        # Python's genuine except-as cleanup has already run, while
                        # the same error is still the outer handled exception.
                        if _hia_port == 36:
                            _HIA_SLOT_ACK(0)
                    elif _hia_port == 37:
                        _HIA_SLOT_UNWIND()
                    else:
                        _HIA_SLOT_BAD_PORT(_hia_port)
            except _HIA_SLOT_EXCEPTION:
                # The graph has only a final alias/unwind continuation after a handler
                # replacement. A transport failure is never acknowledged as foreign.
                if not _HIA_SLOT_FAILED():
                    raise
                while _HIA_SLOT_PENDING():
                    _hia_port = _HIA_SLOT_BEGIN()
                    if _hia_port == 36:
                        _HIA_SLOT_ACK(0)
                    elif _hia_port == 37:
                        _HIA_SLOT_UNWIND()
                    else:
                        _HIA_SLOT_BAD_PORT(_hia_port)
                _HIA_SLOT_PROPAGATING()
                raise
            _HIA_SLOT_PROPAGATING()
            raise


def _begin(self, epoch, target=None):
    _HIA_SLOT_START(7)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 38:
                workspace = ctypes.create_string_buffer(STATE_BYTES)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 39:
                token = struct.unpack('<4Q', os.urandom(32))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 40:
                if target is None:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 41:
                fields = (_decimal(epoch),)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 42:
                fields = (_decimal(epoch), _decimal(target))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 43:
                self._call(7, fields, flags=1, token=token, state=workspace, labels=('epoch',))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 44:
                self._call(7, fields, flags=2, token=token, state=workspace, labels=('epoch', 'retained_generation'))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 45:
                return _HIA_SLOT_RETURN((workspace, token))
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def admit_evaluation(self, evaluation, objective):
    _HIA_SLOT_START(8)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 46:
                from .hia_agent_store import wire
                _HIA_SLOT_ACK(0)
            elif _hia_port == 47:
                name = 'report_complete'
                self._call(17, (wire(evaluation[name]),))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 48:
                name = 'planned_workload_complete'
                self._call(17, (wire(evaluation[name]),))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 49:
                name = 'termination_confirmed'
                self._call(17, (wire(evaluation[name]),))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 50:
                outcome = evaluation['outcome']
                _HIA_SLOT_ACK(0)
            elif _hia_port == 51:
                allow_unchanged = objective['allow_unchanged']
                _HIA_SLOT_ACK(0)
            elif _hia_port == 52:
                receipt = self.image.transition(request_packet(18, (wire(outcome), wire(allow_unchanged))))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 53:
                if receipt.status in {16, 17}:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 54:
                if allow_unchanged:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 55:
                outcome not in {'improved', 'unchanged'}
                _HIA_SLOT_ACK(0)
            elif _hia_port == 56:
                outcome not in {'improved'}
                _HIA_SLOT_ACK(0)
            elif _hia_port == 57:
                _custody('native unhashable outcome refusal did not raise a Python error')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 58:
                _raise(receipt)
                return _HIA_SLOT_RETURN(None)
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def admit_net_benefit(self, objective):
    _HIA_SLOT_START(9)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 59:
                from .hia_agent_store import wire
                _HIA_SLOT_ACK(0)
            elif _hia_port == 60:
                self._call(19, (wire(objective.get('require_net_benefit', False)),))
                return _HIA_SLOT_RETURN(None)
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def adopt(self, args, snapshot, evaluation, abi, native):
    _HIA_SLOT_START(10)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 61:
                from .hia_agent_store import wire
                _HIA_SLOT_ACK(0)
            elif _hia_port == 62:
                db = self.store.db
                _HIA_SLOT_ACK(0)
            elif _hia_port == 63:
                active = snapshot['active_artifact'] is not None
                _HIA_SLOT_ACK(0)
            elif _hia_port == 64:
                plan = self._call(12, flags=int(active))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 65:
                if plan.action == 1:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 66:
                self._execute(db, 'INSERT INTO slots VALUES (?,?,?,?,?)', (args['target_slot'], args['context']['id'], '0', '0', abi))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 67:
                self._execute(db, 'INSERT INTO versions VALUES (?,?,?)', (args['target_slot'], '0', wire(evaluation['baseline_artifact']).decode()))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 68:
                current = self._execute(db, 'SELECT * FROM slots WHERE name=?', (args['target_slot'],)).fetchone()
                _HIA_SLOT_ACK(0)
            elif _hia_port == 69:
                self._call(4, (_text(current['abi_sha256']), _text(abi)))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 70:
                data, _metadata, _program = native(snapshot['active_artifact'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 71:
                self._call(5, (_text(sha256(data).hexdigest()), _text(evaluation['baseline_artifact']['sha256'])))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 72:
                workspace, token = self._begin(snapshot['current']['epoch'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 73:
                cursor = self._execute(db, 'SELECT generation FROM versions WHERE slot=?', (args['target_slot'],))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 74:
                # This is the actual Python for stack. The mechanical C iterator adds
                # no Python __next__/catch frame and never retains the continuation frame.
                for row in _HIA_SLOT_ITERATION_OPEN(cursor):
                    _HIA_SLOT_ITERATION_ITEM()
                    self._call(8, (_decimal(row['generation']),), token=token,
                               state=workspace, labels=('generation',))
                    _HIA_SLOT_ACK(0)
                _HIA_SLOT_ITERATION_END()
            elif _hia_port == 78:
                final = self._call(9, token=token, state=workspace)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 79:
                current = {'generation': final.fields[0].decode('ascii'), 'epoch': final.fields[1].decode('ascii')}
                _HIA_SLOT_ACK(0)
            elif _hia_port == 80:
                self._execute(db, 'INSERT INTO versions VALUES (?,?,?)', (args['target_slot'], current['generation'], wire(args['candidate_artifact']).decode()))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 81:
                self._execute(db, 'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?', (current['generation'], current['epoch'], args['context']['id'], args['target_slot']))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 82:
                return _HIA_SLOT_RETURN(current)
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def rollback(self, args, snapshot, native):
    _HIA_SLOT_START(11)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 84:
                from .hia_agent_store import decode_data, digest
                _HIA_SLOT_ACK(0)
            elif _hia_port == 85:
                db = self.store.db
                _HIA_SLOT_ACK(0)
            elif _hia_port == 86:
                self._call(6, flags=int(snapshot['active_artifact'] is not None), a=1)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 87:
                row = self._execute(db, 'SELECT artifact FROM versions WHERE slot=? AND generation=?', (args['target_slot'], args['retained_generation'])).fetchone()
                _HIA_SLOT_ACK(0)
            elif _hia_port == 88:
                self._call(10, flags=int(row is not None))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 89:
                artifact = decode_data(row['artifact'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 90:
                _data, metadata, _program = native(artifact)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 91:
                current_row = self._execute(db, 'SELECT * FROM slots WHERE name=?', (args['target_slot'],)).fetchone()
                _HIA_SLOT_ACK(0)
            elif _hia_port == 92:
                self._call(11, (_text(digest(metadata['signatures'])), _text(current_row['abi_sha256'])))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 93:
                workspace, token = self._begin(snapshot['current']['epoch'], args['retained_generation'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 94:
                final = self._call(9, token=token, state=workspace)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 95:
                current = {'generation': final.fields[0].decode('ascii'), 'epoch': final.fields[1].decode('ascii')}
                _HIA_SLOT_ACK(0)
            elif _hia_port == 96:
                self._execute(db, 'UPDATE slots SET generation=?,epoch=?,context_id=? WHERE name=?', (current['generation'], current['epoch'], args['context']['id'], args['target_slot']))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 97:
                return _HIA_SLOT_RETURN((current, artifact))
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def _lease_value(fields):
    _HIA_SLOT_START(12)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 98:
                from .hia_agent_store import decode_data
                _HIA_SLOT_ACK(0)
            elif _hia_port == 99:
                identity, slot, generation, artifact = fields
                _HIA_SLOT_ACK(0)
            elif _hia_port == 100:
                return _HIA_SLOT_RETURN({'id': _untext(identity), 'slot': _untext(slot), 'generation': _untext(generation), 'artifact': decode_data(artifact)})
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def acquire(self, target_slot, snapshot_reader, native):
    _HIA_SLOT_START(13)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 101:
                from .hia_agent_store import wire
                _HIA_SLOT_ACK(0)
            elif _hia_port == 102:
                db = self.store.db
                _HIA_SLOT_ACK(0)
            elif _hia_port == 103:
                snapshot = snapshot_reader(target_slot)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 104:
                self._call(6, flags=int(snapshot['active_artifact'] is not None))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 105:
                native(snapshot['active_artifact'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 106:
                fields = (_text('lease-' + uuid.uuid4().hex), _text(target_slot), _text(snapshot['current']['generation']), wire(snapshot['active_artifact']))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 107:
                result = self._call(15, fields, flags=1)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 108:
                lease = self._lease_value(result.fields)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 109:
                self._execute(db, 'INSERT INTO leases VALUES (?,?,?,?,1)', (lease['id'], lease['slot'], lease['generation'], result.fields[3].decode()))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 110:
                return _HIA_SLOT_RETURN(lease)
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def lease(self, lease, *, release=False, connection=None):
    _HIA_SLOT_START(14)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 111:
                from .hia_agent_store import decode_data, keys, wire
                _HIA_SLOT_ACK(0)
            elif _hia_port == 112:
                keys(lease, ('id', 'slot', 'generation', 'artifact'), label='generation lease')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 113:
                if connection is None:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 114:
                db = self.store.db
                _HIA_SLOT_ACK(0)
            elif _hia_port == 115:
                db = connection
                _HIA_SLOT_ACK(0)
            elif _hia_port == 116:
                row = self._execute(db, 'SELECT * FROM leases WHERE id=?', (lease['id'],)).fetchone()
                _HIA_SLOT_ACK(0)
            elif _hia_port == 117:
                if row is None:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 118:
                raw_fields = (b'', b'', b'', b'')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 119:
                raw_fields = (_text(row['id']), _text(row['slot']), _text(row['generation']), b'')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 120:
                if type(row['active']) is int:
                    _HIA_SLOT_ACK(1)
                else:
                    _HIA_SLOT_ACK(0)
            elif _hia_port == 121:
                active = b'I' + str(row['active']).encode('ascii')
                _HIA_SLOT_ACK(0)
            elif _hia_port == 122:
                active = b'X'
                _HIA_SLOT_ACK(0)
            elif _hia_port == 123:
                checked = self._call(16, (*raw_fields, _text(lease['slot']), _text(lease['generation']), active), flags=int(row is not None))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 124:
                identity, slot, generation, _placeholder = checked.fields
                _HIA_SLOT_ACK(0)
            elif _hia_port == 125:
                artifact = wire(decode_data(row['artifact']))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 126:
                claimed_artifact, valid = _claimed_artifact_wire(lease['artifact'])
                _HIA_SLOT_ACK(0)
            elif _hia_port == 127:
                # Preserve LOAD_METHOD and its receiver on the original expression stack.
                # The C operand helper observes release once; HIA chooses opcode 13 or 14.
                result = self._call(
                    _HIA_SLOT_LEASE_OPCODE(_HIA_SLOT_LEASE_OPEN(), release),
                    (identity, slot, generation, artifact, _text(lease['slot']),
                     _text(lease['generation']), claimed_artifact),
                    flags=1, a=1, b=int(valid))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 131:
                return _HIA_SLOT_RETURN(self._lease_value(result.fields))
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


def release(self, lease):
    _HIA_SLOT_START(15)
    while True:
        try:
            _hia_port = _HIA_SLOT_BEGIN()
            if _hia_port == 133:
                db = self.store.db
                _HIA_SLOT_ACK(0)
            elif _hia_port == 134:
                frozen = self.lease(lease, release=True, connection=db)
                _HIA_SLOT_ACK(0)
            elif _hia_port == 135:
                self._execute(db, 'UPDATE leases SET active=0 WHERE id=?', (frozen['id'],))
                _HIA_SLOT_ACK(0)
            elif _hia_port == 136:
                return _HIA_SLOT_RETURN({'released': True, 'generation': frozen['generation'], 'artifact_retained': True})
            else:
                _HIA_SLOT_BAD_PORT(_hia_port)
        except _HIA_SLOT_EXCEPTION:
            if not _HIA_SLOT_FAILED():
                raise
            while _HIA_SLOT_PENDING():
                _hia_port = _HIA_SLOT_BEGIN()
                if _hia_port in (37, 83, 132):
                    _HIA_SLOT_UNWIND()
                else:
                    _HIA_SLOT_BAD_PORT(_hia_port)
            _HIA_SLOT_PROPAGATING()
            raise


CONTINUATIONS = {
    1: __init__,
    2: _execute,
    3: _call,
    4: snapshot,
    5: validate_u64,
    6: conditional,
    7: _begin,
    8: admit_evaluation,
    9: admit_net_benefit,
    10: adopt,
    11: rollback,
    12: _lease_value,
    13: acquire,
    14: lease,
    15: release,
}
