"""Same-owner sequential lock observation before inherited graph revalidation."""
import json

from hepta import modules, packages
from experiments.policy_failures.owner import Owner as PolicyOwner


class Owner(PolicyOwner):
    def revalidate(self, handle):
        # Keep inherited unchanged unchanged. This separate operation deliberately
        # preserves original lock diagnostics outside modules._unchanged's catch.
        entered = False
        try:
            self._enter()
            entered = True
            authority = next((graph for known, graph in self._handles if handle is known), None)
            if authority is None:
                self.context.reject('graph handle does not belong to this owner',
                                    category='schema', phase='owned_loader')
            self._ops.revalidation_hook(handle.project, modules._LEGACY_UNCHANGED)
            if authority.locked:
                file = authority.package.root / 'Hepta.lock'
                if not self._ops.path(file, 'is_file'):
                    packages.fail('E_LOCK_MISSING',
                        'Run hepta lock to create Hepta.lock before --locked validation', file)
                try:
                    actual = self._ops.json(json.loads, self._ops.read(file, 'lock'), file)
                except (ValueError, UnicodeError) as error:
                    if self.context.failure is not None:
                        raise
                    packages.fail('E_LOCK_INVALID', str(error), file)
                if actual != authority.package_state:
                    packages.fail('E_LOCK_STALE',
                        'Manifest, dependency graph, or source bytes differ from Hepta.lock', file)
            # Lock reads can invoke checkpoints that mutate graph inputs. Graph
            # validation must come last. Lock changes during it remain a race.
            return modules._revalidate(authority, ops=self._ops)
        except BaseException as error:
            self.context.record(error=error, phase='lock_revalidation')
            raise
        finally:
            if entered:
                self._busy = False
