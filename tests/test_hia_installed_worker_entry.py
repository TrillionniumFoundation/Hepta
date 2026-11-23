"""Exercise the public provider argv and the immutable native launch handoff."""
from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_agent_store import wire
from tools.build_hia_installed_worker_entry import PREFIX, configuration
from tools.generate_hia_installed_worker_entry import SOURCE, PACKER, MAGIC
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path(__file__).resolve().parents[1]

class InstalledWorkerEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_execution_budget_session import BudgetSessionTests
        BudgetSessionTests.setUpClass()
        cls.addClassCleanup(BudgetSessionTests.doClassCleanups)
        folder = BudgetSessionTests.session.parent
        compiler = folder/'B2.image.bin'
        cls.policy = compile_stage(folder,'installed-entry',compiler,(ROOT/SOURCE).read_bytes())[0].read_bytes()
        cls.packer = compile_stage(folder,'installed-packer',compiler,(ROOT/PACKER).read_bytes())[0]
        # A bounded sample peer makes each argument, the preserved public input
        # and the transport identity observable without invoking a shell.
        peer = folder/'inspect-worker-argv'
        program = b'''#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 5 || !getenv("HIA_TRANSPORT_ARGUMENTS_SHA256")) return 1;
    for (int i=1; i<argc; i++) puts(argv[i]);
    puts(getenv("HIA_TRANSPORT_ARGUMENTS_SHA256"));
    int c;
    while ((c=getchar()) != EOF) putchar(c);
    return 0;
}
'''
        subprocess.run(['cc','-Os','-s','-x','c','-o',peer,'-'],input=program,check=True)
        cls.sample_peer = peer.read_bytes()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state = root/'state with spaces'
        self.release = root/'release'
        self.release.mkdir()
        self.profile = root/'worker.json'
        self.profile.write_bytes(b'{"test":"profile"}')
        self.profile.chmod(0o400)
        self.capsule = root/'worker-capsule.bin'
        self.capsule.write_bytes(b'configured-capsule')
        self.capsule.chmod(0o400)
        self.pin = sha256(self.capsule.read_bytes()).hexdigest()
        self.identities = {key+'_sha256':sha256(key.encode()).hexdigest() for key in ('worker','backend','catalog')}
        helper = sha256(self.profile.read_bytes()).hexdigest()
        self.identities['native_helpers_sha256'] = helper
        self.options = ['--native-helpers-manifest', str(self.profile), '--expected-native-helpers-sha256', helper]
        self.argv = [*PREFIX, '--state-root', str(self.state)]
        for key in ('worker','backend','catalog'):
            self.argv.extend(('--expected-'+key+'-sha256', self.identities[key+'_sha256']))
        self.argv.extend(('--artifact-root', str(root), *self.options, '--request-json-stdin'))
        # A synthetic echo peer exposes every forwarded argument. The installed
        # qualification separately exercises the 166-role sealed HIA launcher.
        config = configuration(self.profile, self.release, self.capsule, self.pin,
                               self.sample_peer, self.identities, [root])
        image = self.policy+config+struct.pack('<Q',len(config))
        frame = struct.pack('<2Q', MAGIC, len(image))+image
        self.exe = compile_stage(root,'installed-worker',self.packer,frame,output_extension='.elf')[0]
        self.exe.chmod(0o500)

    def run_worker(self, args):
        child = subprocess.run([self.exe,*args],input=b'original public stdin',
                               env={'PATH':'','HIA_TRANSPORT_ARGUMENTS_SHA256':'preserved'},
                               capture_output=True,timeout=5)
        return child.returncode, child.stdout, child.stderr

    def test_original_provider_argv_and_identity_query(self):
        expected = '\n'.join(map(str,(self.state,self.release,self.capsule,self.pin,'preserved'))).encode() + b'\noriginal public stdin'
        self.assertEqual(self.run_worker(self.argv),(0,expected,b''))
        for prefix in ((),PREFIX):
            for options in ((),self.options):
                self.assertEqual(self.run_worker([*prefix,'--installation-manifest',*options]),
                                 (0,wire(self.identities)+b'\n',b''))
        self.assertFalse(self.state.exists())

    def test_each_identity_scope_and_profile_is_checked_before_input(self):
        for flag in ('--expected-worker-sha256','--expected-catalog-sha256','--expected-backend-sha256',
                     '--native-helpers-manifest','--expected-native-helpers-sha256','--artifact-root','--state-root'):
            with self.subTest(flag=flag):
                altered = self.argv.copy()
                idx = altered.index(flag)+1
                altered[idx] = '/unsafe/../alias' if flag=='--state-root' else altered[idx]+'X'
                self.assertEqual(self.run_worker(altered),(2,b'',b''))
        self.profile.chmod(0o600)
        self.profile.write_bytes(b'{"test":"profila"}')
        self.profile.chmod(0o400)
        self.assertEqual(self.run_worker(self.argv),(2,b'',b''))
        self.assertFalse(self.state.exists())
