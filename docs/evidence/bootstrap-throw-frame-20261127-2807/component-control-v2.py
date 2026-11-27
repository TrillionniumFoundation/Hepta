from pathlib import Path
import builtins,ctypes,hashlib,json,sys,types,unittest,weakref
ROOT=Path(sys.argv.pop(1)).resolve(strict=True)
sys.path.insert(0,str(ROOT))
from hepta import hia_agent_service as api,hia_service_bootstrap_native as native
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime_prepared import prepare_runtime_program
from tests.hia_service_bootstrap_observer import VMEntry

class RootValue:
    def absolute(self):return self
    def resolve(self,*,strict):
        assert strict is True
        return self
    def is_dir(self):return True

class GeneratorMechanicalLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=native.SOURCE.read_bytes()
        assert len(raw)==141504 and hashlib.sha256(raw).hexdigest()=='c7e0fe0d84f5062b01fbdf1c6dbc683268f1ac5c42379c6bda710efaaf8a28a2'
        cls.program=prepare_runtime_program(assemble_program(raw))
    def make(self,mode):
        image=object.__new__(native.NativeServiceBootstrap)
        image.image_sha256='independent-VM-not-executable'
        image.admitted_source_sha256=hashlib.sha256(native.SOURCE.read_bytes()).hexdigest()
        image._entry=VMEntry(self.program)
        captured=dict(vars(builtins))
        namespace={'__name__':'hepta.hia_agent_service','__package__':'hepta',
                   '__builtins__':captured,'Path':lambda value:value}
        imports={}
        for name,function in api._SERVICE_BOOTSTRAP_IMPORT_PORTS.items():
            clone=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
            clone.__kwdefaults__=None if function.__kwdefaults__ is None else dict(function.__kwdefaults__)
            imports[name]=clone
        root0,root1=RootValue(),RootValue()
        references=(weakref.ref(root0),weakref.ref(root1))
        iterator=iter([root0,root1])
        generator=native._bootstrap_generator(image,mode,iterator,namespace,captured,imports,dict(native.GRAPH_LOCAL_LAYOUTS))
        return image,generator,references
    def success(self,mode):
        frames=[]
        constructor=native.ServiceBootstrapFrame
        def capture(*args,**kwargs):
            frame=constructor(*args,**kwargs)
            frames.append(weakref.ref(frame))
            return frame
        native.ServiceBootstrapFrame=capture
        try:
            image,generator,roots=self.make(mode)
            yielded=next(generator)
            self.assertIs(yielded,roots[0]() if mode==native.GENERATOR_ROOTS else False)
            del yielded
            error=RuntimeError('original throw identity')
            try:
                generator.throw(error)
            except RuntimeError as caught:
                self.assertIs(caught,error)
                saved_traceback=caught.__traceback__
            else:self.fail('real generator throw returned')
            self.assertIsNone(generator.gi_frame)
            self.assertGreater(image._entry.calls,0)
            self.assertEqual(len(frames),1)
            self.assertIsNone(frames[0](),'completed mechanical frame is retained by the original throw traceback')
            held=[]
            current=saved_traceback
            while current is not None:
                if current.tb_frame.f_code is native._bootstrap_generator.__code__:
                    held.append(current.tb_frame.f_locals)
                current=current.tb_next
            self.assertEqual(len(held),1)
            self.assertNotIn('frame',held[0])
            original=held[0]['original_locals']
            self.assertEqual(set(original),{'.0','root'})
            self.assertIs(original['root'],roots[0]())
            self.assertIsNotNone(roots[0]())
            self.assertIsNotNone(roots[1]())
            self.assertIs(error.__traceback__,saved_traceback)
            self.assertIsNone(error.__cause__)
        finally:native.ServiceBootstrapFrame=constructor
    def test_roots_successful_throw_releases_only_mechanical_frame(self):
        self.success(native.GENERATOR_ROOTS)
    def test_directories_successful_throw_releases_only_mechanical_frame(self):
        self.success(native.GENERATOR_DIRECTORIES)
    def test_z_failed_ack_retains_the_unconfirmed_owner(self):
        frames=[]
        constructor=native.ServiceBootstrapFrame
        def capture(*args,**kwargs):
            frame=constructor(*args,**kwargs)
            frames.append(weakref.ref(frame))
            return frame
        native.ServiceBootstrapFrame=capture
        try:
            image,generator,roots=self.make(native.GENERATOR_ROOTS)
            yielded=next(generator)
            del yielded
            entry=image._entry
            injected=[]
            def fail_after_real_entry(*args):
                returned=entry(*args)
                raw=ctypes.string_at(args[0],args[1])
                event=int.from_bytes(raw[8:16],'little')
                if event==native.THROW_GENERATOR:
                    injected.append(event)
                    raise OSError('lost confirmed return after actual HIA throw entry')
                return returned
            image._entry=fail_after_real_entry
            error=RuntimeError('original pending throw')
            try:
                generator.throw(error)
            except native.ServiceBootstrapUnknown as caught:
                self.assertIsInstance(caught.__cause__,OSError)
            else:self.fail('unconfirmed actual entry was accepted')
            self.assertEqual(injected,[native.THROW_GENERATOR])
            self.assertGreater(entry.calls,0)
            self.assertEqual(len(frames),1)
            frame=frames[0]()
            self.assertIsNotNone(frame)
            self.assertTrue(frame.fenced)
            self.assertTrue(frame.native_failed)
            self.assertIsNotNone(frame._delivery.loss)
            self.assertIsNotNone(roots[0]())
            self.assertIsNotNone(roots[1]())
        finally:native.ServiceBootstrapFrame=constructor

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GeneratorMechanicalLifetimeTests))
    print(json.dumps({'tests':result.testsRun,'failures':[test.id() for test,unused in result.failures],
                      'errors':[test.id() for test,unused in result.errors],'skips':len(result.skipped)},sort_keys=True),flush=True)
    sys.exit(0 if result.wasSuccessful() else 1)
