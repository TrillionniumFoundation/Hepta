from pathlib import Path
import ast
root=Path('core-numeric-source83-on-v89-r3')
old=Path('core-numeric-source83-on-v89-r2/control/child.py').read_text()
fragment=(root/'negative_admission_fragment.py').read_text()
text=old.replace('"""Isolated source/VM child with native, compiler and descendant-exec poisons."""','"""Source/VM controls with four exact negative Python commands and all other entry poisons."""',1)
text=text.replace('import ctypes\n','import ctypes\nfrom hashlib import sha256\n',1).replace('import sys\n','import sys\nimport stat\nimport tempfile\n',1)
text=text.replace('from common import HERE, require, request, runtime, save','from common import HERE, identity, pin, require, request, runtime, save',1)
text=text.replace('\ndef main():\n','\n'+fragment+'\n\ndef main():\n',1)
text=text.replace("    result_code = 1\n","    current_test = {'id': None}\n    admission = NegativeAdmissions(policy, source, output, lambda: current_test['id'], forbidden)\n    result_code = 1\n",1)
text=text.replace("        'native_or_compiler_or_process_attempts': attempted, 'native_executed': False,","        'native_or_compiler_or_process_attempts': attempted, 'forbidden_attempts': attempted,\n        'source_child_process_policy': NEGATIVE_PROCESS_POLICY,\n        'allowed_negative_process_records': admission.rows,\n        'negative_permission_refusals': admission.refusals,\n        'allowed_negative_processes': 0, 'zero_process_scope_claimed': False,\n        'native_executed': False,",1)
text=text.replace("            stack.enter_context(patch.object(subprocess, 'Popen', forbidden))","            stack.enter_context(patch.object(subprocess, 'Popen', admission.popen))\n            stack.enter_context(patch.object(subprocess, 'run', admission.run))",1)
text=text.replace("                    def startTest(self, test):\n                        executed.append(test.id());\n", "UNEXPECTED")
text=text.replace("                    def startTest(self, test):\n                        executed.append(test.id())\n                        super().startTest(test)","                    def startTest(self, test):\n                        require(current_test['id'] is None, 'overlapping source-test lifecycle')\n                        current_test['id'] = test.id()\n                        executed.append(test.id())\n                        super().startTest(test)\n                    def stopTest(self, test):\n                        try:\n                            super().stopTest(test)\n                        finally:\n                            current_test['id'] = None",1)
text=text.replace("                        'one or more complete frozen source controls failed')","                        'one or more complete frozen source controls failed')\n                admission.complete()",1)
text=text.replace("        report['seconds'] = time.monotonic() - at","        report['allowed_negative_processes'] = sum(row['process_started'] is True for row in admission.rows)\n        report['forbidden_attempt_count'] = len(attempted)\n        report['seconds'] = time.monotonic() - at",1)
assert text.count('self.original_run(*arguments, **keywords)')==1
assert text.count("admission.complete()")==1
assert "UNEXPECTED" not in text
ast.parse(text)
(root/'control/child.py').write_text(text)
print(len(text.encode()))

