import json,pathlib,sys,time,unittest
root,out,name,*selectors=sys.argv[1:]
sys.path.insert(0,root);out=pathlib.Path(out)
suite=unittest.defaultTestLoader.loadTestsFromNames(selectors);planned=suite.countTestCases();started=time.monotonic_ns()
with (out/(name+".log")).open("w") as stream:result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
record={"scope":name,"selectors":selectors,"planned":planned,"run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),"skips":len(result.skipped),"expected_failures":len(result.expectedFailures),"unexpected_successes":len(result.unexpectedSuccesses),"failed_ids":[x.id() for x,_ in result.failures],"error_ids":[x.id() for x,_ in result.errors],"passed":result.wasSuccessful() and not result.skipped,"wall_elapsed_ns":time.monotonic_ns()-started}
(out/(name+".json")).write_text(json.dumps(record,indent=2,sort_keys=True)+chr(10))
print(json.dumps(record,sort_keys=True))
