PYTHON ?= python

.PHONY: check native bench release examples groups formal cross
check:
	$(PYTHON) -m unittest discover -s tests -v
native:
	$(PYTHON) tools/validate.py --output artifacts/native-validation.json
	$(PYTHON) tools/abi_fuzz.py --output artifacts/abi-matrix.json
bench:
	$(PYTHON) tools/validate.py --bench --output artifacts/native-validation.json
	$(PYTHON) tools/benchmark_suite.py --output artifacts/representative-benchmarks.json
examples:
	$(PYTHON) -m hepta run examples/parser.hepta
	$(PYTHON) -m hepta run examples/ownership.hepta
	$(PYTHON) -m hepta run examples/tasks.hepta
	$(PYTHON) -m hepta run examples/results.hepta
	$(PYTHON) -m hepta run examples/packages/app --locked
groups:
	$(PYTHON) tools/validate_groups.py --repeats 3 --output evidence/groups/native_validation.json
formal:
	$(PYTHON) tools/verify_formal.py
cross:
	$(PYTHON) tools/validate_cross.py
release:
	$(PYTHON) tools/release_check.py
