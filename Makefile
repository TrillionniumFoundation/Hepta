.PHONY: check native bench release examples groups formal cross
check:
	python -m unittest discover -s tests -v
native:
	python tools/validate.py --output artifacts/native-validation.json
	python tools/abi_fuzz.py --output artifacts/abi-matrix.json
bench:
	python tools/validate.py --bench --output artifacts/native-validation.json
	python tools/benchmark_suite.py --output artifacts/representative-benchmarks.json
examples:
	python -m hepta run examples/parser.hepta
	python -m hepta run examples/ownership.hepta
	python -m hepta run examples/tasks.hepta
	python -m hepta run examples/results.hepta
	python -m hepta run examples/packages/app --locked
groups:
	python tools/validate_groups.py --repeats 3 --output evidence/groups/native_validation.json
formal:
	python tools/verify_formal.py
cross:
	python tools/validate_cross.py
release:
	python tools/release_check.py
