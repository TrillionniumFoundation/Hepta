.PHONY: check native bench release examples
check:
	python -m unittest discover -s tests -v
native:
	python tools/validate.py --output artifacts/native-validation.json
	python tools/abi_fuzz.py --output artifacts/abi-matrix.json
bench:
	python tools/validate.py --bench --output artifacts/native-validation.json
examples:
	python -m hepta run examples/parser.hepta
	python -m hepta run examples/ownership.hepta
	python -m hepta run examples/tasks.hepta
release:
	python tools/release_check.py
