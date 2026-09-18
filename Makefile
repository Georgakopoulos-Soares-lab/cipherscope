# Artifact entry points. PYTHON must import cipherscope (PYTHONPATH=src is set here)
# and, for the real-OpenFHE targets, the openfhe binding.
PYTHON ?= python3
export PYTHONPATH := src

.PHONY: test artifact-smoke reproduce-small tables checksums verify-checksums seeded gate cpp-gate

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

## Fake-backend suite, then one real-OpenFHE trace through validate/analyze/view.
artifact-smoke: test
	@$(PYTHON) -c "import openfhe" 2>/dev/null \
	  && $(MAKE) --no-print-directory smoke-real PYTHON=$(PYTHON) \
	  || echo "artifact-smoke: openfhe is not importable by $(PYTHON); fake-backend suite passed, real-OpenFHE smoke skipped"

smoke-real:
	rm -rf cipherscope-results/smoke
	$(PYTHON) -m cipherscope run --output cipherscope-results/smoke \
	  examples/profile_unmodified.py -- examples/synthetic/repeated_rotations.py
	$(PYTHON) -m cipherscope validate cipherscope-results/smoke
	$(PYTHON) -m cipherscope coverage cipherscope-results/smoke
	$(PYTHON) -m cipherscope view cipherscope-results/smoke

## Seeded benchmark + ablation + every paper table, from a clean results directory.
reproduce-small: seeded
	$(PYTHON) -m cipherscope ablate cipherscope-results/seeded/bundles/*/ \
	  --output evaluation/raw/semantic_ablation.csv
	cp cipherscope-results/seeded/case_results.json evaluation/raw/seeded/case_results.json
	$(MAKE) --no-print-directory tables PYTHON=$(PYTHON)

seeded:
	rm -rf cipherscope-results/seeded
	$(PYTHON) -m cipherscope seeded evaluation/seeded/ground_truth.json --output cipherscope-results/seeded

tables:
	rm -rf evaluation/tables
	$(PYTHON) evaluation/generate_paper_tables.py

## Developer-lane real-binding gate; set CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT/NATIVE_COMMIT per docs/evidence.md.
gate:
	CIPHERSCOPE_OPENFHE_BOOTSTRAP=1 $(PYTHON) -m tests.integration_openfhe.run_gate \
	  --output artifact/feasibility/$${CIPHERSCOPE_OPENFHE_LANE:-developer}/feasibility.json

## C++ frontend gate; needs GCC with plugin headers, CMake, and OPENFHE_DIR=<dir containing OpenFHEConfig.cmake>.
cpp-gate:
	PYTHONPATH=src:. $(PYTHON) -m tests.integration_cpp.run_gate --openfhe-dir $${OPENFHE_DIR:?set OPENFHE_DIR}

checksums:
	cd evaluation/raw && find . -type f ! -name CHECKSUMS.sha256 | LC_ALL=C sort | xargs shasum -a 256 > CHECKSUMS.sha256

verify-checksums:
	cd evaluation/raw && shasum -a 256 -c CHECKSUMS.sha256
