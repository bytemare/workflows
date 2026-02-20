.PHONY: release go-coverage python-coverage

GO_COVERAGE_REPORT_PATH ?= coverage.out
PYTHON_COVERAGE_REPORT_PATH ?= coverage.xml

release:
	@echo "Creating a new release ..."\
	@tag=$${tag:-};\
	 if [ -z "$$tag" ]; then\
	 	 echo "Error: tag variable is not set. Use 'make release tag=vX.Y.Z'";\
	 	 exit 1;\
	 fi;\
	 git fetch origin;\
	if ! git tag -s -a "$$tag" -m "chore: cut $$tag"; then\
		echo "Error: Failed to create tag";\
		exit 1;\
	fi;\
	git push origin "$$tag"

# Generate Go coverage report
go-coverage:
	@echo "Generating Go coverage..."
	@report_path="$(GO_COVERAGE_REPORT_PATH)" && \
	    mkdir -p "$$(dirname "$$report_path")" && \
	    go test -v -race -covermode=atomic -coverpkg=../... -coverprofile="$$report_path" ../... && \
	    echo "Go coverage report generated: $$report_path"

# Generate Python coverage report
python-coverage:
	@echo "Generating Python coverage..."
	@report_path="$(PYTHON_COVERAGE_REPORT_PATH)" && \
	    mkdir -p "$$(dirname "$$report_path")" && \
	    if [ ! -d ".venv" ]; then \
	        python3 -m venv .venv; \
	    fi && \
	    . .venv/bin/activate && \
	    pip install --require-hashes --only-binary :all: --quiet -r ../tests/requirements-test.txt && \
	    pytest -c pyproject.toml ../tests/test_ort_report.py \
	        --cov=../scripts/ort-report \
	        --cov-report=xml:"$$report_path" \
	        --cov-report=term \
	        --quiet && \
	    deactivate && \
	    echo "Python coverage report generated: $$report_path"
