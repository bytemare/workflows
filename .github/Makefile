.PHONY: release coverage

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
	@go test -v -race -covermode=atomic -coverpkg=../... -coverprofile=coverage.out ../
	@echo "Go coverage report generated: coverage.out"

# Generate Python coverage report
python-coverage:
	@echo "Generating Python coverage..."
	@cd .. && \
	    if [ ! -d ".venv" ]; then \
	        python3 -m venv .venv; \
	    fi && \
	    . .venv/bin/activate && \
	    pip install --require-hashes --only-binary :all: --quiet -r tests/requirements-test.txt && \
	    pytest -c .github/pyproject.toml tests/test_ort_report.py \
	        --cov=scripts/ort-report \
	        --cov-report=xml \
	        --cov-report=term \
	        --quiet && \
	    deactivate
	@echo "Python coverage report generated: coverage.xml"
