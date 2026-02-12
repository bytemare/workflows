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

# Generate coverage reports for Go and Python code
coverage:
	@echo "Generating Go coverage..."
	@cd .. && go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
	@echo ""
	@echo "Generating Python coverage..."
	@cd .. && \
		if [ ! -d ".venv" ]; then \
			python3 -m venv .venv; \
		fi && \
		. .venv/bin/activate && \
		pip install --quiet -r tests/requirements-test.txt && \
		pytest tests/test_ort_report.py \
			--cov=scripts/ort-report \
			--cov-report=xml \
			--cov-report=term \
			--quiet && \
		deactivate
	@echo ""
	@echo "Coverage reports generated:"
	@echo "  - coverage.out (Go)"
	@echo "  - coverage.xml (Python)"
