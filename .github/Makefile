.PHONY: release go-coverage python-coverage java-coverage typescript-coverage rust-coverage

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

# Generate Java coverage report
java-coverage:
	@echo "Generating Java coverage..."
	@cd .. && \
		mvn --batch-mode --quiet -f tests/coverage-fixtures/java/pom.xml clean test jacoco:report && \
		cp tests/coverage-fixtures/java/target/site/jacoco/jacoco.xml .github/coverage-java.xml
	@echo "Java coverage report generated: coverage-java.xml"

# Generate TypeScript coverage report
typescript-coverage:
	@echo "Generating TypeScript coverage..."
	@cd .. && \
		cd tests/coverage-fixtures/typescript && \
		npm install --quiet --no-fund --no-audit && \
		npm run --silent coverage && \
		cd ../../.. && \
		cp tests/coverage-fixtures/typescript/coverage/lcov.info .github/coverage-typescript.lcov
	@echo "TypeScript coverage report generated: coverage-typescript.lcov"

# Generate Rust coverage report
rust-coverage:
	@echo "Generating Rust coverage..."
	@cd .. && \
		cd tests/coverage-fixtures/rust && \
		cargo llvm-cov --workspace --lcov --output-path coverage/lcov.info && \
		cd ../../.. && \
		cp tests/coverage-fixtures/rust/coverage/lcov.info .github/coverage-rust.lcov
	@echo "Rust coverage report generated: coverage-rust.lcov"
