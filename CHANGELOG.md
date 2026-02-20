# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/workflows/releases).

## v0.2.0 - 27/01/2026

### Added

#### Workflow Suite Architecture
- **Three orchestration workflows** for modular, opt-in CI/CD composition
  - `suite-codescan.yaml` - Code Scan Suite: Semgrep, CodeQL, SonarQube, Govulncheck, Gitleaks, Codecov, Do Not Submit
  - `suite-lint.yaml` - Lint Suite: gofmt, Super-Linter (bash, YAML, Markdown, Python, workflows)
  - `suite-governance.yaml` - Governance Suite: Dependency Review, ORT, OpenSSF Scorecard
- **Three-tier workflow hierarchy**: Bundled workflows call suites, suites orchestrate individual tools
- **Boolean inputs** for easy tool enablement with typed parameters and secrets passthrough
- **Unified bundled workflow** (`wf-analysis.yaml`) with opinionated defaults calling all suites

#### License Compliance
- **ORT (OSS Review Toolkit) integration** for automated license and policy scanning
  - Python-based report generator with GitHub job summaries and annotations
  - Policy violation detection with configurable fail modes
  - Repository exclusion and resolution configuration support
  - Comprehensive test suite with 80.57% code coverage

#### Testing Infrastructure
- **Python testing framework** with cryptographically pinned dependencies
  - SHA256 hash verification for supply chain security
  - Multi-platform support (Linux x86_64, macOS ARM64)
  - pytest 9.0.2 with coverage reporting

#### Coverage Workflow Modularity
- **New reusable coverage workflows**: `suite-coverage.yaml`, `coverage-go.yaml`, and `coverage-python.yaml`.
- **Hybrid integration model**: coverage can be consumed through `suite-codescan.yaml` passthrough or by calling `suite-coverage.yaml` directly.

### Changed
- **Terminology**: "CodeScan" naming for security and code analysis workflows (previously referenced as "SAST")

#### Coverage Orchestration
- **Coverage generation moved to dedicated reusable coverage workflows** and is now executed once per workflow run.
- **Metadata-driven coverage bundling**: language producers now upload `coverage-report-<language>` artifacts containing coverage files plus `coverage-metadata.json`, and the bundle job aggregates them generically.
- **Dynamic SonarQube Python versioning**: `coverage-python-version` now flows through coverage metadata/manifest and sets `sonar.python.version` automatically when Python coverage is present.
- **SonarQube and Codecov workflows now consume coverage artifacts** (`coverage-report-all`) via a manifest (`coverage/manifest.json`) instead of executing coverage commands.
- **Top-level `wf-analysis.yaml` now uses shared coverage inputs** (`coverage-enabled` plus Go/Python coverage commands) to avoid duplicate coverage execution.
- **Consumer manifest resolution is strict**: `coverage-manifest-path` must exist exactly (no fallback lookup).
- **Coverage make helpers now support configurable output paths and package targets** via `GO_COVERAGE_REPORT_PATH`, `GO_COVERAGE_PACKAGE`, `GO_COVERAGE_TEST_TARGET`, and `PYTHON_COVERAGE_REPORT_PATH`.

#### Test Workflow
- **`test-go.yaml` now supports an optional `test-command` input** to override the default Go test command.

#### Repository Go Fixture Layout
- **Go smoke fixture moved from repo root to `tests`** (`tests/go.mod`, `tests/examples_test.go`, `tests/internal/addition.go`, and `tests/addition_test.go`).
- **Root Go workspace shim added**: `go.work` keeps root-run Go commands that target the fixture path working without presenting the repository as a root Go module.
- **Govulncheck package targeting is now configurable**: `govulncheck.yaml` adds `go-package`, and `suite-codescan.yaml` forwards it via `govulncheck-go-package`.

### Removed
- **Breaking API removal in `suite-codescan.yaml`**: removed `sonarqube-coverage`, `sonarqube-coverage-command`, `sonarqube-setup-go`, `codecov-coverage-command`, `codecov-coverage-file`, and `codecov-setup-go`.
- **Breaking API removal in `sonarqube.yaml`**: removed command-based coverage inputs (`coverage`, `coverage-command`, `setup-go`) in favor of artifact+manifest inputs.
- **Breaking API removal in `codecov.yaml`**: removed command/file-based coverage inputs (`coverage-command`, `coverage-file`, `setup-go`) in favor of artifact+manifest inputs.

### Security
- **Supply chain hardening** via SHA256-pinned Python dependencies
- **Command injection prevention** in ORT annotation generation
- **License policy enforcement** through ORT evaluation

## v0.1.0 - 27/01/2026

### Releasing
- SLSA Level 3 provenance generation integrated into release workflow.

### Documentation
- Added governance and releasing documents to docs/
- Upgraded Code of Conduct to Contributor Covenant 3.0.
