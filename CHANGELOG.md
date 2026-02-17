# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/ecc/releases).

## [Unreleased]

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

### Changed
- **Terminology**: "CodeScan" naming for security and code analysis workflows (previously referenced as "SAST")

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
