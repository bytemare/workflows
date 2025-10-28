# Workflows

A collection of hardened, reusable GitHub Workflows for Go projects with high assurance supply chain security.
They don't reinvent the wheel but combine tools and best practices into easy-to-use, modular workflows.
You're welcome to use them, though they primarily target my own projects and I will adapt them accordingly.

All workflows enforce egress filtering using [Harden-Runner](https://github.com/step-security/harden-runner).

- [Workflow Suites](#workflow-suites)
  - [SAST Suite](#sast-suite)
  - [Lint Suite](#lint-suite)
  - [Governance Suite](#governance-suite)
  - [Test Suite](#test-suite)
- [Ready-to-use bundled workflows (recommended)](#ready-to-use-bundled-workflows-recommended)
- [Security Workflows](#security-workflows)
  - [CodeQL](#codeql)
  - [Govulncheck](#govulncheck)
  - [Dependency Review](#dependency-review)
  - [Semgrep](#semgrep)
  - [OpenSSF Scorecard](#openssf-scorecard)
  - [License Check](#license-check)
- [Quality Workflows](#quality-workflows)
  - [Do not submit](#do-not-submit)
  - [GolangCI Lint](#golangci-lint)
  - [SonarQube](#sonarqube)
  - [Codecov](#codecov)
- [Build & Release Workflows](#build--release-workflows)
  - [Tests](#tests)
  - [SLSA Level 3 / SLSA Level 4](#release-slsa-level-3--4)

---

## Ready-to-use bundled workflows (recommended)

The three `wf-*.yaml` files in `.github/workflows/` call all the available suites with opinionated defaults, easy to copy/paste while remaining easy to tweak:

- **`wf-tests.yaml`** - Automated testing on pull requests and main branch for Go code
- **`wf-analysis.yaml`** - Security and quality analysis (e.g. linting, CodeQL, OpenSSF Scorecard)
- **`wf-release.yaml`** - SLSA Level 3 compliant releases with reproducible builds (SLSA Level 4-ready)

Copy these files to your `.github/workflows/` directory and flip the booleans or tokens to match your project’s needs.

---

## Workflow Suites

Five orchestration workflows keep caller YAML minimal while still letting you opt into the checks you need. Each suite exposes simple, typed inputs and fans out to the hardened building blocks in this repository.

### SAST Suite

Security scanners such as Semgrep, CodeQL, SonarQube, and Govulncheck. Enable a tool by setting its boolean input to `true` and supply optional tokens inline when required.

```yaml
jobs:
  sast:
    uses: bytemare/workflows/.github/workflows/sast.yaml@[pinned sha]
    with:
      semgrep: true
      semgrep-token: ${{ secrets.SEMGREP_APP_TOKEN }}
      codeql: true
      codeql-language: go
      sonarqube: true
      sonarqube-token: ${{ secrets.SONAR_TOKEN }}
      sonarqube-configuration: .github/sonar-project.properties
      govulncheck: true
```

Tokens are optional—if you enable Semgrep or SonarQube without providing one, the suite fails fast with a clear message.

### Lint Suite

`lint.yaml` covers formatting and content/style linters across languages (Go, shell, workflows, Markdown, YAML, Python, spelling) and requires no additional secrets. Super-Linter handles the heavy lifting while still giving you control over which validators run and which configuration files they consume.

```yaml
jobs:
  lint:
    uses: bytemare/workflows/.github/workflows/lint.yaml@[pinned sha]
    with:
      gofmt: true
      super-linter: true
      super-linter-enabled-linters: BASH,GITHUB_ACTIONS,GO,GOLANGCI_LINT,MARKDOWN,YAML,PYTHON,SPELL
      super-linter-go-config: .github/.golangci.yml
      super-linter-yaml-config: .github/.yamllint
```

Defaults keep configuration terse—you only need to override items like `super-linter-go-config`, `super-linter-enabled-linters`, or supply additional config files (Markdown, YAML, Python) when diverging from the standard settings. Use `super-linter-disabled-linters` to opt out of specific validators when the defaults are too noisy.

### Governance Suite

`governance.yaml` bundles project hygiene, compliance, and reporting jobs (dependency review, license audit, Do Not Submit, Scorecard, Codecov). Tokens are passed through the workflow `secrets` block when enabled.

```yaml
jobs:
  governance:
    uses: bytemare/workflows/.github/workflows/governance.yaml@[pinned sha]
    with:
      dependency-review: true
      license-check: true
      do-not-submit: true
      scorecard: true
      codecov: true
    secrets:
      scorecard_token: ${{ secrets.SCORECARD_TOKEN }}
      codecov_token: ${{ secrets.CODECOV_TOKEN }}
```

### Test Suite

`test-go.yaml` wraps provides Go testing with version matrixing.
It runs `go test -v -race -vet=all ./...` and enforces egress filtering through Harden-Runner.

```yaml
jobs:
  tests:
    uses: bytemare/workflows/.github/workflows/tests.yaml@[pinned sha]
    with:
      go-versions: '["1.25", "1.24", "1.23"]'
```

All suites default to safe, conservative values. If you omit an input the workflow simply skips the corresponding capability.

## Security Workflows

### [CodeQL](https://github.com/github/codeql-action)

Advanced semantic code analysis to find security vulnerabilities in Go code.

**Configuration:**

```yaml
jobs:
    uses: bytemare/workflows/.github/workflows/codeql.yaml@[pinned sha]
    with:
      language: go
    permissions:
      actions: read
      contents: read
      security-events: write
```

---

### [Govulncheck](https://github.com/golang/govulncheck-action)

Scan Go dependencies for known vulnerabilities using the official Go vulnerability database.

**Configuration:**

```yaml
jobs:
  govulncheck:
    uses: bytemare/workflows/.github/workflows/govulncheck.yaml@[pinned commit SHA]
    permissions:
      contents: read
      # Needed to upload the results to code-scanning dashboard.
      security-events: write
```

---

### [Dependency Review](https://github.com/actions/dependency-review-action)

Prevent introduction of vulnerable or malicious dependencies in pull requests.

**Configuration:**

```yaml
jobs:
  dependency-review:
    uses: bytemare/workflows/.github/workflows/dependency-review.yaml@[pinned commit SHA]
    permissions:
      contents: read
```

---

### [Semgrep](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs#sample-github-actions-configuration-file)

Static code analysis tool that finds bugs, detects vulnerabilities, and enforces code standards using customizable rules.

**Note:** Requires Semgrep setup and `SEMGREP_APP_TOKEN` repository secret.

**Configuration:**

```yaml
jobs:
  Semgrep:
  permissions:
    contents: read
    # Needed to upload the results to code-scanning dashboard.
    security-events: write
  uses: bytemare/workflows/.github/workflows/semgrep.yaml@[pinned commit SHA]
  secrets:
    semgrep: ${{ secrets.SEMGREP_APP_TOKEN }}
```

---

### [OpenSSF Scorecard](https://github.com/ossf/scorecard-action)

Automated security health metrics for your repository.

**Note:** Requires OpenSSF Best Practices setup and `SCORECARD_TOKEN` repository secret.

**Configuration:**

```yaml
jobs:
  scorecard:
    uses: bytemare/workflows/.github/workflows/scorecard.yaml@[pinned commit SHA]
    secrets:
      token: ${{ secrets.SCORECARD_TOKEN }}
    permissions:
      # Needed to upload the results to code-scanning dashboard.
      security-events: write
      # Needed for GitHub OIDC token if publish_results is true.
      id-token: write
      # Needed for nested workflow
      actions: read
      # To detect SAST tools
      checks: read
      attestations: read
      contents: read
      deployments: read
      issues: read
      discussions: read
      packages: read
      pages: read
      pull-requests: read
      repository-projects: read
      statuses: read
      models: read
```

---

### [License Check](https://github.com/google/golicense)

Scans Go dependencies for compliance with an allowed license policy.

**Configuration:**

```yaml
jobs:
  license-check:
    uses: bytemare/workflows/.github/workflows/license-check.yaml@[pinned commit SHA]
    permissions:
      contents: read
```

---

## Quality Workflows

### [GolangCI Lint](https://github.com/golangci/golangci-lint-action)

Comprehensive Go code linting with 50+ linters in parallel.

**Note:** It's recommended to provide an adapted `.golangci.yml` configuration file to customize the linting rules.

**Configuration:**

```yaml
jobs:
  golangci-lint:
    name: GolangCI Lint
    uses: bytemare/workflows/.github/workflows/golangci-lint.yaml@[pinned commit SHA]
    with:
      config-path: ".github/.golangci.yml"
      scope: "./..."
    permissions:
      contents: read
```

---

### [Do not submit](https://github.com/chainguard-dev/actions/tree/main/donotsubmit)

Reminds you to not submit source that has the string "do not submit" (but in all uppercase letters) in it.

**Configuration:**

```yaml
jobs:
  DoNotSubmit:
    name: Do Not Submit
    uses: bytemare/workflows/.github/workflows/do-not-submit.yaml@[pinned commit SHA]
```

---

### [SonarQube](https://github.com/sonarsource/sonarqube-scan-action)

Continuous code quality and security inspection with detailed metrics.

**Notes:**
- Requires SonarQube setup and `SONAR_TOKEN` repository secret.
- It's recommended to provide an adapted `sonar-project.properties` configuration file.

**Configuration:**

```yaml
jobs:
  sonarqube:
    uses: bytemare/workflows/.github/workflows/sonarqube.yaml@[pinned commit SHA]
    with:
      configuration: ${{ inputs.sonar-configuration }}
    secrets:
      github: ${{ secrets.GITHUB_TOKEN }}
      sonar: ${{ secrets.SONAR_TOKEN }}
    permissions:
      contents: read
      security-events: write
```

---

### [Codecov](https://github.com/codecov/codecov-action)

Test coverage reporting and tracking with trend analysis.

**Note:** Requires Codecov setup and `CODECOV_TOKEN` repository secret.

**Configuration:**

```yaml
jobs:
  codecov:
    uses: bytemare/workflows/.github/workflows/codecov.yaml@[pinned commit SHA]
    secrets:
      codecov: ${{ secrets.CODECOV_TOKEN }}
```

---

## Build & Release Workflows

### Tests

Run your Go test suite with ```go test -v -vet=all ./...```.

**Configuration:**

```yaml
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        go: [ '1.25', '1.24', '1.23' ] # Test against multiple Go versions
      uses: bytemare/workflows/.github/workflows/wf-tests.yaml@[pinned commit SHA]
      with:
        version: ${{ matrix.go }}
```

---

### Release (SLSA Level 3 & 4)

Build and publish signed, reproducible release artifacts with SLSA Level 4 provenance.

- 🔒 **SLSA Level 4 Compliance** - Hermetic, reproducible builds with non-falsifiable provenance.
- 📦 **SBOM** - CycloneDX Software Bill of Materials
- ✍️ **Keyless Signing** - Cosign signatures with Rekor transparency logs
- 🗂️ **Complete Metadata** - Commit metadata, environment snapshots, verification reports
- ⚓️ **Native GitHub Attestations** - With the SBOM and build provenance

**Configuration:**

```yaml
name: Release

on:
  push:
    tags:
      - '*.*.*'      # Semantic versioning tags
      - 'v*.*.*'     # Tags starting with 'v'
  workflow_dispatch:  # Manual trigger
  pull_request:       # Dry-run on PRs

permissions: {}

jobs:
  release:
    uses: bytemare/workflows/.github/workflows/slsa.yaml@[pinned commit SHA]
    with:
      dry_run: ${{ github.event_name == 'pull_request' }}
      create_release: ${{ github.event_name != 'pull_request' }}
      sign_blobs: true
      extended_metadata: false  # Set to true for forensics mode
    permissions:
      contents: write           # Create releases
      id-token: write          # OIDC for signing
      attestations: write      # GitHub attestations
      actions: read            # Read workflow data
      security-events: write   # Upload SARIF (optional)
```

Quick verification using the helper script:
```bash
# Download the verification script
curl -sSL https://raw.githubusercontent.com/bytemare/workflows/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh

# Run quick verification (checksums + signatures)
./verify-release.sh --repo <owner>/<repo> --tag <tag>

# Run full verification (all artifacts)
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode full

# Run containerized reproducibility check (rebuilds inside golang:1.25-bookworm@sha256:42d8e9de...)
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode reproduce
```

See [VERIFICATION.md](VERIFICATION.md) for complete documentation and verification instructions.

## Notes

- **Pinned Dependencies:** Update the container digest (`golang:1.25-bookworm@sha256:...`) and cosign checksum in `.github/workflows/slsa.yaml` if you need to change toolchains. The packaging metadata (`build.env`) records this value under `SLSA_BUILDER_IMAGE` so verification tooling can reuse it.
- **Permissions:** All workflows use minimal permissions as per least-privilege principle
- **Secrets:** SonarQube, Codecov, and OpenSSF Scorecard require repository secrets to be configured
- **Customization:** Most workflows support additional inputs - check the workflow file for details
- **Verification tooling:** `verify-release.sh --mode reproduce` requires Docker to be available locally.

For questions or issues, see the [issue tracker](https://github.com/bytemare/workflows/issues).
