# Workflows
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bytemare/workflows/badge)](https://scorecard.dev/viewer/?uri=github.com/bytemare/workflows)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11828/badge)](https://www.bestpractices.dev/projects/11828)

A collection of hardened, reusable GitHub Workflows for Go projects with high assurance supply chain security.
They don't reinvent the wheel but combine tools and best practices into easy-to-use, modular workflows.
You're welcome to use them, though they primarily target my own projects and I will adapt them accordingly.

All reusable workflows that execute code enforce egress filtering using [Harden-Runner](https://github.com/step-security/harden-runner).

- [Ready-to-use bundled workflows](#ready-to-use-bundled-workflows)
  - [A single top-level workflow to use them all (recommended)](#a-single-top-level-workflow-to-use-them-all-recommended)
  - [Workflow Suites](#workflow-suites)
    - [Code Scan Suite](#code-scan-suite)
    - [Lint Suite](#lint-suite)
    - [Governance Suite](#governance-suite)
    - [Test Suite](#test-suite)
- [Individual workflows by tool](#individual-workflows-by-tool)
  - [CodeQL](#codeql)
  - [Govulncheck](#govulncheck)
  - [Dependency Review](#dependency-review)
  - [OSS Review Toolkit (ORT)](#oss-review-toolkit-ort)
  - [Semgrep](#semgrep)
  - [OpenSSF Scorecard](#openssf-scorecard)
  - [Do not submit](#do-not-submit)
  - [SonarQube](#sonarqube)
  - [Codecov](#codecov)
  - [Go Tests](#go-tests)
- [Release Integrity (SLSA Level 3)](#release-integrity-slsa-level-3)

---

## Ready-to-use bundled workflows

### A single top-level workflow to use them all (recommended)

The [wf-analysis.yaml](.github/workflows/wf-analysis.yaml) calls all the available suites with opinionated defaults, easy to copy/paste while remaining easy to tweak, including code scanning, SAST, linting, governance and license scans, etc.

Copy that file to your `.github/workflows/` directory and flip the booleans or tokens to match your project’s needs.

---

### Workflow Suites

Four orchestration workflows keep caller YAML minimal while still letting you opt into the checks you need. Each suite exposes simple, typed inputs and fans out to the hardened building blocks in this repository.

### Code scan suite

Code scanners such as Semgrep, CodeQL, SonarQube, Govulncheck, Gitleaks, Codecov, and Do Not Submit. Enable a tool by setting its boolean input to `true` and supply the secret's token name.

```yaml
jobs:
  CodeScan:
    uses: bytemare/workflows/.github/workflows/suite-codescan.yaml@[pinned commit SHA]
    permissions:
      contents: read
      security-events: write
      actions: read
    with:
      # DoNotSubmit
      do-not-submit: true
      # Semgrep
      semgrep: true
      # CodeQL
      codeql: true
      codeql-language: go # comma-separated list supported
      # SonarQube
      sonarqube: true
      sonarqube-configuration: .github/sonar-project.properties
      sonarqube-coverage: true
      sonarqube-coverage-command: "go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./..."
      sonarqube-coverage-setup-go: true # set to true when using Go
      # Codecov upload
      codecov: true
      codecov-coverage-command: "go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./..."
      codecov-coverage-file: coverage.out # optional: defaults to coverage.out
      codecov-coverage-setup-go: true # set to true when using Go
      # Govulncheck
      govulncheck: true
      # Gitleaks
      gitleaks: true
    secrets:
      # Semgrep token
      semgrep: ${{ secrets.SEMGREP_APP_TOKEN }}
      # SonarQube token
      sonarqube: ${{ secrets.SONAR_TOKEN }}
      # Codecov token
      codecov: ${{ secrets.CODECOV_TOKEN }}
```

Tokens are optional. If you enable Semgrep, SonarQube, or Codecov without providing one, the suite fails fast with a clear message. For bash, rely on Semgrep (CodeQL does not support it).

### Lint Suite

`suite-lint.yaml` covers formatting and content/style linters across multiple languages (e.g. Go, shell, workflows, Markdown, YAML, Python, spelling) and requires no additional secrets. Super-Linter handles the heavy lifting while still giving you control over which validators run and which configuration files they consume.

```yaml
jobs:
  Lint:
    uses: bytemare/workflows/.github/workflows/suite-lint.yaml@[pinned commit SHA]
    permissions:
      contents: read
      packages: read
      statuses: write
    with:
      # gofmt
      gofmt: true
      # Super-Linter
      super-linter: true
      super-linter-validate-all-codebase: true # optional: defaults to true
      super-linter-enabled-linters: |
        VALIDATE_BASH,VALIDATE_BASH_EXEC,VALIDATE_EDITORCONFIG,VALIDATE_ENV,VALIDATE_GITHUB_ACTIONS,VALIDATE_GO_MODULES,VALIDATE_MARKDOWN,VALIDATE_PYTHON,VALIDATE_YAML
      super-linter-rules-path: .github  # optional: defaults to .github
 ```

Set `super-linter-rules-path` if you have linter configurations.
Set `super-linter-enabled-linters` to activate specific validators.

### Governance Suite

`suite-governance.yaml` bundles project hygiene, compliance, and reporting jobs (dependency review, ORT license audit, OpenSSF Scorecard). Tokens are passed through the workflow `secrets` block when enabled.

```yaml
jobs:
  Governance:
    uses: bytemare/workflows/.github/workflows/suite-governance.yaml@[pinned commit SHA]
    permissions:
      contents: write
      security-events: write
      id-token: write
      actions: read
      checks: read
      attestations: read
      deployments: read
      issues: read
      discussions: read
      packages: read
      pages: read
      pull-requests: write
      repository-projects: read
      statuses: read
      models: read
      artifact-metadata: read
    with:
      # OpenSSF Scorecard
      scorecard: true
      # Dependency Review
      dependency-review: true
      # ORT
      ort: true
      # ---- Baseline PR gate (fast, GitHub-native) ----
      dependency_review_config_file: ".github/dependency-review-config.yaml"
      allow_spdx: "MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,Unlicense,CC0-1.0"
      warn_only: false              # set true for a gentle rollout
      use_pr_comment: true          # posts summary on PRs (requires pull-requests: write)
      run_component_detection: true # submits PR dependency graph for polyglot repos
      # ---- High assurance gate ORT ----
      ort_config_repository: https://github.com/oss-review-toolkit/ort-config # optional: defaults to https://github.com/oss-review-toolkit/ort-config
      ort_config_revision: "34c5d317e44e86505d0d257f2c1076deda35d9df" # optional pin for policy repository
      ort_config_source: ".github/ort" # optional repo-specific ORT config directory
      ort_config_target: "~/.ort/config" # optional ORT config target directory
      ort_fail_on: "violations" # fail mode: violations|issues|never
      ort_cli_args: "-P ort.analyzer.enabledPackageManagers=GoMod"
    secrets:
      # OpenSSF Scorecard token
      scorecard: ${{ secrets.SCORECARD_TOKEN }}
```

When enabling OpenSSF Scorecard ensure the caller job grants the required permissions (see their sections for details).

### Test Suite

`test-go.yaml` provides Go testing for a single version. Use a matrix in your caller for multiple versions (see Go Tests below).
It runs `go test -v -race -vet=all ./...` and enforces egress filtering through Harden-Runner.

```yaml
jobs:
  tests:
    uses: bytemare/workflows/.github/workflows/test-go.yaml@[pinned commit SHA]
    with:
      version: '1.25'
```

All suites default to safe, conservative values. If you omit an input the workflow simply skips the corresponding capability.

## Individual workflows by tool

### [Codecov](https://github.com/codecov/codecov-action)

Test coverage reporting and tracking with trend analysis.

**Note:** Requires Codecov setup and `CODECOV_TOKEN` repository secret. The default coverage file path is `coverage.out`.

**Configuration:**

```yaml
jobs:
  codecov:
    uses: bytemare/workflows/.github/workflows/codecov.yaml@[pinned commit SHA]
    permissions:
      contents: read
    with:
      coverage-command: "go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./..."
      coverage-file: coverage.out # optional; defaults to coverage.out
      setup-go: true # set to true if you're using Go
    secrets:
      token: ${{ secrets.CODECOV_TOKEN }}
```

---

### [CodeQL](https://github.com/github/codeql-action)

Advanced semantic code analysis to find security vulnerabilities in Go code.

**Configuration:**

```yaml
jobs:
  codeql:
    uses: bytemare/workflows/.github/workflows/codeql.yaml@[pinned commit SHA]
    with:
      language: go
    permissions:
      actions: read
      contents: read
      security-events: write
```

---

### [Dependency Review](https://github.com/actions/dependency-review-action)

Prevent introduction of vulnerable or malicious dependencies in pull requests + rapid license check.

**Configuration:**

```yaml
jobs:
  dependency-review:
    uses: bytemare/workflows/.github/workflows/dependency-review.yaml@[pinned commit SHA]
    permissions:
      contents: write
      id-token: write
      pull-requests: write
    with:
      allow_spdx: MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,Unlicense,CC0-1.0
      warn_only: false
      use_pr_comment: true
      run_component_detection: true
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

### [Gitleaks](https://github.com/gitleaks/gitleaks-action)

Detect hardcoded secrets.

```yaml
jobs:
  Gitleaks:
    permissions:
      contents: read
      security-events: write
    uses: bytemare/workflows/.github/workflows/gitleaks.yaml@[pinned commit SHA]
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

### [OSS Review Toolkit (ORT)](https://github.com/oss-review-toolkit/ort)

High-assurance license scan to detect license and policy violations.

**Configuration:**

```yaml
jobs:
  ort:
    uses: bytemare/workflows/.github/workflows/ort.yaml@[pinned commit SHA]
    with:
      ort_config_repository: https://github.com/your-org/ort-config.git # optional; set it to use your custom ORT policy
      ort_config_revision: main # optional pin of that policy
      ort_fail_on: violations
      ort_cli_args: ""
    permissions:
      contents: read
      actions: read # required for ORT job
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
      security-events: write
      id-token: write
      actions: read
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
      artifact-metadata: read
```

**Note:** OpenSSF Scorecard requires read access to many repository resources to perform comprehensive security analysis. All permissions are read-only except `security-events: write` (for uploading results) and `id-token: write` (for OIDC attestation).

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

### [SonarQube](https://github.com/sonarsource/sonarqube-scan-action)

Continuous code quality and security inspection with detailed metrics.

**Notes:**
- Requires SonarCloud setup and the `SONAR_TOKEN` repository secret.
- It's recommended to provide an adapted `sonar-project.properties` configuration file.
- Coverage is optional. You can disable it or supply a custom command for non-Go repos.

**Configuration:**

```yaml
jobs:
  sonarqube:
    uses: bytemare/workflows/.github/workflows/sonarqube.yaml@[pinned commit SHA]
    with:
      configuration: .github/sonar-project.properties
      coverage: true
      coverage-command: "go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./..."
      setup-go: true # set to true if you're using Go
    secrets:
      github: ${{ secrets.GITHUB_TOKEN }}
      sonar: ${{ secrets.SONAR_TOKEN }}
    permissions:
      contents: read
      security-events: write
```

---

### Go Tests

Run your Go test suite with `go test -v -race -vet=all ./...`.
This is equivalent to copying `wf-go-tests.yaml` from this repo.

**Configuration:**

```yaml
name: Go Tests
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        go: [ '1.25', '1.24', '1.23' ] # Test against multiple Go versions
    uses: bytemare/workflows/.github/workflows/test-go.yaml@[pinned commit SHA]
    with:
      version: ${{ matrix.go }}
```

---

## Release Integrity (SLSA Level 3)
Releases are built with the reusable [bytemare/slsa](https://github.com/bytemare/slsa) workflow and ship the evidence required for SLSA Level 3 compliance:

- 📦 Artifacts are uploaded to the release page, and include the deterministic source archive plus subjects.sha256, signed SBOM (sbom.cdx.json), GitHub provenance (*.intoto.jsonl), a reproducibility report (verification.json), and a signed Verification Summary Attestation (verification-summary.attestation.json[.bundle]).
- ✍️ All artifacts are signed using [Sigstore](https://sigstore.dev) with transparency via [Rekor](https://rekor.sigstore.dev).
- ✅ Verification (or see the latest docs at [bytemare/slsa](https://github.com/bytemare/slsa)):
```shell
curl -sSL https://raw.githubusercontent.com/bytemare/slsa/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode full --signer-repo bytemare/slsa
```
Run again with `--mode reproduce` to build in a container, or `--mode vsa` to validate just the verification summary.
