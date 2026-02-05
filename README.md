# Workflows
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/bytemare/workflows/badge)](https://scorecard.dev/viewer/?uri=github.com/bytemare/workflows)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11828/badge)](https://www.bestpractices.dev/projects/11828)

A collection of hardened, reusable GitHub Workflows for Go projects with high assurance supply chain security.
They don't reinvent the wheel but combine tools and best practices into easy-to-use, modular workflows.
You're welcome to use them, though they primarily target my own projects and I will adapt them accordingly.

All workflows enforce egress filtering using [Harden-Runner](https://github.com/step-security/harden-runner).

- [Ready-to-use bundled workflows (recommended)](#ready-to-use-bundled-workflows-recommended)
- [Workflow Suites](#workflow-suites)
  - [Code Scan Suite](#code-scan-suite)
  - [Lint Suite](#lint-suite)
  - [Governance Suite](#governance-suite)
  - [Test Suite](#test-suite)
- [Workflows](#workflows)
  - [CodeQL](#codeql)
  - [Govulncheck](#govulncheck)
  - [Dependency Review](#dependency-review)
  - [Semgrep](#semgrep)
  - [OpenSSF Scorecard](#openssf-scorecard)
  - [License Check](#license-check)
  - [Do not submit](#do-not-submit)
  - [SonarQube](#sonarqube)
  - [Codecov](#codecov)
  - [Go Tests](#go-tests)
- [Release Integrity (SLSA Level 3)](#release-integrity-slsa-level-3)

---

## Ready-to-use bundled workflows (recommended)

The `wf-*.yaml` files in `.github/workflows/` call all the available suites with opinionated defaults, easy to copy/paste while remaining easy to tweak:

- **`wf-analysis.yaml`** - Code scanning, SAST, linting, governance, etc., assembling all available workflows in this repo
- **`wf-release.yaml`** - SLSA Level 3 compliant releases with reproducible builds (SLSA Level 4-ready)

Copy these files to your `.github/workflows/` directory and flip the booleans or tokens to match your project’s needs.

---

## Workflow Suites

Five orchestration workflows keep caller YAML minimal while still letting you opt into the checks you need. Each suite exposes simple, typed inputs and fans out to the hardened building blocks in this repository.

### Code scan suite

Code scanners such as Semgrep, CodeQL, SonarQube, Govulncheck, Gitleaks, and Codecov. Enable a tool by setting its boolean input to `true` and supply the secret's token name.

```yaml
jobs:
  CodeScan:
    uses: bytemare/workflows/.github/workflows/codescan.yaml@[pinned commit SHA]
    permissions:
      contents: read
      security-events: write
      actions: read
    with:
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
      sonarqube-coverage-setup-go: true
      # Codecov upload
      codecov: true
      codecov-coverage-command: "go test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./..."
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

`lint.yaml` covers formatting and content/style linters across multiple languages (e.g. Go, shell, workflows, Markdown, YAML, Python, spelling) and requires no additional secrets. Super-Linter handles the heavy lifting while still giving you control over which validators run and which configuration files they consume.

```yaml
jobs:
  Lint:
    uses: bytemare/workflows/.github/workflows/lint.yaml@[pinned commit SHA]
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
        BASH,BASH_EXEC,VALIDATE_EDITORCONFIG,ENV,GITHUB_ACTIONS,GO_MODULES,MARKDOWN,PYTHON,YAML
      super-linter-rules-path: .github  # optional: defaults to .github
 ```

Set `super-linter-rules-path` if you have linter configurations.
Set `super-linter-enabled-linters` to activate specific validators.

### Governance Suite

`governance.yaml` bundles project hygiene, compliance, and reporting jobs (dependency review, license audit, Do Not Submit, Scorecard, Codecov). Tokens are passed through the workflow `secrets` block when enabled.

```yaml
jobs:
  governance:
    uses: bytemare/workflows/.github/workflows/governance.yaml@[pinned commit SHA]
    with:
      dependency-review: true
      license-check: true
      do-not-submit: true
      scorecard: true
    secrets:
      scorecard_token: ${{ secrets.SCORECARD_TOKEN }}
```

### Test Suite

`test-go.yaml` wraps provides Go testing with version matrixing.
It runs `go test -v -race -vet=all ./...` and enforces egress filtering through Harden-Runner.

```yaml
jobs:
  tests:
    uses: bytemare/workflows/.github/workflows/tests.yaml@[pinned commit SHA]
    with:
      go-versions: '["1.25", "1.24", "1.23"]'
```

All suites default to safe, conservative values. If you omit an input the workflow simply skips the corresponding capability.

## Workflows

### [CodeQL](https://github.com/github/codeql-action)

Advanced semantic code analysis to find security vulnerabilities in Go code.

**Configuration:**

```yaml
jobs:
    uses: bytemare/workflows/.github/workflows/codeql.yaml@[pinned commit SHA]
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
      artifact-metadata: read # permissions:disable-line
```

---

### [License Check](https://github.com/google/golicense)

End-to-end dependency due diligence that works for any language:

- Dependency graph submission on pull requests so GitHub understands PR-only dependencies.
- Dependency Review with a strict SPDX allow-list (`allow_spdx`) plus optional warn-only and PR summary comment modes.
- Optional high-assurance ORT analysis (`assurance: high`) that surfaces rule violations.

**Configuration:**

```yaml
jobs:
  license-check:
    uses: bytemare/workflows/.github/workflows/license-check.yaml@[pinned commit SHA]
    with:
      allow_spdx: MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,Unlicense,CC0-1.0
      warn_only: false
      use_pr_comment: true
      run_component_detection: true
      assurance: standard # switch to "high" (or use v* tags) for ORT
      ort_config_repository: https://github.com/your-org/ort-config.git # required for ORT
      ort_config_revision: main # optional pin
      ort_fail_on: violations
      ort_cli_args: ""
    permissions:
      contents: read
      pull-requests: write # required when posting PR comments
```

---

### [GitLeaks](https://github.com/gitleaks/gitleaks-action)

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
- Coverage is optional; disable it or supply a custom command for non-Go repos.

**Configuration:**

```yaml
jobs:
  sonarqube:
    uses: bytemare/workflows/.github/workflows/sonarqube.yaml@[pinned commit SHA]
    with:
      configuration: ${{ inputs.sonar-configuration }}
      coverage: false
      coverage-command: "pytest --cov=."
      coverage-setup-go: false
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

### Go Tests

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