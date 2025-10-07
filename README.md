# Workflows
A collection of hardened reusable GitHub Workflows.

| Workflow          | Purpose                                                                 | Import path                                                        |
|-------------------|-------------------------------------------------------------------------|--------------------------------------------------------------------|
| CodeQL            | Static analysis with CodeQL for Golang.                                 | `bytemare/workflows/.github/workflows/codeql.yaml@main`            |
| GolangCI Lint     | Linting with golangci-lint.                                             | `bytemare/workflows/.github/workflows/golangci-lint.yaml@main`     |
| Govulncheck       | Vulnerability scanning with govulncheck.                                | `bytemare/workflows/.github/workflows/govulncheck.yaml@main`       |
| Dependency-Review | Dependency review for pull requests.                                    | `bytemare/workflows/.github/workflows/dependency-review.yaml@main` |
| Semgrep           | Semgrep static analysis.                                                | `bytemare/workflows/.github/workflows/semgrep.yaml@main`           |
| SonarQube         | SonarQube static analysis.                                              | `bytemare/workflows/.github/workflows/sonarqube.yaml@main`         |
| Codecov           | Coverage reporting with Codecov.                                        | `bytemare/workflows/.github/workflows/codecov.yaml@main`           |
| Release           | Build and publish signed release artifacts (tarball, SBOM, provenance). | `bytemare/workflows/.github/workflows/slsa-provenance.yaml@main`   |
| Scorecard         | OpenSSF Scorecard supply chain checks.                                  | `bytemare/workflows/.github/workflows/scorecard.yaml@main`         |
| Test              | Runs ```go test -v -vet=all ./...```                                    | `bytemare/workflows/.github/workflows/wf-tests.yaml@main`          |

Note that you'll probably need to set up these tools for your repository (e.g. SonarQube, Codecov, Semgrep).

## Supply Chain Security for high-assurance software distribution

This workflow provides **SLSA Level 3 compliance** with built-in **SLSA Level 4 readiness**, featuring reproducible builds, cryptographic provenance, and multiple verification layers.

### Key Features

**SLSA Level 3 Compliance:**
- 📝 Non-falsifiable provenance via SLSA generic generator
- 🔐 Isolated build environment (GitHub-hosted runners)
- ✍️ Keyless signing via Sigstore (Cosign + Rekor transparency logs)
- 🔒 Tamper-proof attestations with OIDC identity binding

**SLSA Level 4 Readiness:**
- 🔄 **Reproducible builds** - Same commit → identical digest (independently verifiable)
- 🔍 **Dual reproducibility checks** - Internal self-check + independent CI rebuild
- 📊 **Machine-readable verification** - `verification.json` for automated policy enforcement
- 🗂️ **Two-tier subject model** - Archive + checksums.txt for chained integrity verification

**Additional Supply Chain Hardening:**
- 📦 **SBOM** (Software Bill of Materials) with dependency tracking
- 🔗 **Complete audit trail** - From commit metadata to final artifact
- 📋 **Extended metadata mode** - Optional git tree + environment snapshots for forensics
- 🛡️ **Bundle-based detached signatures** - Single-file verification convenience

**What You Gain:**
1. **Reproducibility guarantees** - Distribution packagers (e.g. Debian, Nix, Homebrew) can independently verify
2. **Two-tier integrity model** - SLSA subjects (archive + checksums.txt) → metadata files
3. **Verification automation** - JSON reports for CI/CD policy gates/enforcement
4. **Extended forensics** - Optional git tree + environment snapshots for incident response
5. **Bundle convenience** - Single `.bundle` file contains signature + certificate + Rekor proof

### Quick Verification

**Requirements:** `shasum` (or `sha256sum`), `cosign` (≥2.x)

**Option A: Using GitHub CLI (recommended)**
```bash
# Download release artifacts
gh release download <tag> -p '*.tar.gz' -p '*.bundle' -p 'subjects.sha256'

# Verify the tarball checksum
ART=$(ls -1 *.tar.gz | head -1)
shasum -a 256 "${ART}" | diff - <(head -n1 subjects.sha256) && echo "✅ Tarball checksum verified"

# Verify signatures (replace <owner> with repository owner, e.g., bytemare)
cosign verify-blob \
  --bundle "${ART}.bundle" \
  --certificate-identity-regexp '^https://github\.com/<owner>/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${ART}" && echo "✅ Tarball signature verified"

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/<owner>/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt && echo "✅ Checksums signature verified"
```

**Option B: Manual download (without gh CLI)**
```bash
# Download from browser or using curl (replace owner/repo and version)
REPO="owner/repo"
TAG="v1.0.0"
OWNER="owner"
curl -LO "https://github.com/${REPO}/releases/download/${TAG}/${REPO##*/}-${TAG}.tar.gz"
curl -LO "https://github.com/${REPO}/releases/download/${TAG}/${REPO##*/}-${TAG}.tar.gz.bundle"
curl -LO "https://github.com/${REPO}/releases/download/${TAG}/checksums.txt.bundle"
curl -LO "https://github.com/${REPO}/releases/download/${TAG}/subjects.sha256"

# Verify tarball checksum
shasum -a 256 "${REPO##*/}-${TAG}.tar.gz" | diff - <(head -n1 subjects.sha256) && echo "✅ Checksum verified"

# Verify signature
cosign verify-blob \
  --bundle "${REPO##*/}-${TAG}.tar.gz.bundle" \
  --certificate-identity-regexp "^https://github\.com/${OWNER}/" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${REPO##*/}-${TAG}.tar.gz" && echo "✅ Signature verified"
```

**Note:** Replace `<owner>` with the repository owner. The checksum verification above only verifies the tarball. For complete verification of all metadata files, download them and see [VERIFICATION.md](VERIFICATION.md).

**For complete verification steps, reproducibility testing, and troubleshooting, see [VERIFICATION.md](VERIFICATION.md)**
