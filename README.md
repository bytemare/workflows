# Workflows
A collection of hardened reusable GitHub Workflows.

| Workflow          | Purpose                                                                 |
|-------------------|-------------------------------------------------------------------------|
| CodeQL            | Static analysis with CodeQL for Golang.                                 |
| GolangCI Lint     | Linting with golangci-lint.                                             |
| Govulncheck       | Vulnerability scanning with govulncheck.                                |
| Dependency-Review | Dependency review for pull requests.                                    |
| Semgrep           | Semgrep static analysis.                                                |
| SonarQube         | SonarQube static analysis.                                              |
| Codecov           | Coverage reporting with Codecov.                                        |
| Release           | Build and publish singed release artifacts (tarball, SBOM, provenance). |
| Scorecard         | OpenSSF Scorecard supply chain checks.                                  |
| Test              | Runs ```go test -v -vet=all ./...```                                    |

Note that you'll probably need to set up these tools for your repository (e.g. SonarQube, Codecov, Semgrep).


## SLSA Level 3 outputs
| Output                                                                                                          | Purpose                                                                                            |
|-----------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| *.tar.gz                                                                                                        | Deterministic source tarball (stable directory prefix + gzip -n)                                   |
| sbom.cdx.json                                                                                                   | CycloneDX SBOM (modules + licenses)                                                                |
| subjects.sha256 files (raw,.txt,.b64)                                                                           | SHA-256 digest files (raw artifact digest, friendly txt, base64 `sha256` line (for SLSA generator) |
| *.tar.gz.sig                                                                                                    | Cosign detached signature (keyless)                                                                |
| *.tar.gz.cert                                                                                                   | Fulcio-issued short-lived signing certificate                                                      |
| SLSA Level 3 provenance (in-toto predicate) and SBOM attestation | Uploaded by SLSA generator + GitHub attestations                                                   |

+ Rekor transparency log entry.


### Verifying a Release Locally
You will need: `shasum` (or `sha256sum`), `cosign` (>=2.x), optional `gh` CLI, and `jq` for JSON inspection.

#### 1. Download Artifacts
Download from the GitHub Release page (or use the CLI):
```bash
gh release download <tag> \
  -p '*.tar.gz' -p 'subjects.sha256*' -p 'sbom.cdx.json' -p '*.tar.gz.sig' -p '*.tar.gz.cert'
```

#### 2. Verify SHA-256 Digest
```bash
# Extract expected hex digest and filename
EXPECTED_LINE=$(cat subjects.sha256.txt)
# Recompute digest
ACTUAL_LINE="$(shasum -a 256 *.tar.gz | awk '{print $1"  "$2}')"
[ "$EXPECTED_LINE" = "$ACTUAL_LINE" ] && echo "Digest OK" || { echo "Digest MISMATCH"; exit 1; }
```
(Alternatively: `grep $(shasum -a 256 *.tar.gz | cut -d' ' -f1) subjects.sha256`.)

#### 3. Verify Keyless Cosign Signature
```bash
ART=$(ls -1 *.tar.gz | head -1)
cosign verify-blob \
  --certificate "${ART}.cert" \
  --signature   "${ART}.sig" \
  "${ART}"
```
Successful output indicates Rekor inclusion & certificate validity. You can inspect certificate claims:
```bash
openssl x509 -in "${ART}.cert" -noout -text | grep -E 'Subject:|SAN:|Issuer'
```
Expect OIDC issuer like `https://token.actions.githubusercontent.com` and a SAN containing the repository path.

#### 4. Inspect the SBOM
```bash
jq '.components | length as $n | {componentCount:$n}' sbom.cdx.json
# List top components
jq -r '.components[] | "\(.name)@\(.version)"' sbom.cdx.json | head -20
```

#### 5. Retrieve / Verify GitHub Native Build Attestation
If you have `gh` >= 2.50 with the attestations feature:
```bash
# Verify build provenance for the artifact path
gh attestation verify \
  --repo <owner>/<repo> \
  --subject-path "${ART}" \
  --predicate-type slsa.dev/provenance/v1
```

#### 6. Verify SLSA Provenance Asset
The SLSA generator uploads a provenance file (name may resemble `multiple.intoto.jsonl` or `<artifact>.intoto.jsonl`). After downloading:
```bash
PROV=$(ls -1 *.intoto.jsonl 2>/dev/null | head -1 || true)
[ -f "$PROV" ] && grep -q "$(cut -d' ' -f1 subjects.sha256)" "$PROV" && echo "Provenance references artifact digest" || echo "Provenance file not present or mismatch"
```
You may also feed it to the SLSA verifier tooling if you maintain internal policies.

#### 7. Cross-check Base64 Digest (Consistency)
```bash
# Reconstruct base64 from raw digest and compare
diff <(base64 -w0 subjects.sha256) subjects.sha256.b64 && echo "Base64 digest consistent" || echo "Base64 mismatch"
```