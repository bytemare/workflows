# Release Verification & Reproducibility Guide

> **Quick Start:** Jump to [Quick Verification](#quick-verification) for basic checks.  
> **Auditors/Packagers:** See [Complete Verification](#complete-verification) and [Reproducing Builds](#reproducing-builds-locally).

## Table of Contents
- [Why Verify Releases?](#why-verify-releases)
- [What We Provide](#what-we-provide)
- [Build Modes](#build-modes-lean-vs-extended)
- [Quick Verification](#quick-verification)
- [Complete Verification](#complete-verification)
- [Reproducing Builds Locally](#reproducing-builds-locally)
- [Troubleshooting](#troubleshooting)

---

## Why Verify Releases?

Modern software supply chains face risks from accidental nondeterminism to targeted tampering. This verification process ensures:

| Stakeholder                   | Benefit                                                       |
|-------------------------------|---------------------------------------------------------------|
| **Application integrators**   | Confident dependency integrity & traceability                 |
| **Security/compliance teams** | Evidence of non-falsifiable provenance & deterministic builds |
| **Distribution packagers**    | Independent rebuild & digest comparison capability            |
| **Auditors/researchers**      | Clear metadata trail for forensic analysis                    |
| **Regulated environments**    | Attestable, reproducible artifacts for policy compliance      |

**The Verification Chain:**
1. **Reproducibility** → Verifiability (same commit = same artifact)
2. **Provenance** → Authenticity (cryptographic proof of build context)
3. **Signatures** → Integrity (tamper-proof via Sigstore transparency)
4. **Manifests** → Auditability (complete dependency & environment trail)

---

## What We Provide

### Core Artifacts (Always Present)

| File                                    | Purpose                                                 | SLSA Level and requirement                      |
|-----------------------------------------|---------------------------------------------------------|-------------------------------------------------|
| `<repo>-<tag>.tar.gz`                   | Deterministic source archive (git archive + gzip `-n`)  | L3 (primary subject), L4 (reproducible)         |
| `subjects.sha256`                       | SLSA subjects list (2 lines: archive + checksums.txt)   | L3 (required input to provenance generator)     |
| `checksums.txt`                         | Aggregated SHA-256 checksums (convenience verification) | L3 (secondary subject), L4 (integrity manifest) |
| `<repo>-<tag>.tar.gz.{sig,cert,bundle}` | Cosign signatures for tarball                           | L3 (authenticity via Sigstore transparency)     |
| `checksums.txt.{sig,cert,bundle}`       | Cosign signatures for checksums manifest                | L3 (signed integrity manifest)                  |
| `sbom.cdx.json`                         | CycloneDX SBOM (dependencies + licenses)                | L3 (attested via GitHub attestations)           |
| `sbom.cdx.json.{sig,cert,bundle}`       | Cosign signatures for SBOM                              | L3 (signed dependency manifest)                 |
| `*.intoto.jsonl`                        | SLSA Level 3 provenance attestation                     | L3 (required non-falsifiable provenance)        |
| `manifest.files.sha256`                 | Per-file SHA-256 (content-addressed mapping)            | L4 (reproducibility verification aid)           |
| `commit.metadata`                       | Commit lineage (hash, tree, parents, author, subject)   | L4 (build context audit trail)                  |
| `build.env`                             | Environment snapshot (tools, versions, script hash)     | L4 (reproducibility environment fingerprint)    |
| `verification.json`                     | Machine-readable reproducibility summary                | L4 (automated policy enforcement)               |
| `scripts/package-source.sh`             | Canonical packaging recipe                              | L4 (reproducible build script)                  |

### Extended Artifacts (Optional)

Enable with `extended_metadata: true` in workflow or `EXTENDED_METADATA=true` locally.

| File                | Purpose                                     |
|---------------------|---------------------------------------------|
| `manifest.git-tree` | Git object tree structure (modes, blob IDs) |
| `go.env.json`       | Go toolchain environment (sorted JSON)      |

**Note:** Separate `.sha256` sidecar files removed for simplicity. Integrity verified via `checksums.txt` and `subjects.sha256`.

---

## Build Modes (Lean vs Extended)

| Mode               | Enable Via                | Artifacts           | Use Case                                      |
|--------------------|---------------------------|---------------------|-----------------------------------------------|
| **Lean** (default) | Default setting           | Core artifacts only | Fast builds, sufficient for most verification |
| **Extended**       | `extended_metadata: true` | + git tree + Go env | Deep forensics, regulatory compliance         |

---

## Quick Verification

**For end users who want to verify authenticity quickly.**

### Automated Verification (Recommended)

The easiest way to verify a release is using the automated verification script:

```bash
# Download the script
curl -sSL https://raw.githubusercontent.com/bytemare/workflows/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh

# Run quick verification (checksums + signatures)
./verify-release.sh --repo bytemare/workflows --tag 0.0.4

# Run full verification (all artifacts)
./verify-release.sh --repo bytemare/workflows --tag 0.0.4 --mode full

# Run containerized reproducibility check (uses golang:1.25-bookworm@sha256:42d8e9de...)
./verify-release.sh --repo bytemare/workflows --tag 0.0.4 --mode reproduce
```

**Verification Modes:**
- **quick** (default) - Basic checksum and signature verification (fast, recommended for most users).
- **full** - Complete verification of all release artifacts including SBOM and provenance.
- **reproduce** - Hermetic rebuild using the `SLSA_BUILDER_IMAGE` recorded in `build.env` (defaults to `golang:1.25-bookworm@sha256:42d8e9dea06f23d0bfc908826455213ee7f3ed48c43e287a422064220c501be9`), yielding independent SLSA Level 4 evidence.

The script automatically:
- Checks for required tools (gh, jq, cosign, openssl, sha256sum/shasum, git for full mode)
- Downloads all necessary artifacts
- Verifies checksums and signatures
- Validates SLSA provenance and SBOM (in full mode)
- Tests reproducibility (in reproduce mode)
- Provides concise one-line output with clear success/failure indicators

### Manual Verification

If you prefer to verify manually or understand the process:

### Prerequisites
- `shasum` or `sha256sum`
- `cosign` (≥2.x)
- `gh` CLI, `jq`
- `docker` (only required for `--mode reproduce`)
- `build.env` includes `SLSA_BUILDER_IMAGE=<digest>` to reconstruct the exact builder image (the verification script reads this automatically).

### Steps

**1. Download artifacts**
```bash
gh release download <tag> -p '*.tar.gz' -p '*.bundle' -p 'subjects.sha256' -p 'checksums.txt'
```

**2. Verify the tarball checksum**
```bash
ART=$(find . -maxdepth 1 -name "*.tar.gz" -type f -print -quit)
shasum -a 256 -- "${ART}" | diff - <(head -n1 subjects.sha256) && echo "✅ Tarball checksum verified"
```

**3. Verify signatures**

```bash
# Set your repository details
OWNER="bytemare"  # Replace with actual repository owner

# Verify tarball signature
cosign verify-blob \
  --bundle "${ART}.bundle" \
  --certificate-identity-regexp "^https://github\.com/${OWNER}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${ART}" && echo "✅ Tarball signature verified"

# Verify checksums signature
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "^https://github\.com/${OWNER}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt && echo "✅ Checksums signature verified"
```

**Done!** Your artifacts are authentic and untampered.

**Note:** This quick verification only checks the tarball. For complete verification of all metadata files, see the Complete Verification section below or use the automated script with `--mode full`.

---

## Complete Verification

**For security auditors and compliance requirements.**

### 1. Verify SLSA Subjects Structure

Confirm exactly 2 subjects (archive + checksums.txt):
```bash
wc -l subjects.sha256  # Should output: 2
```

### 2. Verify Primary Archive Digest

```bash
ART=$(find . -maxdepth 1 -name "*.tar.gz" -type f -print -quit)
sha256sum -- "${ART}" | diff -u - <(head -n1 subjects.sha256) \
  || echo "❌ Archive digest mismatch" >&2
```

### 3. Verify Checksums Manifest Digest

```bash
sha256sum -- checksums.txt | diff -u - <(tail -n1 subjects.sha256) \
  || echo "❌ checksums.txt digest mismatch" >&2
```

### 4. Verify Per-File Content (Deep Check)

First, download the manifest file:
```bash
gh release download <tag> -p 'manifest.files.sha256'
```

Then verify each file in the tarball:
```bash
ART=$(find . -maxdepth 1 -name "*.tar.gz" -type f -print -quit)
BASENAME="${ART%.tar.gz}"

# Save the current directory where manifest.files.sha256 is located
MANIFEST_DIR=$(pwd)

mkdir -p /tmp/verify && tar -xzf "${ART}" -C /tmp/verify
cd /tmp/verify/${BASENAME}

while read -r hash file; do
  computed=$(sha256sum -- "$file" | awk '{print $1}')
  [ "$hash" = "$computed" ] || { echo "❌ Mismatch: $file"; exit 1; }
done < "${MANIFEST_DIR}/manifest.files.sha256"

echo "✅ Per-file content verified"
cd "${MANIFEST_DIR}"
```

### 5. Verify Signatures (Alternative Methods)

**Option A: Bundle files (recommended)**
```bash
OWNER="bytemare"  # Replace with actual repository owner

cosign verify-blob \
  --bundle <file>.bundle \
  --certificate-identity-regexp "^https://github\.com/${OWNER}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <file>
```

**Option B: Separate signature + certificate**
```bash
OWNER="bytemare"  # Replace with actual repository owner

cosign verify-blob \
  --certificate <file>.cert \
  --signature <file>.sig \
  --certificate-identity-regexp "^https://github\.com/${OWNER}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <file>
```

### 6. Inspect Certificate Claims (Implicit in Signature Verification)

When using Sigstore bundles (`.bundle`), the certificate is securely packaged alongside the signature. The `cosign verify-blob` command automatically validates the entire certificate chain against the public Sigstore transparency log (Rekor).

**Therefore, a separate certificate inspection step is not required.** The successful verification of the signature in the previous steps is sufficient proof of the certificate's validity and its connection to the build.

**Note on `.cert` files:** You may notice `.cert` files attached to releases. Depending on the `cosign` version and flags used during signing, these files may be empty, contain a single certificate, or even be a bundle themselves. Attempting to manually parse them can be misleading. The authoritative source for verification is always the `.bundle` file.

### 7. Verify GitHub Attestations

Download the tarball if not already present, then verify:
```bash
ART=$(find . -maxdepth 1 -name "*.tar.gz" -type f -print -quit)
OWNER="bytemare"  # Replace with actual repository owner
REPO="workflows"  # Replace with actual repository name

gh attestation verify \
  --repo ${OWNER}/${REPO} \
  "${ART}"
```

**Note:** This verifies both SLSA provenance and SBOM attestations attached via GitHub's attestation API.

### 8. Verify SLSA Provenance File

Download the provenance file, which is a Sigstore bundle in JSON format.

```bash
gh release download <tag> -p '*.intoto.jsonl'
PROV=$(find . -maxdepth 1 -name "*.intoto.jsonl" -type f -print -quit 2>/dev/null)
```

**A) Quick Check (Digest)**

Verify the provenance bundle references the correct artifact digests from `subjects.sha256`.

```bash
if grep -q "$(head -n1 subjects.sha256 | awk '{print $1}')" "$PROV"; then
    echo "✅ Provenance references primary artifact digest"
else
    echo "❌ Provenance mismatch on primary artifact"
fi
```

**B) Deep Inspection (Attestation Content)**

The provenance attestation is a base64-encoded payload inside the bundle. To inspect its contents (like the `subject` or `builder` fields), you can decode it:

```bash
# This command extracts and pretty-prints the decoded attestation
jq -r '.dsseEnvelope.payload' "$PROV" | base64 -d | jq '.'
```

This allows an auditor to manually confirm the build type, builder ID, and other critical details.

### 9. Inspect SBOM

First, download the SBOM file:
```bash
gh release download <tag> -p 'sbom.cdx.json'
```

Then inspect it:
```bash
# Count dependencies
jq '.components | length' sbom.cdx.json

# List top dependencies
jq -r '.components[] | "\(.name)@\(.version)"' sbom.cdx.json | head -20
```

### 10. Check Reproducibility Report

First, download the verification report:
```bash
gh release download <tag> -p 'verification.json'
```

Then inspect it:
```bash
jq '.reproducibility' verification.json
```
Should show:
```json
{
  "internal_self_check": "passed",
  "extended_metadata": false,
  "file_manifest_entries": <number>
}
```

---

## Reproducing Builds Locally

**For distribution packagers and SLSA Level 4 verification.**

### Lean Mode Reproduction

```bash
TAG="v1.2.3"
REPO_URL="https://github.com/OWNER/REPO.git"

# Clone exact tag
git clone --depth=1 --branch "$TAG" "$REPO_URL" repro && cd repro

# Set required environment variables
export GITHUB_SHA=$(git rev-parse HEAD)
export GITHUB_REPOSITORY=OWNER/REPO
export GITHUB_REF_NAME=$TAG
export GITHUB_REF_TYPE=tag
export GITHUB_RUN_NUMBER=0

# Run packaging script
bash scripts/package-source.sh
```

### Extended Mode Reproduction

```bash
EXTENDED_METADATA=true bash scripts/package-source.sh
```

Extended artifacts (`manifest.git-tree`, `go.env.json`) will appear with digests in `checksums.txt`.

### Verify Reproducibility

Compare your locally built digest with the published one:
```bash
# Set your repository details
OWNER="bytemare"  # Replace with actual repository owner
REPO="workflows"  # Replace with actual repository name
TAG="0.0.4"       # Replace with the tag you're verifying

# Your local digest
local_digest=$(sha256sum dist/*.tar.gz | awk '{print $1}')

# Published digest
published_digest=$(curl -sL https://github.com/${OWNER}/${REPO}/releases/download/${TAG}/subjects.sha256 | head -n1 | awk '{print $1}')

[ "$local_digest" = "$published_digest" ] && \
  echo "✅ REPRODUCIBLE BUILD CONFIRMED" || \
  echo "❌ Digest mismatch - not reproducible"
```

### Manual Minimal Commands

For understanding the core process:
```bash
BASENAME="$(echo "${GITHUB_REPOSITORY#*/}" | sed 's/[^A-Za-z0-9._-]/_/g')-$(echo "$GITHUB_REF_NAME" | sed 's/[^A-Za-z0-9._-]/_/g')"
mkdir -p dist
ARCHIVE_PATH="dist/${BASENAME}.tar.gz"

# Create deterministic archive
git archive --format=tar --prefix="${BASENAME}/" "$GITHUB_SHA" | gzip -n -9 > "$ARCHIVE_PATH"

# Generate subject digest
sha256=$( (command -v sha256sum && sha256sum "$ARCHIVE_PATH" || shasum -a 256 "$ARCHIVE_PATH") | awk '{print $1}')
printf '%s  %s\n' "$sha256" "$(basename "$ARCHIVE_PATH")" > subjects.sha256

# Script later appends checksums.txt digest and base64-encodes for SLSA (ephemeral)
```

---

## Troubleshooting

### Common Issues & Solutions

| Issue                            | Likely Cause                                    | Solution                                                                             |
|----------------------------------|-------------------------------------------------|--------------------------------------------------------------------------------------|
| **Internal self-check fails**    | Nondeterministic FS, tool version drift         | Re-run and inspect `build.env` to confirm git/gzip versions match                    |
| **Rebuild digest mismatch**      | Hidden state dependency, incorrect env vars     | Ensure clean clone, verify `GITHUB_*` vars, and compare `manifest.files.sha256`      |
| **Per-file content mismatch**    | Line ending corruption, LFS filters             | Check for CRLF conversion and disable Git LFS filters if needed                      |
| **Missing extended artifacts**   | Extended mode not enabled                       | Re-run with `EXTENDED_METADATA=true`                                                 |
| **Signature verification fails** | Wrong file pairing, network issues              | Use bundle files for simplicity or check Rekor availability                          |
| **Cosign "unknown authority"**   | Missing Sigstore root                           | Update cosign and run `cosign initialize`                                            |
| **Certificate inspection fails** | Manually parsing `.cert` file with bundles      | Trust `cosign verify-blob --bundle`. This handles certificate validation implicitly. |
| **Invalid provenance structure** | Provenance is a Sigstore bundle, not plain JSON | Use `jq` and `base64` to decode the `.dsseEnvelope.payload` for manual inspection.   |

### Determinism Guarantees

The build process ensures reproducibility via:

1. ✅ **Hermetic builds** - The packaging job runs via a pinned digest, so inputs are locked to a known toolchain.
2. ✅ **Clean tree enforcement** - Aborts if uncommitted changes exist
3. ✅ **Stable naming** - Sanitized repo/ref names in archive prefix
4. ✅ **Archive determinism** - `git archive` + `gzip -n` (zero mtime)
5. ✅ **Locale normalization** - `LC_ALL=C`, `TZ=UTC`, `umask 022`
6. ✅ **Dual reproducibility checks**:
   - Internal: Script rebuilds & compares (fast fail)
   - External: CI rebuild job (independent workspace)
7. ✅ **Content manifest** - Per-file SHA-256 for deep verification
8. ✅ **Script integrity** - Hash stored in `build.env`
9. ✅ **Bundle convenience** - Single-file signature verification

The release workflow separates artifact creation (`package_source`) from
networked actions (`sbom_and_release`), ensuring the build step itself stays
hermetic while attestations/signatures run with a tightly scoped allowlist.

### Getting Help

- **Build issues:** Check `build.env` and `verification.json`
- **Signature issues:** Verify Rekor is accessible: `curl -I https://rekor.sigstore.dev`
- **SLSA questions:** See [SLSA spec](https://slsa.dev/spec/v1.0/levels)

---

## Additional Resources

- **Sigstore Documentation:** https://docs.sigstore.dev/
- **SLSA Framework:** https://slsa.dev/
- **Cosign CLI:** https://docs.sigstore.dev/cosign/overview/
- **CycloneDX SBOM:** https://cyclonedx.org/

---

## License

This verification guide is provided under the project's MIT license.
