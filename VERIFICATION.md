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

### Prerequisites
- `shasum` or `sha256sum`
- `cosign` (≥2.x)
- Optional: `gh` CLI, `jq`

### Steps

**1. Download artifacts**
```bash
gh release download <tag> -p '*.tar.gz' -p '*.bundle' -p 'subjects.sha256'
```

**2. Verify the tarball checksum**
```bash
ART=$(ls -1 *.tar.gz | head -1)
shasum -a 256 "${ART}" | diff - <(head -n1 subjects.sha256) && echo "✅ Tarball checksum verified"
```

**3. Verify signatures (replace <owner> with repository owner, e.g., bytemare)**
```bash
cosign verify-blob \
  --bundle "${ART}.bundle" \
  --certificate-identity-regexp '^https://github\.com/<owner>/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${ART}" && echo "✅ Tarball signature verified"

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/bytemare/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt && echo "✅ Checksums signature verified"
```

**Done!** Your artifacts are authentic and untampered.

**Note:** This quick verification only checks the tarball. For complete verification of all metadata files, see the Complete Verification section below.

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
sha256sum <repo>-<tag>.tar.gz | diff -u - <(head -n1 subjects.sha256) \
  || echo "❌ Archive digest mismatch" >&2
```

### 3. Verify Checksums Manifest Digest

```bash
sha256sum checksums.txt | diff -u - <(tail -n1 subjects.sha256) \
  || echo "❌ checksums.txt digest mismatch" >&2
```

### 4. Verify Per-File Content (Deep Check)

```bash
BASENAME=<repo>-<tag>
mkdir -p /tmp/verify && tar -xzf "${BASENAME}.tar.gz" -C /tmp/verify
cd /tmp/verify/$BASENAME

while read -r hash file; do
  computed=$(sha256sum "$file" | awk '{print $1}')
  [ "$hash" = "$computed" ] || { echo "❌ Mismatch: $file"; exit 1; }
done < /path/to/manifest.files.sha256

echo "✅ Per-file content verified"
```

### 5. Verify Signatures (Alternative Methods)

**Option A: Bundle files (recommended)**
```bash
cosign verify-blob --bundle <file>.bundle <file>
```

**Option B: Separate signature + certificate**
```bash
cosign verify-blob --certificate <file>.cert --signature <file>.sig <file>
```

### 6. Inspect Certificate Claims

```bash
openssl x509 -in "${ART}.cert" -noout -text | grep -E 'Subject:|SAN:|Issuer'
```
Expect:
- **Issuer:** `https://token.actions.githubusercontent.com`
- **SAN:** Repository path (e.g., `https://github.com/owner/repo/...`)

### 7. Verify GitHub Attestations

```bash
gh attestation verify \
  --repo <owner>/<repo> \
  --subject-path "${ART}" \
  --predicate-type slsa.dev/provenance/v1
```

### 8. Verify SLSA Provenance File

```bash
PROV=$(ls -1 *.intoto.jsonl 2>/dev/null | head -1)
[ -f "$PROV" ] && \
  grep -q "$(cut -d' ' -f1 subjects.sha256)" "$PROV" && \
  echo "✅ Provenance references artifact digest" || \
  echo "❌ Provenance mismatch"
```

### 9. Inspect SBOM

```bash
# Count dependencies
jq '.components | length' sbom.cdx.json

# List top dependencies
jq -r '.components[] | "\(.name)@\(.version)"' sbom.cdx.json | head -20
```

### 10. Check Reproducibility Report

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
# Your local digest
local_digest=$(sha256sum dist/*.tar.gz | awk '{print $1}')

# Published digest
published_digest=$(curl -sL https://github.com/OWNER/REPO/releases/download/$TAG/subjects.sha256 | head -n1 | awk '{print $1}')

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

| Issue                            | Likely Cause                                | Solution                                                                    |
|----------------------------------|---------------------------------------------|-----------------------------------------------------------------------------|
| **Internal self-check fails**    | Nondeterministic FS, tool version drift     | Re-run and inspect `build.env` to confirm git/gzip versions match                |
| **Rebuild digest mismatch**      | Hidden state dependency, incorrect env vars | Ensure clean clone, verify `GITHUB_*` vars, and compare `manifest.files.sha256` |
| **Per-file content mismatch**    | Line ending corruption, LFS filters         | Check for CRLF conversion and disable Git LFS filters if needed                          |
| **Missing extended artifacts**   | Extended mode not enabled                   | Re-run with `EXTENDED_METADATA=true`                                        |
| **Signature verification fails** | Wrong file pairing, network issues          | Use bundle files for simplicity or check Rekor availability                   |
| **Cosign "unknown authority"**   | Missing Sigstore root                       | Update cosign and run `cosign initialize`                                      |

### Determinism Guarantees

The build process ensures reproducibility via:

1. ✅ **Clean tree enforcement** - Aborts if uncommitted changes exist
2. ✅ **Stable naming** - Sanitized repo/ref names in archive prefix
3. ✅ **Archive determinism** - `git archive` + `gzip -n` (zero mtime)
4. ✅ **Locale normalization** - `LC_ALL=C`, `TZ=UTC`, `umask 022`
5. ✅ **Dual reproducibility checks**:
   - Internal: Script rebuilds & compares (fast fail)
   - External: CI rebuild job (independent workspace)
6. ✅ **Content manifest** - Per-file SHA-256 for deep verification
7. ✅ **Script integrity** - Hash stored in `build.env`
8. ✅ **Bundle convenience** - Single-file signature verification

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
