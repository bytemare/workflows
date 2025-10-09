#!/usr/bin/env bash
#
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree or at
# https://spdx.org/licenses/MIT.html
#

# This script automates the verification of SLSA Level 3 compliant releases,
# including checksum verification, signature verification, and a full, containerized
# reproducibility check.
#
# Usage:
#   ./verify-release.sh --repo OWNER/REPO --tag TAG [--mode MODE]
#
# Arguments:
#   --repo OWNER/REPO    Repository in format owner/repo (e.g., bytemare/workflows)
#   --tag TAG            Release tag to verify (e.g., 0.0.4)
#   --mode MODE          Verification mode: quick, full, or reproduce (default: quick)
#
# Modes:
#   quick     - Basic checksum and signature verification.
#   full      - Complete verification of all release artifacts (checksums, signatures, SBOM, provenance).
#   reproduce - Full, containerized reproducibility check.
#

set -euo pipefail

# Color codes for output
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_MISSING_TOOL=1
readonly EXIT_MISSING_ARG=2
readonly EXIT_VERIFICATION_FAILED=3
readonly EXIT_DOWNLOAD_FAILED=4

# Global variables
REPO=""
TAG=""
MODE="quick"
WORK_DIR=""
OWNER=""
REPO_NAME=""

# Print a verification step
verify_step() {
    local message="$1"
    printf "% -60s" "$message..."
}

verify_ok() {
    echo -e " ${GREEN}✓${NC}"
}

verify_fail() {
    local error="${1:-""}"
    echo -e " ${RED}✗${NC}"
    if [[ -n "$error" ]]; then
        echo -e "  ${RED}Error: $error${NC}" >&2
    fi
}

# Usage information
usage() {
    cat << EOF
Usage: $0 --repo OWNER/REPO --tag TAG [--mode MODE]

Verify SLSA Level 3 compliant release artifacts.

Required Arguments:
  --repo OWNER/REPO    Repository in format owner/repo (e.g., bytemare/workflows)
  --tag TAG            Release tag to verify (e.g., 0.0.4)

Optional Arguments:
  --mode MODE          Verification mode (default: quick)
                       - quick: Basic checksum and signature verification.
                       - full: Complete verification of all release artifacts.
                       - reproduce: Full, containerized reproducibility check.
  --help               Show this help message

Examples:
  $0 --repo bytemare/workflows --tag 0.0.4
  $0 --repo bytemare/workflows --tag 0.0.4 --mode full
  $0 --repo bytemare/workflows --tag 0.0.4 --mode reproduce

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --repo)
                REPO="$2"
                shift 2
                ;; 
            --tag)
                TAG="$2"
                shift 2
                ;; 
            --mode)
                MODE="$2"
                shift 2
                ;; 
            --help)
                usage
                exit $EXIT_SUCCESS
                ;; 
            *)
                echo -e "${RED}Error: Unknown argument: $1${NC}" >&2
                usage
                exit $EXIT_MISSING_ARG
                ;; 
        esac
    done

    if [[ -z "$REPO" ]]; then
        echo -e "${RED}Error: Missing required argument: --repo${NC}" >&2
        usage
        exit $EXIT_MISSING_ARG
    fi

    if [[ -z "$TAG" ]]; then
        echo -e "${RED}Error: Missing required argument: --tag${NC}" >&2
        usage
        exit $EXIT_MISSING_ARG
    fi

    if [[ "$MODE" != "quick" && "$MODE" != "full" && "$MODE" != "reproduce" ]]; then
        echo -e "${RED}Error: Invalid mode: $MODE (must be quick, full, or reproduce)${NC}" >&2
        usage
        exit $EXIT_MISSING_ARG
    fi

    OWNER="${REPO%%/*}"
    REPO_NAME="${REPO##*/}"

    if [[ -z "$OWNER" || -z "$REPO_NAME" ]]; then
        echo -e "${RED}Error: Invalid repository format. Use OWNER/REPO${NC}" >&2
        exit $EXIT_MISSING_ARG
    fi
}

# Check for required tools
check_tools() {
    local missing_tools=()
    local required_tools=("gh" "jq" "openssl" "cosign")

    if [[ "$MODE" == "reproduce" ]]; then
        required_tools=("docker")
    fi

    if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
        missing_tools+=("sha256sum or shasum")
    fi

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing required tools: ${missing_tools[*]}${NC}" >&2
        exit $EXIT_MISSING_TOOL
    fi
}

# Download release artifacts for quick/full modes
download_artifacts() {
    local patterns=(
        "*.tar.gz"
        "*.bundle"
        "subjects.sha256"
        "checksums.txt"
    )

    if [[ "$MODE" == "full" ]]; then
        patterns+=(
            "*.cert"
            "*.intoto.jsonl"
            "sbom.cdx.json"
            "verification.json"
            "manifest.files.sha256"
        )
    fi

    verify_step "Downloading release artifacts"

    for pattern in "${patterns[@]}"; do
        gh release download "$TAG" --repo "$REPO" -p "$pattern" >/dev/null 2>&1 || true
    done

    if [[ ! -f subjects.sha256 ]] || [[ ! -f checksums.txt ]]; then
        verify_fail "Critical files (subjects.sha256, checksums.txt) missing"
        return 1
    fi

    local tarball=$(ls -1 *.tar.gz 2>/dev/null | head -1)
    if [[ -z "$tarball" ]]; then
        verify_fail "Source tarball missing"
        return 1
    fi

    verify_ok
    return 0
}

# --- Verification functions for quick/full modes ---
verify_subjects() {
    verify_step "Verifying SLSA subjects structure"
    local subject_count=$(wc -l < subjects.sha256 | tr -d ' ')
    if [[ "$subject_count" -eq 2 ]]; then
        verify_ok
    else
        verify_fail "Expected 2 subjects, found $subject_count"
        return 1
    fi
}

verify_tarball_checksum() {
    verify_step "Verifying tarball checksum"
    local tarball=$(ls -1 *.tar.gz | head -1)
    local computed_hash
    if command -v sha256sum &> /dev/null; then
        computed_hash=$(sha256sum "$tarball" | awk '{print $1}')
    else
        computed_hash=$(shasum -a 256 "$tarball" | awk '{print $1}')
    fi
    local expected_hash=$(head -n1 subjects.sha256 | awk '{print $1}')
    if [[ "$computed_hash" == "$expected_hash" ]]; then
        verify_ok
    else
        verify_fail "Tarball checksum mismatch"
        return 1
    fi
}

verify_checksums_manifest() {
    verify_step "Verifying checksums manifest"
    local computed_hash
    if command -v sha256sum &> /dev/null; then
        computed_hash=$(sha256sum checksums.txt | awk '{print $1}')
    else
        computed_hash=$(shasum -a 256 checksums.txt | awk '{print $1}')
    fi
    local expected_hash=$(tail -n1 subjects.sha256 | awk '{print $1}')
    if [[ "$computed_hash" == "$expected_hash" ]]; then
        verify_ok
    else
        verify_fail "Checksum mismatch"
        return 1
    fi
}

verify_signatures() {
    local tarball=$(ls -1 *.tar.gz | head -1)
    verify_step "Verifying tarball signature"
    if cosign verify-blob --bundle "${tarball}.bundle" --certificate-identity-regexp "^https://github\.com/${OWNER}/" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" "$tarball" &> /dev/null; then
        verify_ok
    else
        verify_fail "Cosign tarball verification failed"
        return 1
    fi

    verify_step "Verifying checksums signature"
    if cosign verify-blob --bundle "checksums.txt.bundle" --certificate-identity-regexp "^https://github\.com/${OWNER}/" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" "checksums.txt" &> /dev/null; then
        verify_ok
    else
        verify_fail "Cosign checksums.txt verification failed"
        return 1
    fi
}

verify_attestations() {
    verify_step "Verifying GitHub attestations"
    local tarball=$(ls -1 *.tar.gz | head -1)
    if gh attestation verify --repo "$REPO" "$tarball" &> /dev/null; then
        verify_ok
    else
        verify_fail "Attestation verification failed"
        return 1
    fi
}

verify_provenance_file() {
    verify_step "Verifying SLSA provenance file"
    local provenance=$(ls -1 *.intoto.jsonl 2>/dev/null | head -1)
    if [[ -z "$provenance" ]]; then
        verify_fail "Provenance file not found"
        return 1
    fi
    if jq -r '.dsseEnvelope.payload' "$provenance" | base64 -d | jq -e '.subject' &>/dev/null; then
        verify_ok
    else
        verify_fail "Invalid provenance (could not find subject)"
        return 1
    fi
}

inspect_sbom() {
    verify_step "Inspecting SBOM"
    if [[ ! -f sbom.cdx.json ]]; then
        verify_fail "SBOM file not found"
        return 1
    fi
    if jq -e '.components | length' sbom.cdx.json &> /dev/null; then
        verify_ok
    else
        verify_fail "Invalid SBOM format"
        return 1
    fi
}

run_verification() {
    local exit_code=$EXIT_SUCCESS
    verify_subjects || exit_code=$EXIT_VERIFICATION_FAILED
    verify_tarball_checksum || exit_code=$EXIT_VERIFICATION_FAILED
    verify_checksums_manifest || exit_code=$EXIT_VERIFICATION_FAILED
    verify_signatures || exit_code=$EXIT_VERIFICATION_FAILED

    if [[ "$MODE" == "full" ]]; then
        verify_attestations || exit_code=$EXIT_VERIFICATION_FAILED
        verify_provenance_file || exit_code=$EXIT_VERIFICATION_FAILED
        inspect_sbom || exit_code=$EXIT_VERIFICATION_FAILED
    fi
    return $exit_code
}

# --- Reproducibility Check function for reproduce mode ---
run_repro_check() {
    local CONTAINER_SCRIPT=$(cat <<'EOS'
#!/usr/bin/env bash
#
# --- This entire script runs inside a temporary Docker container ---
#
set -euo pipefail

# --- Container Script: Variables ---
REPO="${1:-}"
TAG="${2:-}"
REPO_NAME="${3:-}"

# --- Container Script: Formatting ---
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

step() { echo -e "\n${YELLOW}--- $1 ---
${NC}"; }
info() { printf "% -50s" "$1..."; }
ok() { echo -e " ${GREEN}✓${NC}"; }
fail() {
    echo -e " ${RED}✗${NC}"
    if [[ -n "${1:-}" ]]; then echo -e "  ${RED}Error: ${1}${NC}" >&2; fi
    exit 1
}

# --- Container Script: Main Logic ---
step "Installing Dependencies (inside container)"
info "Updating apt and installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq git ca-certificates gzip wget coreutils perl-base >/dev/null
ok

info "Installing Go toolchain (1.25.x)"
wget -q -O go.tar.gz https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go.tar.gz
export PATH=/usr/local/go/bin:$PATH
rm go.tar.gz
ok

step "Fetching Original Artifact"
WORK_DIR="/tmp/verify-repro"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

ARTIFACT_NAME="${REPO_NAME}-${TAG}.tar.gz"
ARTIFACT_URL="https://github.com/$REPO/releases/download/$TAG/$ARTIFACT_NAME"
info "Downloading $ARTIFACT_NAME"
wget -q "$ARTIFACT_URL" || fail "Could not download original artifact from $ARTIFACT_URL"
ok

info "Calculating original digest"
original_digest=$(sha256sum "$ARTIFACT_NAME" | awk '{print $1}')
echo -n "$original_digest"
ok

step "Rebuilding Artifact"
info "Cloning repository"
temp_repo="/tmp/repro-repo"
git clone --branch "$TAG" "https://github.com/$REPO.git" "$temp_repo" >/dev/null 2>&1 || fail "Failed to clone repository for tag $TAG"
cd "$temp_repo"
ok

info "Running packaging script"
export GITHUB_SHA=$(git rev-parse HEAD)
export GITHUB_REPOSITORY="$REPO"
export GITHUB_REF_NAME="$TAG"
export GITHUB_REF_TYPE="tag"
export GITHUB_RUN_NUMBER="0"

set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
umask 022
SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$GITHUB_SHA")"
export SOURCE_DATE_EPOCH
sanitize() { local in="$1" out; out="${in//[^A-Za-z0-9._-]/_}"; [ -n "$out" ] || fail "Sanitized empty: $in"; printf '%s\n' "$out"; }
REPO_SAFE="$(sanitize "${GITHUB_REPOSITORY#*/}")"
TAG_SAFE="$(sanitize "${GITHUB_REF_NAME//\//_}")"
BASENAME="${REPO_SAFE}-${TAG_SAFE}"
OUTDIR=dist
mkdir -p "$OUTDIR"
ARCHIVE_PATH="${OUTDIR}/${BASENAME}.tar.gz"
git archive --format=tar --prefix="${BASENAME}/" "$GITHUB_SHA" | gzip -n -9 > "$ARCHIVE_PATH"
ok

info "Calculating rebuilt digest"
rebuilt_digest=$(sha256sum "$ARCHIVE_PATH" | awk '{print $1}')
echo -n "$rebuilt_digest"
ok

step "Comparing Digests"
info "Checking for match"
if [[ "$original_digest" == "$rebuilt_digest" ]]; then
    ok
    echo -e "\n${GREEN}✓ SUCCESS: Artifact is reproducible.${NC}"
else
    fail "Digests do not match!"
    echo -e "  Original: $original_digest" >&2
    echo -e "  Rebuilt:  $rebuilt_digest" >&2
fi
EOS
    )

    echo "--- Launching reproducibility check for $REPO @ $TAG in Docker... ---"
    docker run --rm -i "ubuntu:22.04" /bin/bash -c "$CONTAINER_SCRIPT" -- "$REPO" "$TAG" "$REPO_NAME"
    echo "--- Reproducibility check complete. ---"
    return 0
}


# Main function
main() {
    parse_args "$@"
    check_tools

    if [[ "$MODE" == "reproduce" ]]; then
        run_repro_check
        exit $?
    fi

    echo -e "\n${YELLOW}Verifying release: ${REPO} @ ${TAG} (${MODE} mode)${NC}\n"

    WORK_DIR="/tmp/verify-${REPO_NAME}-${TAG}-$$"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    if ! download_artifacts; then
        echo -e "\n${RED}Verification failed: Could not download artifacts${NC}\n"
        exit $EXIT_DOWNLOAD_FAILED
    fi

    local verification_result=$EXIT_SUCCESS
    run_verification || verification_result=$?

    echo ""
    if [[ $verification_result -eq $EXIT_SUCCESS ]]; then
        echo -e "${GREEN}✓ All verifications passed${NC}"
        echo -e "Release ${TAG} from ${REPO} is authentic and verified\n"
    else
        echo -e "${RED}✗ Some verifications failed${NC}"
        echo -e "Please review the errors above\n"
    fi

    echo "Artifacts saved in: $WORK_DIR"
    echo "To clean up: rm -rf $WORK_DIR"
    echo ""

    exit $verification_result
}

main "$@"