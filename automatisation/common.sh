#!/usr/bin/env bash
# Shared configuration for the ai-confidential-operator kind automation.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-confidential-operator}"
NAMESPACE="${NAMESPACE:-confidential-system}"
DEMO_NAMESPACE="${DEMO_NAMESPACE:-confidential-demo}"
MONITORING_NAMESPACE="${MONITORING_NAMESPACE:-monitoring}"
IMAGE_NAME="${IMAGE_NAME:-confidential-operator}"
IMAGE_TAG="${IMAGE_TAG:-dev}"
HELM_RELEASE="${HELM_RELEASE:-confidential}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
OPERATOR_DIR="${REPO_ROOT}"
CHART_DIR="${HERE}/../charts/ai-confidential-operator"
DOCKERFILE="${REPO_ROOT}/Dockerfile"

log()  { printf '\033[36m[confidential-kind]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[confidential-kind] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[confidential-kind] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed"
}
