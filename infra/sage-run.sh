#!/usr/bin/env bash
# Thin wrapper around `docker run sagemath/sagemath`.
#
# Usage:
#   bash infra/sage-run.sh script.sage             # run a .sage file
#   bash infra/sage-run.sh -c 'print(factor(42))'  # inline expression
#   bash infra/sage-run.sh shell                   # interactive bash
#   bash infra/sage-run.sh sage                    # interactive sage REPL
#
# The repo root is mounted at /work inside the container.
# Working directory inside the container is /work, so relative paths resolve
# against the repo root.
#
# Exit codes pass through from the container.

set -e

IMG="${SAGE_IMG:-sagemath/sagemath:latest}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# Convert Windows path to Unix-style for Docker Desktop on Windows
if [[ "$REPO" =~ ^/[a-z]/ ]]; then
    # git-bash-style: /c/Users/... → C:\Users\...
    DRIVE="${REPO:1:1}"
    REST="${REPO:2}"
    REPO_WIN="${DRIVE^^}:${REST//\//\\}"
    MOUNT="$REPO_WIN"
else
    MOUNT="$REPO"
fi

run_docker() {
    docker run --rm -i -v "${MOUNT}:/work" -w /work "$IMG" "$@"
}

run_docker_tty() {
    docker run --rm -it -v "${MOUNT}:/work" -w /work "$IMG" "$@"
}

case "${1:-}" in
    "")
        echo "Usage: $0 {script.sage|-c 'expr'|shell|sage}" >&2
        exit 2
        ;;
    shell)
        run_docker_tty bash
        ;;
    sage)
        run_docker_tty sage
        ;;
    -c)
        shift
        run_docker sage -c "$*"
        ;;
    *)
        # Assume it's a .sage or .py script path relative to repo root
        run_docker sage "$@"
        ;;
esac
