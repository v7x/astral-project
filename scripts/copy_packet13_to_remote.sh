#!/bin/sh
# Copy reviewed Packet 13 checkout to enrolled disposable host.
set -eu

remote=${1:-testuser@aspr-test}
remote_dir=${2:-/home/testuser/astral-project}
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v rsync >/dev/null 2>&1 || {
    printf '%s\n' 'rsync is required on local host' >&2
    exit 69
}

ssh "$remote" "mkdir -p '$remote_dir'"
rsync -a --delete \
    --exclude '.git/' \
    --exclude '.venv/' \
    --exclude '.mypy_cache/' \
    --exclude '.ruff_cache/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    "$project_dir/" "$remote:$remote_dir/"

printf 'Copied %s -> %s:%s\n' "$project_dir" "$remote" "$remote_dir"
