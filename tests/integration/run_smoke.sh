#!/usr/bin/env bash
# End-to-end smoke test: builds + installs the collection into a temp
# directory, mocks boto3 via PYTHONPATH/sitecustomize, then runs
# ansible-inventory --list to confirm the vars plugin is loaded and
# returns the secrets mocked in sitecustomize_mock_boto3.py.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

py=${PYTHON:-$repo_root/.venv/bin/python}
ansible_inventory=${ANSIBLE_INVENTORY:-$repo_root/.venv/bin/ansible-inventory}
ansible_galaxy=${ANSIBLE_GALAXY:-$repo_root/.venv/bin/ansible-galaxy}

"$ansible_galaxy" collection build . --force --output-path "$tmp" >/dev/null
"$ansible_galaxy" collection install "$tmp"/community-aws_secrets_manager-*.tar.gz \
  -p "$tmp/collections" --force >/dev/null

# Stage the boto3 mock as a sitecustomize importable from PYTHONPATH.
install -m 0644 tests/integration/sitecustomize_mock_boto3.py "$tmp/sitecustomize.py"

cd tests/integration
PYTHONPATH="$tmp:${PYTHONPATH:-}" \
  ANSIBLE_COLLECTIONS_PATH="$tmp/collections" \
  ANSIBLE_CONFIG="$repo_root/tests/integration/ansible.cfg" \
  AWS_REGION=us-west-2 \
  "$ansible_inventory" --list --yaml
