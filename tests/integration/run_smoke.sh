#!/usr/bin/env bash
# End-to-end smoke test: builds + installs the collection into a temp
# directory, mocks boto3 via PYTHONPATH/sitecustomize, then runs
# ansible-inventory --list to confirm the vars plugin is loaded and
# returns the secrets mocked in sitecustomize_mock_boto3.py.
#
# Exits non-zero if any expected per-host variable is missing — used
# both as a local sanity check and as the CI integration signal.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo_root"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Override knobs for CI / non-venv invocations. These intentionally do
# NOT use the bare PYTHON / ANSIBLE_INVENTORY / ANSIBLE_GALAXY names —
# ANSIBLE_INVENTORY in particular is Ansible's own env var for the
# inventory source path, so colliding with it makes Ansible try to
# parse the override value as an inventory file. The SMOKE_* prefix
# keeps us out of Ansible's namespace.
py=${SMOKE_PYTHON:-$repo_root/.venv/bin/python}
ansible_inventory=${SMOKE_ANSIBLE_INVENTORY:-$repo_root/.venv/bin/ansible-inventory}
ansible_galaxy=${SMOKE_ANSIBLE_GALAXY:-$repo_root/.venv/bin/ansible-galaxy}

"$ansible_galaxy" collection build . --force --output-path "$tmp" >/dev/null
"$ansible_galaxy" collection install "$tmp"/community-aws_secrets_manager-*.tar.gz \
  -p "$tmp/collections" --force >/dev/null

# Stage the boto3 mock as a sitecustomize importable from PYTHONPATH.
install -m 0644 tests/integration/sitecustomize_mock_boto3.py "$tmp/sitecustomize.py"

cd tests/integration
output=$(
  PYTHONPATH="$tmp:${PYTHONPATH:-}" \
    ANSIBLE_COLLECTIONS_PATH="$tmp/collections" \
    ANSIBLE_CONFIG="$repo_root/tests/integration/ansible.cfg" \
    AWS_REGION=us-west-2 \
    "$ansible_inventory" --list --yaml
)
echo "$output"

# Assert: per-host vars resolve correctly. Each line must appear under
# the right host's block, otherwise the prefix template wasn't honored.
fail=0
expect() {
  local pattern=$1
  if ! grep -qE "$pattern" <<<"$output"; then
    echo "smoke: missing expected line matching $pattern" >&2
    fail=1
  fi
}

expect '^[[:space:]]+web1:'
expect '^[[:space:]]+API_KEY: key-web1'
expect '^[[:space:]]+DB_HOST: db1\.internal'
expect '^[[:space:]]+DB_PASS: p1'
expect '^[[:space:]]+web2:'
expect '^[[:space:]]+DB_HOST: db2\.internal'
expect '^[[:space:]]+DB_PASS: p2'

# Negative assertion: web2 must NOT have web1's API_KEY (would mean we
# leaked vars across entities).
if grep -A4 '^[[:space:]]\+web2:' <<<"$output" | grep -q 'API_KEY'; then
  echo "smoke: web2 unexpectedly received an API_KEY (cross-host bleed)" >&2
  fail=1
fi

if [[ $fail -ne 0 ]]; then
  echo "smoke: FAILED" >&2
  exit 1
fi
echo "smoke: OK"
