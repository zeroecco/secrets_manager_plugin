# community.aws_secrets_manager

An Ansible **vars plugin** that pulls per-host variables from
[AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
using the `BatchGetSecretValue` API. Aggressively cached, opt-in via
`vars_plugins_enabled`, designed to be cheap enough to run on every inventory
parse.

The same niche that `community.hashi_vault` fills for HashiCorp Vault — and
the gap that has historically existed for AWS, since pre-2023 the only
options were per-secret `GetSecretValue` lookups (one round trip per secret).
`BatchGetSecretValue` (released 2023, up to 20 secrets per call) makes a
plugin written today genuinely cheap.

## Why a vars plugin and not a lookup?

A lookup runs at template time, which means every play that references a
secret pays the latency. A vars plugin runs once at inventory stage, gets
cached, and lets you reference secrets the same way you reference any other
host var:

```yaml
- hosts: web1
  tasks:
    - debug: var=DB_PASS
```

No `lookup('aws_secret', ...)`, no extra Jinja, no recomputation per task.

## Install

```bash
ansible-galaxy collection install git+https://example.invalid/community/aws_secrets_manager.git
pip install boto3
```

Or for local development:

```bash
ansible-galaxy collection build .
ansible-galaxy collection install community-aws_secrets_manager-*.tar.gz
```

## Configure

Vars plugins shipped in collections are not auto-loaded; you must list the
FQCN in `vars_plugins_enabled` to opt in. (Built-in vars plugins use
`REQUIRES_ENABLED = True` to achieve the same effect, but for collection
plugins that attribute is redundant — and ansible-core warns if you set it.)

Add to `ansible.cfg`:

```ini
[defaults]
vars_plugins_enabled = host_group_vars, community.aws_secrets_manager.aws_secrets

[vars_aws_secrets]
prefix    = ansible/{{ inventory_hostname }}/
region    = us-west-2
cache_ttl = 600
stage     = inventory
```

Or via environment variables:

```bash
export ANSIBLE_VARS_AWS_SECRETS_PREFIX='ansible/{{ inventory_hostname }}/'
export ANSIBLE_VARS_AWS_SECRETS_REGION=us-west-2
```

## How it works

1. For each host being resolved, the plugin templates `prefix` against
   `inventory_hostname` (and `inventory_hostname_short`, `group_names`).
2. It calls `BatchGetSecretValue` with `Filters=[{Key: name, Values: [prefix]}]`,
   which does a server-side prefix match. Up to 20 secrets per call, paginated
   via `NextToken`.
3. JSON-encoded `SecretString` values are parsed and merged into the host's
   variable namespace at the top level. Non-JSON values are exposed under a
   sanitized variable name derived from the secret's basename.
4. Results are cached in-process keyed by `(profile, region, resolved_prefix)`
   for `cache_ttl` seconds. The `cache=True` argument the variable manager
   passes to the plugin is honored.

## Example

Secrets in AWS:

```
ansible/web1/database -> {"DB_HOST": "db.internal", "DB_PASS": "hunter2"}
ansible/web1/api      -> {"API_KEY": "abc123"}
ansible/web2/database -> {"DB_HOST": "db2.internal", "DB_PASS": "hunter2"}
```

Playbook:

```yaml
- hosts: all
  tasks:
    - debug: var=DB_HOST
    - debug: var=API_KEY
```

`web1` sees `DB_HOST=db.internal`, `web2` sees `DB_HOST=db2.internal`.

## Options

| Option           | Default     | Description                                           |
| ---------------- | ----------- | ----------------------------------------------------- |
| `prefix`         | (required)  | Templated secret-name prefix. Server-side prefix match. |
| `region`         | env / boto3 | AWS region.                                           |
| `profile`        | env / boto3 | Named AWS profile.                                    |
| `stage`          | `inventory` | When the plugin runs (`inventory`, `task`, `all`).    |
| `cache_ttl`      | `300`       | In-process cache TTL in seconds. `0` disables.        |
| `nested`         | `false`     | Namespace each secret under its basename instead of merging JSON keys flat. |
| `strict`         | `true`      | Raise on AWS errors. When `false`, log warning and return last cached / empty. |
| `include_groups` | `false`     | Also resolve prefixes for inventory groups.           |

Each option can be set via `ansible.cfg` under `[vars_aws_secrets]` or via an
`ANSIBLE_VARS_AWS_SECRETS_*` environment variable.

## IAM

The minimum policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:BatchGetSecretValue",
        "secretsmanager:GetSecretValue",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:ansible/*"
    }
  ]
}
```

`BatchGetSecretValue` requires both `secretsmanager:BatchGetSecretValue` *and*
`secretsmanager:GetSecretValue` on each secret it returns.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/unit -v
```

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
