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
ansible-galaxy collection install git+https://github.com/zeroecco/secrets_manager_plugin.git
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

```text
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

| Option          | Default     | Description                                                                                       |
| --------------- | ----------- | ------------------------------------------------------------------------------------------------- |
| `prefix`        | _(unset)_   | Templated secret-name prefix for **host** entities. Resolved against `inventory_hostname`.        |
| `group_prefix`  | _(unset)_   | Templated secret-name prefix for **group** entities. Resolved against `group_name` only.          |
| `region`        | env / boto3 | AWS region.                                                                                       |
| `profile`       | env / boto3 | Named AWS profile.                                                                                |
| `stage`         | `inventory` | When the plugin runs (`inventory`, `task`, `all`).                                                |
| `cache_ttl`     | `300`       | In-process cache TTL in seconds. `0` disables.                                                    |
| `nested`        | `false`     | Namespace each secret under its basename instead of merging JSON keys flat.                       |
| `strict`        | `true`      | Raise on **any** AWS error (transport or per-secret). When `false`, warn + partial/cached return. |
| `binary_format` | `base64`    | How to expose `SecretBinary` values: `base64` (string), `raw` (bytes), or `skip` (drop).          |

If both `prefix` and `group_prefix` are unset the plugin is a no-op. Set
either or both. Each option can be set via `ansible.cfg` under
`[vars_aws_secrets]` or via an `ANSIBLE_VARS_AWS_SECRETS_*` environment
variable.

### `strict` semantics

Two failure modes look identical from a caller's perspective but want
different ergonomics. `strict` ties them together:

- **Transport errors** (`BotoCoreError`, `ClientError` from `boto3` itself
  — bad creds, network timeout, throttling, region misconfigured).
- **Per-secret errors** in the `BatchGetSecretValue` response's `Errors`
  list (e.g. `DecryptionFailure` because KMS denied this caller for one
  particular secret, `AccessDeniedException` on a single ARN).

When `strict=true` (default), either kind aborts inventory parsing with a
clear `AnsibleParserError`. Per-secret errors are aggregated across all
paginated pages so the failure message lists every problem secret, not
just the first one.

When `strict=false`, transport errors fall back to the most recent cached
result or an empty dict; per-secret errors yield a partial result
containing whatever did fetch successfully. Both paths log warnings.

### Host vs. group prefix templates

`prefix` and `group_prefix` are deliberately separate. The host context
defines `inventory_hostname`, `inventory_hostname_short`, and
`group_names`; the group context defines only `group_name`. Mixing them
across templates was previously possible (groups quietly received
`inventory_hostname=<group_name>`), which produced confusing failure
modes. Now an out-of-scope variable raises `AnsibleUndefinedVariable`,
which the plugin surfaces as a warning and a no-op for that entity.

### Binary secret values

`SecretBinary` is returned by AWS as `bytes`. By default the plugin
base64-encodes it into an ASCII string so it survives JSON/YAML
serialization, fact caches, and inter-process copies. Reverse it in a
playbook with the `b64decode` filter:

```yaml
- copy:
    content: "{{ tls_key_pem | b64decode }}"
    dest: /etc/ssl/private/host.key
```

Use `binary_format: raw` only if you control the consumer end-to-end —
Python `bytes` objects cannot round-trip through JSON, so they will break
fact caching, callback plugins, and many third-party modules. Use
`binary_format: skip` to drop binary secrets entirely.

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

`BatchGetSecretValue` requires both `secretsmanager:BatchGetSecretValue` _and_
`secretsmanager:GetSecretValue` on each secret it returns.

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/unit -v
```

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
