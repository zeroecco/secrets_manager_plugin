# -*- coding: utf-8 -*-
# Copyright (c) 2026, the community.aws_secrets_manager authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

DOCUMENTATION = r"""
    name: aws_secrets
    version_added: "0.1.0"
    short_description: Load Ansible variables from AWS Secrets Manager
    description:
      - Resolves a templated prefix per host, calls C(BatchGetSecretValue) against
        AWS Secrets Manager, and exposes the contents of matching secrets as
        Ansible variables.
      - Secrets whose C(SecretString) is JSON-encoded are parsed and their keys
        merged into the host's variable namespace. Non-JSON strings are exposed
        under a sanitized key derived from the secret's basename.
      - Aggressively caches the result of each lookup in-process for
        C(cache_ttl) seconds, keyed by C((profile, region, resolved_prefix)).
        The C(cache=True) argument from the variable manager is honored.
      - Uses the C(BatchGetSecretValue) API (released 2023) which fetches up to
        20 secrets per call. With pagination this scales cheaply to entities
        that own dozens of secrets.
      - This plugin is opt-in. Add its FQCN to C(vars_plugins_enabled) in
        C(ansible.cfg) to activate it.
    author:
      - Rich (@rich)
    requirements:
      - python >= 3.9
      - boto3 >= 1.34.0
      - botocore >= 1.34.0
    extends_documentation_fragment:
      - vars_plugin_staging
    options:
      stage:
        description:
          - Stage(s) at which the plugin should run.
          - C(inventory) is recommended; the plugin is cheap enough that the
            results can be folded into inventory variables once and reused.
        type: str
        choices: ['all', 'inventory', 'task']
        default: inventory
        ini:
          - section: vars_aws_secrets
            key: stage
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_STAGE
      prefix:
        description:
          - Prefix used to filter secret names for B(host) entities.
          - Templated against C(inventory_hostname), C(inventory_hostname_short)
            and C(group_names). Note that C(group_name) is B(not) defined in
            this context; use C(group_prefix) for group-scoped lookups.
          - The resolved value is passed verbatim to the AWS C(name) filter,
            which is a case-sensitive begins-with match.
          - If unset, no host-scoped lookups are performed.
        type: str
        required: false
        ini:
          - section: vars_aws_secrets
            key: prefix
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_PREFIX
      group_prefix:
        description:
          - Prefix used to filter secret names for B(group) entities.
          - Templated against C(group_name) only. C(inventory_hostname) is
            B(not) defined in this context; mixing the two in one template
            was previously possible and was a footgun.
          - If unset (default), groups are skipped entirely.
        type: str
        required: false
        ini:
          - section: vars_aws_secrets
            key: group_prefix
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_GROUP_PREFIX
      region:
        description:
          - AWS region. If unset, falls back to the standard boto3 chain
            (C(AWS_REGION), C(AWS_DEFAULT_REGION), profile config).
        type: str
        ini:
          - section: vars_aws_secrets
            key: region
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_REGION
      profile:
        description: AWS named profile to use when constructing the boto3 session.
        type: str
        ini:
          - section: vars_aws_secrets
            key: profile
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_PROFILE
          - name: AWS_PROFILE
      cache_ttl:
        description:
          - In-process cache TTL in seconds. Set to C(0) to disable caching
            entirely (always re-fetch).
          - The TTL is independent of, but composes with, the C(cache=True)
            flag the variable manager passes to vars plugins.
        type: int
        default: 300
        ini:
          - section: vars_aws_secrets
            key: cache_ttl
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_CACHE_TTL
      nested:
        description:
          - When C(false) (default), JSON-encoded secret values are merged
            into the host's variable namespace at the top level. Last write
            wins; secrets are merged in sorted-by-name order for determinism.
          - When C(true), each secret's parsed value is exposed under a
            namespace derived from the secret's name with the prefix stripped.
        type: bool
        default: false
        ini:
          - section: vars_aws_secrets
            key: nested
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_NESTED
      strict:
        description:
          - When C(true), B(any) error from AWS — transport (C(BotoCoreError),
            C(ClientError)) B(or) per-secret entries in the response's
            C(Errors) list (e.g. C(DecryptionFailure), C(AccessDeniedException)
            on a single secret) — aborts inventory parsing.
          - When C(false), all errors are logged as warnings. Transport errors
            fall back to the most recent cached result, or an empty dict.
            Per-secret errors yield a partial result containing whatever
            secrets were successfully fetched.
        type: bool
        default: true
        ini:
          - section: vars_aws_secrets
            key: strict
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_STRICT
      binary_format:
        description:
          - How to encode C(SecretBinary) values for use as Ansible variables.
          - C(base64) (default) yields a UTF-8 string of the standard base64
            encoding. JSON-safe and easy to reverse with the C(b64decode) filter.
          - C(raw) yields a Python C(bytes) object.
          - "Warning about C(raw): bytes do not survive JSON serialization,
            so playbooks that pass these values through C(to_json), C(to_yaml),
            or copy them across worker processes (forks, callback plugins,
            fact cache) may fail. Use only when you control the consumer."
          - C(skip) drops binary secrets entirely; only string secrets are
            exposed.
        type: str
        choices: ['base64', 'raw', 'skip']
        default: base64
        ini:
          - section: vars_aws_secrets
            key: binary_format
        env:
          - name: ANSIBLE_VARS_AWS_SECRETS_BINARY_FORMAT
"""

EXAMPLES = r"""
# ansible.cfg
#   [defaults]
#   vars_plugins_enabled = host_group_vars, community.aws_secrets_manager.aws_secrets
#
#   [vars_aws_secrets]
#   prefix    = ansible/{{ inventory_hostname }}/
#   region    = us-west-2
#   cache_ttl = 600
#
# Secrets in AWS:
#   ansible/web1/database -> {"DB_HOST": "db.internal", "DB_PASS": "hunter2"}
#   ansible/web1/api      -> {"API_KEY": "abc123"}
#
# Playbook:
#   - hosts: web1
#     tasks:
#       - debug: var=DB_HOST
#       - debug: var=API_KEY
"""

import base64
import json
import os
import time
import traceback
from threading import Lock

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    HAS_BOTO3 = True
    BOTO3_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - import guard
    HAS_BOTO3 = False
    BOTO3_IMPORT_ERROR = exc

    class BotoCoreError(Exception):  # type: ignore[no-redef]
        pass

    class ClientError(Exception):  # type: ignore[no-redef]
        pass

from ansible.errors import AnsibleParserError
from ansible.inventory.host import Host
from ansible.inventory.group import Group
from ansible.plugins.vars import BaseVarsPlugin
from ansible.template import Templar
from ansible.utils.display import Display

try:
    # ansible-core 2.19+ introduced a template-trust model: a Templar will
    # only evaluate strings that have been explicitly tagged with
    # `trust_as_template`. On older versions this import doesn't exist, in
    # which case we fall back to passing the raw string through.
    from ansible.template import trust_as_template as _trust_as_template
except ImportError:  # pragma: no cover - older ansible-core
    def _trust_as_template(value):
        return value

display = Display()

# Module-level caches survive the lifetime of the ansible-core process, which
# is exactly what we want: vars plugins are re-instantiated on every call but
# the underlying boto3 client and lookup results are reusable.
_CLIENT_CACHE: dict = {}
_CLIENT_LOCK = Lock()
_RESULT_CACHE: dict = {}
_RESULT_LOCK = Lock()


def _get_client(profile, region):
    """Return a cached boto3 secretsmanager client for (profile, region)."""
    key = (profile or None, region or None)
    with _CLIENT_LOCK:
        client = _CLIENT_CACHE.get(key)
        if client is not None:
            return client
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region
        session = boto3.Session(**session_kwargs)
        client = session.client("secretsmanager")
        _CLIENT_CACHE[key] = client
        return client


def _sanitize_key(name: str, prefix: str) -> str:
    """Derive an Ansible-friendly variable name from a secret name.

    Strips the resolved prefix (if present) and converts path separators and
    other awkward characters to underscores. Falls back to the trailing path
    component when stripping leaves nothing useful.
    """
    if prefix and name.startswith(prefix):
        tail = name[len(prefix):]
    else:
        tail = name
    tail = tail.strip("/_- ")
    if not tail:
        tail = name.rsplit("/", 1)[-1]
    out = []
    for ch in tail:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    sanitized = "".join(out)
    if sanitized and sanitized[0].isdigit():
        sanitized = "_" + sanitized
    return sanitized or "secret"


class VarsModule(BaseVarsPlugin):
    """Vars plugin that pulls per-entity secrets from AWS Secrets Manager.

    Note on opt-in: vars plugins shipped in collections are NOT auto-loaded;
    they only run when their FQCN is listed in C(vars_plugins_enabled). The
    `REQUIRES_ENABLED = True` attribute is therefore unnecessary here (and
    ansible-core warns if you set it on a collection plugin); opt-in is the
    default for collection vars plugins.
    """

    is_stateless = True

    def get_vars(self, loader, path, entities, cache=True):
        if not HAS_BOTO3:
            raise AnsibleParserError(
                "The community.aws_secrets_manager.aws_secrets vars plugin "
                "requires boto3. Install it with `pip install boto3`. "
                "(import error: %s)" % BOTO3_IMPORT_ERROR
            )

        super().get_vars(loader, path, entities)

        # Vars plugins are Configurable; populate options from ini/env/etc.
        # set_options() can fail in legitimate ways (a malformed value in the
        # ini section, an env var that fails type coercion). Silently dropping
        # to vvv hid those failures and made the plugin look like a no-op
        # rather than a misconfiguration. Warn loudly; emit the traceback at
        # vvv for the operators who want it.
        try:
            self.set_options()
        except Exception as exc:
            display.warning(
                "aws_secrets: failed to load plugin options "
                "(check [vars_aws_secrets] in ansible.cfg or "
                "ANSIBLE_VARS_AWS_SECRETS_* env vars): %s: %s"
                % (type(exc).__name__, exc)
            )
            display.vvv(
                "aws_secrets: set_options traceback:\n%s" % traceback.format_exc()
            )

        prefix_template = self._opt("prefix")
        group_prefix_template = self._opt("group_prefix")

        if not prefix_template and not group_prefix_template:
            return {}

        region = self._opt("region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        profile = self._opt("profile")
        cache_ttl = int(self._opt("cache_ttl", 300) or 0)
        nested = bool(self._opt("nested", False))
        strict = bool(self._opt("strict", True))
        binary_format = self._opt("binary_format", "base64") or "base64"
        if binary_format not in ("base64", "raw", "skip"):
            display.warning(
                "aws_secrets: invalid binary_format=%r; falling back to 'base64'"
                % binary_format
            )
            binary_format = "base64"

        merged: dict = {}
        for entity in entities:
            if isinstance(entity, Host):
                if not prefix_template:
                    continue
                ctx = {
                    "inventory_hostname": entity.name,
                    "inventory_hostname_short": entity.name.split(".")[0],
                    "group_names": [g.name for g in getattr(entity, "groups", []) or []],
                }
                active_template = prefix_template
            elif isinstance(entity, Group):
                if not group_prefix_template:
                    continue
                # Deliberately scoped: only `group_name` is defined here.
                # Templates that try to use `inventory_hostname` will raise
                # AnsibleUndefinedVariable, which we surface as a warning.
                ctx = {"group_name": entity.name}
                active_template = group_prefix_template
            else:
                continue

            entity_vars = self._fetch_for_context(
                loader=loader,
                ctx=ctx,
                entity_name=entity.name,
                prefix_template=active_template,
                region=region,
                profile=profile,
                cache_ttl=cache_ttl,
                nested=nested,
                strict=strict,
                binary_format=binary_format,
                cache=cache,
            )
            merged.update(entity_vars)

        return merged

    def _opt(self, name, default=None):
        try:
            value = self.get_option(name)
        except (KeyError, AttributeError):
            return default
        return default if value is None else value

    def _fetch_for_context(
        self,
        loader,
        ctx,
        entity_name,
        prefix_template,
        region,
        profile,
        cache_ttl,
        nested,
        strict,
        binary_format,
        cache,
    ):
        # Resolve the prefix template against the entity context. We construct
        # a Templar with a minimal variable scope so that simple expressions
        # like {{ inventory_hostname }} just work without needing access to
        # accumulated host vars (which the variable manager hasn't finished
        # building when vars plugins run at the inventory stage).
        templar = Templar(loader=loader, variables=ctx)
        try:
            resolved_prefix = templar.template(_trust_as_template(prefix_template))
        except Exception as exc:
            display.warning(
                "aws_secrets: failed to template prefix %r for %s: %s"
                % (prefix_template, entity_name, exc)
            )
            return {}

        if not resolved_prefix:
            return {}

        cache_key = (profile or None, region or None, resolved_prefix)
        now = time.monotonic()

        if cache and cache_ttl > 0:
            with _RESULT_LOCK:
                entry = _RESULT_CACHE.get(cache_key)
                if entry is not None and (now - entry[0]) < cache_ttl:
                    display.vvv(
                        "aws_secrets: cache hit for %s (age=%.1fs)"
                        % (resolved_prefix, now - entry[0])
                    )
                    return dict(entry[1])

        try:
            data = self._fetch_secrets(
                resolved_prefix, region, profile, nested, strict, binary_format
            )
        except (BotoCoreError, ClientError) as exc:
            if strict:
                raise AnsibleParserError(
                    "aws_secrets: failed to fetch secrets with prefix %r: %s"
                    % (resolved_prefix, exc)
                )
            display.warning(
                "aws_secrets: failed to fetch secrets with prefix %r: %s"
                % (resolved_prefix, exc)
            )
            with _RESULT_LOCK:
                entry = _RESULT_CACHE.get(cache_key)
            return dict(entry[1]) if entry else {}

        with _RESULT_LOCK:
            _RESULT_CACHE[cache_key] = (now, data)

        return dict(data)

    def _fetch_secrets(self, prefix, region, profile, nested, strict, binary_format):
        client = _get_client(profile, region)
        # We sort the secrets by name before merging so that "last write wins"
        # collisions are deterministic across runs.
        collected: list[tuple[str, object]] = []
        # Per-secret errors returned in the response's Errors list (e.g.
        # DecryptionFailure, AccessDeniedException for an individual secret).
        # Accumulated across pagination so that strict-mode failures report
        # every problem secret, not just the first page's.
        per_secret_errors: list[dict] = []

        next_token = None
        while True:
            kwargs = {
                "Filters": [{"Key": "name", "Values": [prefix]}],
                "MaxResults": 20,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            response = client.batch_get_secret_value(**kwargs)

            for err in response.get("Errors", []) or []:
                display.warning(
                    "aws_secrets: per-secret error for %s: %s %s"
                    % (
                        err.get("SecretId"),
                        err.get("ErrorCode"),
                        err.get("Message"),
                    )
                )
                per_secret_errors.append(err)

            for secret in response.get("SecretValues", []) or []:
                name = secret.get("Name", "")
                if "SecretString" in secret and secret["SecretString"] is not None:
                    parsed = self._parse(secret["SecretString"])
                elif "SecretBinary" in secret and secret["SecretBinary"] is not None:
                    if binary_format == "skip":
                        continue
                    if binary_format == "base64":
                        parsed = base64.b64encode(secret["SecretBinary"]).decode("ascii")
                    else:  # raw
                        parsed = secret["SecretBinary"]
                else:
                    continue
                collected.append((name, parsed))

            next_token = response.get("NextToken")
            if not next_token:
                break

        if per_secret_errors and strict:
            summary = "; ".join(
                "%s: %s %s"
                % (
                    err.get("SecretId"),
                    err.get("ErrorCode"),
                    err.get("Message"),
                )
                for err in per_secret_errors
            )
            raise AnsibleParserError(
                "aws_secrets: BatchGetSecretValue returned %d per-secret error(s) "
                "with prefix %r and strict=true: %s"
                % (len(per_secret_errors), prefix, summary)
            )

        collected.sort(key=lambda item: item[0])

        result: dict = {}
        for name, parsed in collected:
            if not nested and isinstance(parsed, dict):
                result.update(parsed)
                continue
            key = _sanitize_key(name, prefix)
            result[key] = parsed
        return result

    @staticmethod
    def _parse(value):
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if not stripped or stripped[0] not in "{[":
            return value
        try:
            return json.loads(stripped)
        except (TypeError, ValueError):
            return value


def _reset_caches_for_tests() -> None:
    """Test-only helper: clear module-level caches between unit tests."""
    with _CLIENT_LOCK:
        _CLIENT_CACHE.clear()
    with _RESULT_LOCK:
        _RESULT_CACHE.clear()
