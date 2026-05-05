# -*- coding: utf-8 -*-
"""Unit tests for the community.aws_secrets_manager.aws_secrets vars plugin.

These tests load the plugin module by file path so they don't require the
collection to be installed into an ANSIBLE_COLLECTIONS_PATH. Boto3 itself is
mocked: we never make a real AWS call.
"""
from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


REPO_ROOT = Path(__file__).resolve().parents[4]
PLUGIN_PATH = REPO_ROOT / "plugins" / "vars" / "aws_secrets.py"


def _load_plugin_module():
    """Load aws_secrets.py as a standalone module for testing."""
    spec = importlib.util.spec_from_file_location(
        "aws_secrets_under_test", str(PLUGIN_PATH)
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


aws_secrets = _load_plugin_module()


class _FakeHost:
    """Stand-in for ansible.inventory.host.Host with the bits we need."""

    def __init__(self, name, groups=()):
        self.name = name
        self.groups = list(groups)


class _FakeGroup:
    def __init__(self, name):
        self.name = name


# Patch the isinstance checks in the plugin to accept our fakes.
def _install_fake_inventory_classes(monkeypatch_ish):
    monkeypatch_ish(aws_secrets, "Host", _FakeHost)
    monkeypatch_ish(aws_secrets, "Group", _FakeGroup)


class _LoaderStub:
    """Minimal DataLoader stand-in for Templar."""

    def get_basedir(self):
        return os.getcwd()


class AwsSecretsPluginTests(unittest.TestCase):
    def setUp(self):
        aws_secrets._reset_caches_for_tests()
        # Swap the strict isinstance(Host/Group) checks to use our fakes.
        self._orig_host = aws_secrets.Host
        self._orig_group = aws_secrets.Group
        aws_secrets.Host = _FakeHost
        aws_secrets.Group = _FakeGroup

    def tearDown(self):
        aws_secrets.Host = self._orig_host
        aws_secrets.Group = self._orig_group
        aws_secrets._reset_caches_for_tests()

    def _make_plugin(self, **option_overrides):
        plugin = aws_secrets.VarsModule()

        defaults = {
            "stage": "inventory",
            "prefix": "ansible/{{ inventory_hostname }}/",
            "region": "us-west-2",
            "profile": None,
            "cache_ttl": 300,
            "nested": False,
            "strict": True,
            "include_groups": False,
        }
        defaults.update(option_overrides)

        # set_options() would normally pull from ini/env. Short-circuit it.
        plugin.set_options = lambda *a, **kw: None
        plugin.get_option = lambda name: defaults.get(name)
        return plugin

    def _install_fake_client(self, response_pages):
        """Patch boto3.Session().client('secretsmanager') with a fake.

        ``response_pages`` is a list of dicts that batch_get_secret_value will
        return in order.
        """
        client = MagicMock()
        client.batch_get_secret_value.side_effect = list(response_pages)

        session = MagicMock()
        session.client.return_value = client

        boto3_mod = MagicMock()
        boto3_mod.Session.return_value = session

        patcher = patch.object(aws_secrets, "boto3", boto3_mod)
        patcher.start()
        self.addCleanup(patcher.stop)
        return client

    # ---- basic JSON merge -------------------------------------------------

    def test_json_secrets_merged_flat(self):
        client = self._install_fake_client([
            {
                "SecretValues": [
                    {
                        "Name": "ansible/web1/database",
                        "SecretString": json.dumps({"DB_HOST": "db", "DB_PASS": "x"}),
                    },
                    {
                        "Name": "ansible/web1/api",
                        "SecretString": json.dumps({"API_KEY": "k"}),
                    },
                ],
            },
        ])

        plugin = self._make_plugin()
        host = _FakeHost("web1")
        result = plugin.get_vars(_LoaderStub(), "/inv", [host])

        self.assertEqual(result, {"DB_HOST": "db", "DB_PASS": "x", "API_KEY": "k"})
        client.batch_get_secret_value.assert_called_once()
        kwargs = client.batch_get_secret_value.call_args.kwargs
        self.assertEqual(kwargs["Filters"], [{"Key": "name", "Values": ["ansible/web1/"]}])
        self.assertEqual(kwargs["MaxResults"], 20)

    def test_non_json_value_uses_basename_key(self):
        self._install_fake_client([
            {
                "SecretValues": [
                    {
                        "Name": "ansible/web1/raw-token",
                        "SecretString": "not-json-just-a-string",
                    },
                ],
            },
        ])

        plugin = self._make_plugin()
        result = plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web1")])
        self.assertEqual(result, {"raw_token": "not-json-just-a-string"})

    def test_nested_mode_namespaces_by_basename(self):
        self._install_fake_client([
            {
                "SecretValues": [
                    {
                        "Name": "ansible/web1/database",
                        "SecretString": json.dumps({"DB_HOST": "db"}),
                    },
                ],
            },
        ])

        plugin = self._make_plugin(nested=True)
        result = plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web1")])
        self.assertEqual(result, {"database": {"DB_HOST": "db"}})

    # ---- pagination -------------------------------------------------------

    def test_pagination_follows_next_token(self):
        page1 = {
            "SecretValues": [
                {"Name": "ansible/web1/a", "SecretString": json.dumps({"A": 1})},
            ],
            "NextToken": "tok",
        }
        page2 = {
            "SecretValues": [
                {"Name": "ansible/web1/b", "SecretString": json.dumps({"B": 2})},
            ],
        }
        client = self._install_fake_client([page1, page2])

        plugin = self._make_plugin()
        result = plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web1")])

        self.assertEqual(result, {"A": 1, "B": 2})
        self.assertEqual(client.batch_get_secret_value.call_count, 2)
        second_kwargs = client.batch_get_secret_value.call_args_list[1].kwargs
        self.assertEqual(second_kwargs.get("NextToken"), "tok")

    # ---- caching ----------------------------------------------------------

    def test_cache_hit_avoids_second_aws_call(self):
        client = self._install_fake_client([
            {
                "SecretValues": [
                    {"Name": "ansible/web1/x", "SecretString": json.dumps({"X": 1})},
                ],
            },
        ])

        plugin = self._make_plugin(cache_ttl=300)
        host = _FakeHost("web1")
        first = plugin.get_vars(_LoaderStub(), "/inv", [host])
        second = plugin.get_vars(_LoaderStub(), "/inv", [host])

        self.assertEqual(first, second)
        self.assertEqual(client.batch_get_secret_value.call_count, 1)

    def test_cache_disabled_when_cache_kwarg_false(self):
        client = self._install_fake_client([
            {"SecretValues": [{"Name": "ansible/web1/x", "SecretString": json.dumps({"X": 1})}]},
            {"SecretValues": [{"Name": "ansible/web1/x", "SecretString": json.dumps({"X": 2})}]},
        ])

        plugin = self._make_plugin(cache_ttl=300)
        host = _FakeHost("web1")
        first = plugin.get_vars(_LoaderStub(), "/inv", [host], cache=False)
        second = plugin.get_vars(_LoaderStub(), "/inv", [host], cache=False)

        self.assertEqual(first, {"X": 1})
        self.assertEqual(second, {"X": 2})
        self.assertEqual(client.batch_get_secret_value.call_count, 2)

    def test_cache_expires_after_ttl(self):
        client = self._install_fake_client([
            {"SecretValues": [{"Name": "ansible/web1/x", "SecretString": json.dumps({"X": 1})}]},
            {"SecretValues": [{"Name": "ansible/web1/x", "SecretString": json.dumps({"X": 2})}]},
        ])

        plugin = self._make_plugin(cache_ttl=1)
        host = _FakeHost("web1")
        # The plugin reads time.monotonic() once per _fetch_for_context call,
        # so we need exactly two values: t=0 for the first fetch, t=5 for the
        # second (>1s later → cache miss).
        with patch.object(aws_secrets.time, "monotonic", side_effect=[0.0, 5.0]):
            first = plugin.get_vars(_LoaderStub(), "/inv", [host])
            second = plugin.get_vars(_LoaderStub(), "/inv", [host])

        self.assertEqual(first, {"X": 1})
        self.assertEqual(second, {"X": 2})
        self.assertEqual(client.batch_get_secret_value.call_count, 2)

    # ---- per-host prefix templating --------------------------------------

    def test_prefix_templated_per_host(self):
        client = self._install_fake_client([
            {"SecretValues": []},
            {"SecretValues": []},
        ])

        plugin = self._make_plugin()
        plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web1")])
        plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web2")])

        prefixes = [
            call.kwargs["Filters"][0]["Values"][0]
            for call in client.batch_get_secret_value.call_args_list
        ]
        self.assertEqual(prefixes, ["ansible/web1/", "ansible/web2/"])

    # ---- error handling ---------------------------------------------------

    def test_strict_raises_on_client_error(self):
        from ansible.errors import AnsibleParserError

        # Build a ClientError compatible with whichever class the plugin loaded
        # (real botocore.ClientError or our ImportError fallback stub).
        try:
            client_error = aws_secrets.ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                "BatchGetSecretValue",
            )
        except TypeError:
            client_error = aws_secrets.ClientError("nope")

        client = MagicMock()
        client.batch_get_secret_value.side_effect = client_error
        session = MagicMock()
        session.client.return_value = client
        boto3_mod = MagicMock()
        boto3_mod.Session.return_value = session
        with patch.object(aws_secrets, "boto3", boto3_mod):
            plugin = self._make_plugin(strict=True)
            with self.assertRaises(AnsibleParserError):
                plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web1")])

    def test_non_strict_returns_empty_on_error(self):
        client = MagicMock()
        client.batch_get_secret_value.side_effect = aws_secrets.BotoCoreError()
        session = MagicMock()
        session.client.return_value = client
        boto3_mod = MagicMock()
        boto3_mod.Session.return_value = session
        with patch.object(aws_secrets, "boto3", boto3_mod):
            plugin = self._make_plugin(strict=False)
            result = plugin.get_vars(_LoaderStub(), "/inv", [_FakeHost("web1")])
        self.assertEqual(result, {})

    # ---- groups -----------------------------------------------------------

    def test_groups_skipped_by_default(self):
        client = self._install_fake_client([])
        plugin = self._make_plugin()
        result = plugin.get_vars(_LoaderStub(), "/inv", [_FakeGroup("web")])
        self.assertEqual(result, {})
        client.batch_get_secret_value.assert_not_called()

    # ---- key sanitization -------------------------------------------------

    def test_sanitize_key_strips_prefix_and_normalizes(self):
        self.assertEqual(
            aws_secrets._sanitize_key("ansible/web1/db.creds", "ansible/web1/"),
            "db_creds",
        )
        self.assertEqual(
            aws_secrets._sanitize_key("ansible/web1/api-token", "ansible/web1/"),
            "api_token",
        )
        self.assertEqual(
            aws_secrets._sanitize_key("ansible/web1/9-thing", "ansible/web1/"),
            "_9_thing",
        )


if __name__ == "__main__":
    unittest.main()
