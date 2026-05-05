"""Test-only sitecustomize that swaps in a fake boto3 secretsmanager client.

Used by the integration smoke test (`tests/integration/run_smoke.sh`) so that
ansible-inventory can exercise the vars plugin end-to-end without ever
calling AWS. Activated by putting this directory on PYTHONPATH.
"""
from __future__ import annotations

import json
import sys
import types
from unittest.mock import MagicMock


def _build_fake_boto3() -> types.ModuleType:
    boto3 = types.ModuleType("boto3")

    secrets_by_prefix = {
        "ansible/web1/": [
            {
                "Name": "ansible/web1/database",
                "SecretString": json.dumps({"DB_HOST": "db1.internal", "DB_PASS": "p1"}),
            },
            {
                "Name": "ansible/web1/api",
                "SecretString": json.dumps({"API_KEY": "key-web1"}),
            },
        ],
        "ansible/web2/": [
            {
                "Name": "ansible/web2/database",
                "SecretString": json.dumps({"DB_HOST": "db2.internal", "DB_PASS": "p2"}),
            },
        ],
    }

    def batch_get_secret_value(**kwargs):
        prefix = kwargs["Filters"][0]["Values"][0]
        return {"SecretValues": secrets_by_prefix.get(prefix, [])}

    client = MagicMock()
    client.batch_get_secret_value.side_effect = batch_get_secret_value

    session = MagicMock()
    session.client.return_value = client

    boto3.Session = MagicMock(return_value=session)

    botocore = types.ModuleType("botocore")
    botocore_exceptions = types.ModuleType("botocore.exceptions")

    class BotoCoreError(Exception):
        pass

    class ClientError(Exception):
        def __init__(self, *args, **kwargs):
            super().__init__(*args)

    botocore_exceptions.BotoCoreError = BotoCoreError
    botocore_exceptions.ClientError = ClientError
    botocore.exceptions = botocore_exceptions

    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = botocore_exceptions
    return boto3


sys.modules.setdefault("boto3", _build_fake_boto3())
