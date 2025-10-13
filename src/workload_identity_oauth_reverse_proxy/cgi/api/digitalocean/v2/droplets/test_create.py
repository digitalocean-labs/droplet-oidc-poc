import os
import sys
import uuid
import unittest

import jwt


sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from .create import (
    V1_TOKEN_PREFIX,
    JWT_ISSUER_URL,
    JWT_SIGNING_KEY_PUBLIC_PEM,
    make_workload_identity,
)


class TestCreate(unittest.TestCase):
    def test_make_workload_identity(self):
        droplet_create_reponse = {
            "droplet": {
                # 1 is invalid
                "id": 2,
                "tags": [
                    "oidc-sub:space-readwrite:test-customer-0001",
                    "oidc-sub:database:db-mongodb-nyc3-29995",
                ],
            },
        }

        team = str(uuid.uuid4())
        workload_identities = make_workload_identity(team, droplet_create_reponse)
        claims = jwt.decode(
            workload_identities[2].token_as_string.lstrip(V1_TOKEN_PREFIX),
            JWT_SIGNING_KEY_PUBLIC_PEM,
            audience=JWT_ISSUER_URL,
            algorithms=["RS256"],
        )
        self.assertListEqual(
            claims["sub"].split(":"),
            [
                "database",
                "db-mongodb-nyc3-29995",
                "space-readwrite",
                "test-customer-0001",
                "team",
                team,
            ],
        )
