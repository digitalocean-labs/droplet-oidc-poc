import sys
import dataclasses
import fnmatch
import json
import pathlib
import shutil
import unittest
import argparse
import tempfile
from enum import Enum
from typing import Dict, List, Optional, Tuple

import hcl2
import jsonschema


# --- Data Structures and Constants ---


@dataclasses.dataclass
class RolePolicyNotFoundError(Exception):
    """Exception raised when a policy specified in a role is not found."""

    role_name: str
    policy_name: str

    def __str__(self):
        return f"Policy '{self.policy_name}' for role '{self.role_name}' not found."


class Capabilities(Enum):
    """Enumeration for policy capabilities."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LIST = "list"


@dataclasses.dataclass
class Permissions:
    """Represents the result of a permission check."""

    allow: bool
    capability: Optional[Capabilities] = None
    error_msg: Optional[str] = None


PYTHON_TO_JSONSCHEMA_TYPE = {
    str: "string",
    int: "number",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
    type(None): "null",
}


# --- Core Logic: HCL Parsing, Schema Generation, and Permission Checking ---


def _hcl_params_to_jsonschema_props(params: dict) -> dict:
    """Helper to convert HCL 'allowed_parameters' into JSON Schema 'properties'."""
    properties = {}
    for key, value in params.items():
        if isinstance(value, str) and "*" in value:
            # Handle regex wildcard for a single string value
            properties[key] = {"type": "string", "pattern": value.replace("*", ".*")}
        elif isinstance(value, list):
            # Handle array of objects
            if value and isinstance(value[0], dict):
                allowed_object_schemas = []
                for obj_spec in value:
                    obj_props = {
                        prop_key: {"const": prop_val}
                        for prop_key, prop_val in obj_spec.items()
                    }
                    allowed_object_schemas.append(
                        {
                            "type": "object",
                            "properties": obj_props,
                            "required": sorted(list(obj_spec.keys())),
                            "additionalProperties": False,
                        }
                    )
                properties[key] = {
                    "type": "array",
                    "items": {"anyOf": allowed_object_schemas},
                }
            # Handle enum of simple values
            else:
                py_item_type = type(value[0]) if value else str
                json_item_type = PYTHON_TO_JSONSCHEMA_TYPE.get(py_item_type, "string")
                properties[key] = {"type": json_item_type, "enum": value}
        else:
            # Handle single constant value
            py_type = type(value)
            json_type = PYTHON_TO_JSONSCHEMA_TYPE.get(py_type, "string")
            properties[key] = {"type": json_type, "const": value}
    return properties


def hcl_policy_to_json_schema(policy_body: dict) -> dict:
    """Converts a parsed HCL path policy body into a single JSON Schema."""
    allowed_capabilities = sorted(policy_body.get("capabilities", []))
    raw_params = policy_body.get("allowed_parameters", {})
    allowed_params = (
        raw_params[0] if isinstance(raw_params, list) and raw_params else raw_params
    )

    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "capability": {"enum": allowed_capabilities},
        },
        "required": ["capability"],
    }
    if raw_params:
        body_schema = {"type": "object", "additionalProperties": False}
        body_schema["properties"] = _hcl_params_to_jsonschema_props(allowed_params)
        # Make all specified parameters required
        body_schema["required"] = sorted(list(allowed_params.keys()))
        schema["properties"]["body"] = body_schema
    return schema


def load_configuration(
    secrets_git_path: pathlib.Path,
) -> Tuple[Dict, Dict, Dict]:
    """Loads roles and policies, pre-generating JSON schemas for each policy."""
    # Load Roles and build indexes for any custom claims found
    all_roles = {}
    # This can be extended with other claims to index roles by in the future
    claim_keys_to_index = ["job_workflow_ref"]
    custom_claims_roles_index = {key: {} for key in claim_keys_to_index}

    for role_dir in secrets_git_path.glob("*roles"):
        if not role_dir.is_dir():
            continue
        for hcl_path in role_dir.rglob("*.hcl"):
            try:
                content = hcl2.loads(hcl_path.read_text())
                for role_group in content.get("role", []):
                    for role_name, role_def in role_group.items():
                        all_roles[role_name] = {
                            "role_name": role_name,
                            "definition": role_def,
                        }
                        # Index the role by any specified custom claims
                        for claim_key in claim_keys_to_index:
                            if claim_key in role_def:
                                claim_value = role_def[claim_key]
                                custom_claims_roles_index[claim_key].setdefault(
                                    claim_value, []
                                ).append(role_name)
            except Exception as e:
                print(f"Warning: Could not parse role file {hcl_path}: {e}")

    # Load Policies and Generate Schemas
    policies = {}
    policies_path = secrets_git_path.joinpath("policies")
    if policies_path.is_dir():
        for hcl_path in policies_path.rglob("*.hcl"):
            hcl_content = hcl_path.read_text()
            meta_dict = {"policy": hcl_path.stem}
            policy_name = meta_dict.get("policy")

            parsed_hcl = hcl2.loads(hcl_content)
            policy_schemas = {
                list(path_rule.keys())[0]: hcl_policy_to_json_schema(
                    list(path_rule.values())[0]
                )
                for path_rule in parsed_hcl.get("path", [])
            }
            policies[policy_name] = {
                "meta": meta_dict,
                "schemas": policy_schemas,
            }
    return all_roles, custom_claims_roles_index, policies


def find_matching_schema_for_path(
    schemas: Dict[str, Dict], path: str
) -> Optional[Dict]:
    """Finds the most specific schema for a given path, prioritizing exact matches."""
    if path in schemas:
        return schemas[path]
    glob_matches = [pattern for pattern in schemas if fnmatch.fnmatch(path, pattern)]
    if not glob_matches:
        return None
    # Return the schema for the longest (most specific) matching glob pattern
    best_match = sorted(glob_matches, key=len, reverse=True)[0]
    return schemas[best_match]


def check_permissions(
    roles: Dict,
    custom_claims_roles_index: Dict,
    policies: Dict,
    claims: Dict,
    *,
    path: str,
    capability: str,
    req_json: Optional[Dict],
) -> Permissions:
    """Checks if a request is permitted by iterating through assigned policies."""
    sub = claims.get("sub")
    matching_roles = []

    # Prioritize lookup by custom claims if they exist in the token
    for custom_claim_name, custom_claim_roles in custom_claims_roles_index.items():
        token_custom_claim_value = claims.get(custom_claim_name, None)
        if token_custom_claim_value is None:
            continue
        role_names = custom_claim_roles.get(token_custom_claim_value, [])
        role_definitions = [
            roles.get(role_name, {}).get("definition", {}) for role_name in role_names
        ]
        matching_roles.extend(
            [r for r in role_definitions if r.get("sub") == sub]
        )
    else:
        # Fallback to searching all roles by sub
        for role_info in roles.values():
            if role_info["definition"].get("sub") == sub:
                matching_roles.append(role_info["definition"])

    if not matching_roles:
        return Permissions(
            allow=False, error_msg=f"No matching role found for sub: {sub}"
        )

    policy_names = set(
        p_name
        for role_def in matching_roles
        for p_name in role_def.get("policies", [])
    )
    if not policy_names:
        return Permissions(
            allow=False, error_msg="Matched role(s) contain no policies."
        )

    denial_reasons = []
    for policy_name in sorted(list(policy_names)):
        policy = policies.get(policy_name)
        if not policy:
            raise RolePolicyNotFoundError(role_name="multiple", policy_name=policy_name)

        schema = find_matching_schema_for_path(policy["schemas"], path)
        if not schema:
            continue

        try:
            request_instance = {"capability": capability}
            if "body" in schema["properties"]:
                request_instance["body"] = req_json or {}
            jsonschema.validate(instance=request_instance, schema=schema)
            # If validation succeeds, permission is granted immediately.
            return Permissions(allow=True, capability=Capabilities(capability))
        except jsonschema.ValidationError as e:
            denial_reasons.append(f"policy '{policy_name}': {e.message}")
            continue

    # If the loop completes, no policy granted permission.
    error_msg = "Request denied. No policy allowed the request."
    if denial_reasons:
        error_msg += " Reasons: " + "; ".join(denial_reasons)
    return Permissions(allow=False, error_msg=error_msg)


# --- CI/CD Schema Generation ---


def serialize_configuration_to_string(
    all_roles: Dict,
    custom_claims_roles_index,
    policies,
) -> str:
    """Loads policies, generates JSON schemas, and writes them to a file."""
    export_data = {
        "roles": all_roles,
        "custom_claims_roles_index": custom_claims_roles_index,
        "policies": policies,
    }
    return json.dumps(export_data, sort_keys=True, indent=2)


def serialize_configuration_from_hcl_directory_to_file(
    secrets_dir: pathlib.Path,
    output_path: pathlib.Path,
) -> str:
    """Loads policies, generates JSON schemas, and writes them to a file."""
    all_roles, custom_claims_roles_index, policies = load_configuration(secrets_dir)
    output_string = serialize_configuration_to_string(
        all_roles, custom_claims_roles_index, policies
    )
    output_path.write_text(output_string)
    return output_string


def deserialize_configuration(config_as_json: str):
    """Loads roles, custom claims roles indexes, and policy JSON schemas from JSON string."""
    config_as_dict = json.loads(config_as_json)
    return (
        config_as_dict["roles"],
        config_as_dict["custom_claims_roles_index"],
        config_as_dict["policies"],
    )


# --- Test Setup and Unit Tests ---


def setup_test_directory(root_dir: pathlib.Path):
    """Creates a directory structure with HCL files for testing."""
    if root_dir.exists():
        shutil.rmtree(root_dir)
    policies_dir = root_dir.joinpath("policies")
    gha_roles_dir = root_dir.joinpath("gha-roles")
    droplet_roles_dir = root_dir.joinpath("droplet-roles")
    policies_dir.mkdir(parents=True)
    gha_roles_dir.mkdir(parents=True)
    droplet_roles_dir.mkdir(parents=True)

    (policies_dir / "data-readwrite.hcl").write_text(
        """
# meta:{"policy": "data-readwrite"}
path "/v2/databases/9cc10173-e9ea-4176-9dbc-a4cee4c4ff30" {
  capabilities = ["read"]
}
path "/v2/databases" {
  capabilities = ["read"]
  allowed_parameters = { "tag_name" = ["my-tag"] }
}
path "/v2/spaces/keys" {
  capabilities = ["create"]
  allowed_parameters = { grants = [ { bucket = "my-bucket", permission = "readwrite" } ] }
}
"""
    )
    (policies_dir / "issue-token.hcl").write_text(
        """
# meta:{"policy": "issue-token"}
path "/v1/token/issue" {
  capabilities = ["create"]
  allowed_parameters = { "aud" = "*" }
}
"""
    )
    (gha_roles_dir / "gha-role-name.hcl").write_text(
        """
role "ghe-role-name" {
  aud         = "api://DigitalOcean?team={team}"
  sub          = "repo:orgname/reponame:ref:refs/heads/main"
  policies   = ["data-readwrite"]
  job_workflow_ref = "orgname/reponame/.github/workflows/push.yaml@refs/heads/main"
}
"""
    )
    (droplet_roles_dir / "droplet-role-name.hcl").write_text(
        """
role "droplet-data-readwrite" {
  aud         = "api://DigitalOcean?team={team}"
  sub          = "role:data-readwrite"
  policies   = ["data-readwrite", "issue-token"]
}
"""
    )


class TestPermissions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.maxDiff = None
        cls.temp_dir_manager = tempfile.TemporaryDirectory()
        cls.test_dir = pathlib.Path(cls.temp_dir_manager.name)
        setup_test_directory(cls.test_dir)
        cls.roles, cls.custom_claims_roles_index, cls.policies = load_configuration(
            cls.test_dir
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir_manager.cleanup()

    def test_job_workflow_ref_role_allowed(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {
                "sub": "repo:orgname/reponame:ref:refs/heads/main",
                "job_workflow_ref": "orgname/reponame/.github/workflows/push.yaml@refs/heads/main",
            },
            path="/v2/databases/9cc10173-e9ea-4176-9dbc-a4cee4c4ff30",
            capability="read",
            req_json=None,
        )
        self.assertEqual(
            permissions, Permissions(allow=True, capability=Capabilities.READ)
        )

    def test_droplet_role_can_read_databases(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {"sub": "role:data-readwrite"},
            path="/v2/databases",
            capability="read",
            req_json={"tag_name": "my-tag"},
        )
        self.assertEqual(
            permissions, Permissions(allow=True, capability=Capabilities.READ)
        )

    def test_create_spaces_key_allowed(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {"sub": "role:data-readwrite"},
            path="/v2/spaces/keys",
            capability="create",
            req_json={"grants": [{"bucket": "my-bucket", "permission": "readwrite"}]},
        )
        self.assertEqual(
            permissions, Permissions(allow=True, capability=Capabilities.CREATE)
        )

    def test_create_spaces_key_with_disallowed_grant(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {"sub": "role:data-readwrite"},
            path="/v2/spaces/keys",
            capability="create",
            req_json={
                "grants": [{"bucket": "not-allowed-bucket", "permission": "readwrite"}]
            },
        )
        self.assertFalse(permissions.allow)
        self.assertIn(
            "'data-readwrite': 'my-bucket' was expected",
            permissions.error_msg,
        )

    def test_issue_token_with_wildcard_aud(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {"sub": "role:data-readwrite"},
            path="/v1/token/issue",
            capability="create",
            req_json={"aud": "any-string-is-fine"},
        )
        self.assertEqual(
            permissions, Permissions(allow=True, capability=Capabilities.CREATE)
        )

    def test_delete_denied_by_capability(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {
                "sub": "repo:orgname/reponame:ref:refs/heads/main",
                "job_workflow_ref": "orgname/reponame/.github/workflows/push.yaml@refs/heads/main",
            },
            path="/v2/databases/9cc10173-e9ea-4176-9dbc-a4cee4c4ff30",
            capability="delete",
            req_json=None,
        )
        self.assertFalse(permissions.allow)
        self.assertIn(
            "policy 'data-readwrite': 'delete' is not one of ['read']",
            permissions.error_msg,
        )

    def test_read_with_disallowed_tag(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {"sub": "role:data-readwrite"},
            path="/v2/databases",
            capability="read",
            req_json={"tag_name": "disallowed-tag"},
        )
        self.assertFalse(permissions.allow)
        self.assertIn(
            "policy 'data-readwrite': 'disallowed-tag' is not one of ['my-tag']",
            permissions.error_msg,
        )

    def test_read_with_missing_required_tag(self):
        permissions = check_permissions(
            self.roles,
            self.custom_claims_roles_index,
            self.policies,
            {"sub": "role:data-readwrite"},
            path="/v2/databases",
            capability="read",
            req_json={},  # Empty body, missing tag_name
        )
        self.assertFalse(permissions.allow)
        self.assertIn(
            "policy 'data-readwrite': 'tag_name' is a required property",
            permissions.error_msg,
        )

    def test_generate_schemas_ci_command(self):
        output_file = self.test_dir / "schemas.json"
        serialize_configuration_from_hcl_directory_to_file(self.test_dir, output_file)
        self.assertTrue(output_file.exists())
        schemas_data = {
            policy_name: data["schemas"]
            for policy_name, data in json.loads(output_file.read_text())[
                "policies"
            ].items()
        }

        # Verify data-readwrite policy schemas
        data_readwrite_schemas = schemas_data["data-readwrite"]
        self.assertIn("/v2/databases", data_readwrite_schemas)
        db_schema_body = data_readwrite_schemas["/v2/databases"]["properties"]["body"]
        self.assertEqual(db_schema_body["properties"]["tag_name"]["enum"], ["my-tag"])
        self.assertIn("tag_name", db_schema_body["required"])

        # Verify issue-token policy schemas
        issue_token_schemas = schemas_data["issue-token"]
        self.assertIn("/v1/token/issue", issue_token_schemas)
        token_schema_body = issue_token_schemas["/v1/token/issue"]["properties"]["body"]
        self.assertEqual(
            token_schema_body["properties"]["aud"],
            {"type": "string", "pattern": ".*"},
        )
        self.assertIn("aud", token_schema_body["required"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validate permissions based on HCL policies or generate policy schemas."
    )
    parser.add_argument(
        "--generate-schemas",
        nargs=2,
        metavar=("SECRETS_DIR", "OUTPUT_FILE"),
        help="Generate JSON schemas from HCL policies and save to a file.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run the built-in unit tests.",
    )

    args = parser.parse_args()

    if args.generate_schemas:
        secrets_dir = pathlib.Path(args.generate_schemas[0])
        output_file = pathlib.Path(args.generate_schemas[1])
        if not secrets_dir.is_dir():
            print(f"Error: Input directory not found at '{secrets_dir}'")
            sys.exit(1)
        generate_policy_schemas_json(secrets_dir, output_file)
    elif args.test:
        # To run tests, we pass an empty list to argv to prevent argparse from
        # clashing with unittest's own argument parsing.
        unittest.main(argv=[sys.argv[0], "-vvv"], exit=False)
    else:
        parser.print_help()
