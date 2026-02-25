path "/v2/gen-ai/models/api_keys" {
  capabilities = ["create"]
  allowed_parameters = {
    "name" = "opencode-*"
  }
}
