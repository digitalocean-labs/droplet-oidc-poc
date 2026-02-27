path "/v2/domains/example.com/records" {
  capabilities = ["create"]
  allowed_parameters = {
    "type" = "A",
    "name" = "*\.opencode"
    "data" = "*"
    "priority" = null,
    "port" = null,
    "ttl" = 1800,
    "weight" = null,
    "flags" = null,
    "tag" = null
  }
}
