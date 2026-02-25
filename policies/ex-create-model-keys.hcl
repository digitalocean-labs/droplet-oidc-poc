path "/v1/oidc/issue" {
  capabilities = ["create"]
  allowed_parameters = {
    "aud" = "api://DigitalOcean?actx={actx}"
    "sub" = "actx:{actx}:role:create-model-keys"
    "ttl" = 300
  }
}
