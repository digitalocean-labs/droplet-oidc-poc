role "create-model-keys" {
  aud      = "api://DigitalOcean?actx={actx}"
  sub      = "actx:{actx}:role:create-model-keys"
  policies = ["create-model-keys"]
}
