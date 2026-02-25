role "ex-create-model-keys" {
  aud      = "api://DigitalOcean?actx={actx}"
  sub      = "actx:{actx}:role:ex-create-model-keys"
  policies = ["ex-create-model-keys"]
}
