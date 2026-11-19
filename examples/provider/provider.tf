terraform {
  required_providers {
    vulnetix = {
      source = "vulnetix/resolve"
    }
  }
}

# Minimal. The ApiKey of an admin or owner service account is read from
# VULNESIS_API_KEY and VULNESIS_ORG_ID, so nothing secret is in the
# configuration. Pass both from your CI secret store.
provider "vulnetix" {}
