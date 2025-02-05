terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5"
    }
  }
}

provider "cloudflare" {
  api_token = "RLH7KweQRPvUrSTA95AaEPM16iL6pLEB9kvc4mEa"
}
