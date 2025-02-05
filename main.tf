resource "cloudflare_ruleset" "custom_rules" {
  kind  = "zone"
  name  = "default"
  phase = "http_request_firewall_custom"
  rules = [
    {
      action = "skip"
      action_parameters = {
        phases = [
          "http_ratelimit",
          "http_request_firewall_managed",
          "http_request_sbfm",
        ]
        ruleset = "current"
      }
      description = "finder-allowlist"
      enabled     = true
      expression  = "(ip.src eq 34.87.206.232) or (ip.src eq 34.87.197.255)"
      logging = {
        enabled = true
      }
    },
    {
      action      = "block"
      description = "finder-blocklist"
      enabled     = true
      expression  = "(ip.src eq 152.32.107.175)"
    },
    {
      action      = "managed_challenge"
      description = "finder-blocked-paths"
      enabled     = true
      expression  = "(http.request.uri.path contains \"AWS_WAF_PATH_BLOCK_TEST_9000\") or (http.request.uri.path contains \"xmlrpc.php\") or (http.request.uri.path contains \"/wp-json/finder/v1/dse-proxy/\")"
    },
    {
      action = "skip"
      action_parameters = {
        phases = [
          "http_ratelimit",
          "http_request_firewall_managed",
          "http_request_sbfm",
        ]
        ruleset = "current"
      }
      description = "finder-ua-allowlist"
      enabled     = true
      expression  = "(http.user_agent eq \"Mozilla/5.0(compatible;impact.com agent) AppleWebKit/537.36 (KHTML, like Gecko)Chrome/119.0.6045.214 Safari/537.36)\")"
      logging = {
        enabled = true
      }
    },
    {
      action      = "block"
      description = "finder-ua-blocklist"
      enabled     = true
      expression  = "(http.user_agent contains \"bfac\") or (http.user_agent contains \"bsqlbf\") or (http.user_agent contains \"cisco-torch\") or (http.user_agent contains \"commix\") or (http.user_agent contains \"dirbuster\") or (http.user_agent contains \"domino hunter\") or (http.user_agent contains \"dotdotpwn\") or (http.user_agent contains \"grendel-scan\") or (http.user_agent contains \"havij\") or (http.user_agent contains \"inspath\") or (http.user_agent contains \"metis\") or (http.user_agent contains \"mysqloit\") or (http.user_agent contains \"n-stealth\") or (http.user_agent contains \"nessus\") or (http.user_agent contains \"netsparker\") or (http.user_agent contains \"nikto\") or (http.user_agent contains \"nmap\") or (http.user_agent contains \"nsauditor\") or (http.user_agent contains \"pangolin\") or (http.user_agent contains \"paros\") or (http.user_agent wildcard r\"qualys was\") or (http.user_agent contains \"springenwerk\") or (http.user_agent contains \"sql power injector\") or (http.user_agent contains \"sqlmap\") or (http.user_agent contains \"sqlninja\") or (http.user_agent contains \"teh forest lobster\") or (http.user_agent contains \"uil2pn\") or (http.user_agent contains \"vega/\") or (http.user_agent contains \"w3af.\") or (http.user_agent contains \"webinspect\") or (http.user_agent contains \"webvulnscan\") or (http.user_agent contains \"WPScan\") or (http.user_agent contains \"openvas\") or (http.user_agent contains \"user-agent:\")"
    },
    {
      action      = "block"
      description = "whitelist-office-ips-qa01"
      enabled     = false
      expression  = <<-EOT
                (
                    not ip.src in {59.100.201.238/32 103.240.135.174/32 49.255.111.234/32 123.136.51.7/32 203.177.49.201/32 121.58.213.130/32 37.128.95.182/32 87.237.68.12/32 96.45.204.242/32 68.175.24.12/32 35.197.183.150/32 34.78.215.226/32} and
                    (http.host wildcard r"*.qa01.global.cf.findershopping.com.au")
                )
            EOT
    },
  ]
  zone_id = "e4e9c53a5052928fa90338cd8a4635fc"
}

resource "cloudflare_ruleset" "rate_limits" {
    kind    = "zone"
    name    = "default"
    phase   = "http_ratelimit"
    rules   = [
        {
            action      = "block"
            description = "generic_rate_limit_non-core"
            enabled     = true
            expression  = "(not ip.src.country in {\"AU\" \"CA\" \"PL\" \"GB\" \"US\" \"PH\"})"
            ratelimit   = {
                characteristics     = [
                    "ip.src",
                    "cf.colo.id",
                ]
                mitigation_timeout  = 120
                period              = 60
                requests_per_period = 100
            }
        },
        {
            action      = "block"
            description = "generic_rate_limit_plph"
            enabled     = true
            expression  = "(ip.src.country in {\"PL\" \"PH\"})"
            ratelimit   = {
                characteristics     = [
                    "ip.src",
                    "cf.colo.id",
                ]
                mitigation_timeout  = 120
                period              = 60
                requests_per_period = 1000
            }
        },
        {
            action      = "block"
            description = "generic_rate_limit_core"
            enabled     = true
            expression  = "(ip.src.country in {\"AU\" \"CA\" \"GB\" \"US\"})"
            ratelimit   = {
                characteristics     = [
                    "ip.src",
                    "cf.colo.id",
                ]
                mitigation_timeout  = 300
                period              = 300
                requests_per_period = 5000
            }
        },
    ]
    zone_id = "e4e9c53a5052928fa90338cd8a4635fc"   
}