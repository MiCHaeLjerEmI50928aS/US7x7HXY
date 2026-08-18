output "reverse_proxy_config" {
  value = local_file.reverse_proxy.filename
}

output "webapp_config" {
  value = local_file.web_app.filename
}

output "firewall_rules" {
  value = local_file.firewall_rules.filename
}

output "routing_table" {
  value = local_file.routing.filename
}