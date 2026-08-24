output "zone_name" {
  description = "Kuma zone name this estate registers as on the global CP."
  value       = var.zone_name
}

output "control_plane_internal_ip" {
  description = "Zone CP address. The API is not published outside the VPC — tunnel to it."
  value       = local.cp_ip
}

output "control_plane_tunnel" {
  description = "Opens the zone CP API on http://localhost:5681."
  value       = "gcloud compute ssh ${google_compute_instance.cp.name} --zone ${var.gcp_zone} --tunnel-through-iap -- -N -L 5681:localhost:5681"
}

output "zone_ingress_address" {
  description = "advertisedAddress of the ZoneIngress. Other zones dial this."
  value       = "${google_compute_address.ingress_external.address}:${local.ingress_port}"
}

output "demo_app_url" {
  description = "Counter demo UI, reachable from inside the VPC."
  value       = "http://${local.demo_app_ip}:${local.app_port}"
}

output "demo_app_tunnel" {
  description = "Opens the counter demo on http://localhost:5050."
  value       = "gcloud compute ssh ${google_compute_instance.demo_app.name} --zone ${var.gcp_zone} --tunnel-through-iap -- -N -L 5050:localhost:${local.app_port}"
}

output "cross_zone_outbounds" {
  description = "Kubernetes-zone service each Universal proxy can reach, and the loopback address its outbound binds on. Curl these from either app VM."
  value       = { for svc, port in var.cross_zone_services : svc => "http://127.0.0.1:${port}" }
}

output "dataplanes" {
  description = "Dataplane names and the VM each runs on."
  value = {
    (local.demo_app_dp_name) = google_compute_instance.demo_app.name
    (local.kv_dp_name)       = google_compute_instance.kv.name
    "uni-zone-ingress"       = google_compute_instance.zone_ingress.name
    "uni-zone-egress"        = google_compute_instance.zone_egress.name
  }
}
