# The zone runs on one subnet with pinned host addresses: every Dataplane file is
# rendered before the VMs exist, so the addresses have to be known at plan time.
# Container names are not an option here for the same reason they are not in
# validation/deploy — a name in advertisedAddress is NXDOMAIN from another zone.

locals {
  cp_ip       = cidrhost(var.subnet_cidr, 10)
  ingress_ip  = cidrhost(var.subnet_cidr, 11)
  egress_ip   = cidrhost(var.subnet_cidr, 12)
  demo_app_ip = cidrhost(var.subnet_cidr, 21)
  kv_ip       = cidrhost(var.subnet_cidr, 22)

  # Envoy's inbound listener, the application behind it, and the local ports the
  # explicit outbounds bind on. Inbound and service port must differ: the sidecar
  # shares the VM's network namespace with the app.
  app_port         = 5050
  inbound_port     = 15050
  kv_outbound_port = 25050

  ingress_port = 10001
  egress_port  = 10002

  cp_address = "https://${local.cp_ip}:5678"

  cp_image = "kong/kuma-cp:${var.kong_mesh_version}"
  dp_image = "kong/kuma-dp:${var.kong_mesh_version}"
}

resource "google_compute_network" "mesh" {
  name                    = var.name_prefix
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "mesh" {
  name          = var.name_prefix
  network       = google_compute_network.mesh.id
  region        = var.gcp_region
  ip_cidr_range = var.subnet_cidr
}

# Only the ZoneIngress carries an external address. Everything else reaches
# Konnect KDS, Docker Hub and the Secret Manager API through NAT.
resource "google_compute_router" "mesh" {
  name    = "${var.name_prefix}-router"
  region  = var.gcp_region
  network = google_compute_network.mesh.id
}

resource "google_compute_router_nat" "mesh" {
  name                               = "${var.name_prefix}-nat"
  router                             = google_compute_router.mesh.name
  region                             = var.gcp_region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

resource "google_compute_address" "ingress_external" {
  name   = "${var.name_prefix}-ingress"
  region = var.gcp_region
}

# Mesh traffic: sidecar inbounds, the CP's dp-server and API, the zone proxies.
resource "google_compute_firewall" "internal" {
  name      = "${var.name_prefix}-allow-internal"
  network   = google_compute_network.mesh.name
  direction = "INGRESS"

  source_ranges = [var.subnet_cidr]

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }
}

# Cross-zone traffic terminates on the ZoneIngress and nowhere else.
resource "google_compute_firewall" "zone_ingress" {
  name      = "${var.name_prefix}-allow-zone-ingress"
  network   = google_compute_network.mesh.name
  direction = "INGRESS"

  source_ranges = var.ingress_source_ranges
  target_tags   = ["${var.name_prefix}-ingress"]

  allow {
    protocol = "tcp"
    ports    = [tostring(local.ingress_port)]
  }
}

# SSH through IAP only — no VM but the ingress has a public address, and that one
# publishes a single mesh port.
resource "google_compute_firewall" "iap_ssh" {
  name      = "${var.name_prefix}-allow-iap-ssh"
  network   = google_compute_network.mesh.name
  direction = "INGRESS"

  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
