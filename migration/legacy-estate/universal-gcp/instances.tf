# One VM per component, addresses pinned. Each carries its own proxy token as
# instance metadata; no VM calls a GCP API, so none of them needs a service account
# beyond the project default.

resource "google_compute_instance" "cp" {
  name         = "${var.name_prefix}-cp"
  machine_type = var.cp_machine_type
  zone         = var.gcp_zone

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.mesh.id
    network_ip = local.cp_ip
  }

  metadata = {
    konnect-cp-token = var.konnect_cp_token
  }

  metadata_startup_script = templatefile("${path.module}/templates/cp.sh.tftpl", {
    bootstrap     = local.bootstrap
    konnect_cp_id = var.konnect_cp_id
    kds_address   = var.konnect_kds_address
    zone_name     = var.zone_name
    cp_ip         = local.cp_ip
    cp_image      = local.cp_image
  })

  depends_on = [google_compute_router_nat.mesh]
}

resource "google_compute_instance" "zone_ingress" {
  name         = "${var.name_prefix}-zone-ingress"
  machine_type = var.machine_type
  zone         = var.gcp_zone
  tags         = ["${var.name_prefix}-ingress"]

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.mesh.id
    network_ip = local.ingress_ip

    access_config {
      nat_ip = google_compute_address.ingress_external.address
    }
  }

  metadata = {
    dataplane-token = var.zone_ingress_token
  }

  metadata_startup_script = templatefile("${path.module}/templates/zone-proxy.sh.tftpl", {
    bootstrap      = local.bootstrap
    dataplane_yaml = local.zone_ingress_dataplane
    dp_image       = local.dp_image
    cp_address     = local.cp_address
    proxy_type     = "ingress"
  })

  depends_on = [google_compute_router_nat.mesh]
}

resource "google_compute_instance" "zone_egress" {
  name         = "${var.name_prefix}-zone-egress"
  machine_type = var.machine_type
  zone         = var.gcp_zone

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.mesh.id
    network_ip = local.egress_ip
  }

  metadata = {
    dataplane-token = var.zone_egress_token
  }

  metadata_startup_script = templatefile("${path.module}/templates/zone-proxy.sh.tftpl", {
    bootstrap      = local.bootstrap
    dataplane_yaml = local.zone_egress_dataplane
    dp_image       = local.dp_image
    cp_address     = local.cp_address
    proxy_type     = "egress"
  })

  depends_on = [google_compute_router_nat.mesh]
}

# demo-app: the frontend. Reaches the store over its explicit outbound on
# 127.0.0.1, never through a VIP — there is no transparent proxy on this VM.
resource "google_compute_instance" "demo_app" {
  name         = "${var.name_prefix}-demo-app"
  machine_type = var.machine_type
  zone         = var.gcp_zone

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.mesh.id
    network_ip = local.demo_app_ip
  }

  metadata = {
    dataplane-token = var.demo_app_token
  }

  metadata_startup_script = templatefile("${path.module}/templates/app.sh.tftpl", {
    bootstrap      = local.bootstrap
    dataplane_yaml = local.demo_app_dataplane
    dp_image       = local.dp_image
    cp_address     = local.cp_address
    app_image      = var.counter_demo_image
    app_env_flags = join(" ", [
      "-e OTEL_SERVICE_NAME=demo-app",
      "-e APP_VERSION=v1",
      "-e KV_URL=http://127.0.0.1:${local.kv_outbound_port}",
    ])
  })

  depends_on = [google_compute_router_nat.mesh]
}

# kv: the store. Same image, no KV_URL — that is what selects the role.
resource "google_compute_instance" "kv" {
  name         = "${var.name_prefix}-kv"
  machine_type = var.machine_type
  zone         = var.gcp_zone

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 20
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.mesh.id
    network_ip = local.kv_ip
  }

  metadata = {
    dataplane-token = var.kv_token
  }

  metadata_startup_script = templatefile("${path.module}/templates/app.sh.tftpl", {
    bootstrap      = local.bootstrap
    dataplane_yaml = local.kv_dataplane
    dp_image       = local.dp_image
    cp_address     = local.cp_address
    app_image      = var.counter_demo_image
    app_env_flags  = "-e OTEL_SERVICE_NAME=kv"
  })

  depends_on = [google_compute_router_nat.mesh]
}
