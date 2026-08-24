# The Dataplane, ZoneIngress and ZoneEgress resources, rendered here and bind-mounted
# into kuma-dp. Universal is the only place several of these shapes are expressible:
# on Kubernetes the injector derives inbounds, outbounds, probes and the workload
# label from the Pod and ignores whatever the Dataplane says.

locals {
  demo_app_dp_name = "uni-demo-app"
  kv_dp_name       = "uni-kv"

  # One outbound per Kubernetes-zone service, by kuma.io/service tag. These are what
  # make cross-zone traffic possible at all here: with no transparent proxy there is
  # no VIP and no mesh DNS, so a destination the Dataplane does not name does not
  # exist. Traffic leaves through this zone's ZoneIngress/ZoneEgress pair.
  cross_zone_outbounds = [
    for svc, port in var.cross_zone_services : {
      port = port
      tags = { "kuma.io/service" = svc }
    }
  ]

  demo_app_outbounds = concat(
    [{
      port = local.kv_outbound_port
      tags = { "kuma.io/service" = local.kv_dp_name }
    }],
    local.cross_zone_outbounds,
  )

  demo_app_base = {
    type = "Dataplane"
    mesh = var.mesh
    name = local.demo_app_dp_name
    networking = {
      address           = local.demo_app_ip
      advertisedAddress = local.demo_app_ip
      inbound = [{
        port        = local.inbound_port
        servicePort = local.app_port
        tags = {
          "kuma.io/service"  = local.demo_app_dp_name
          "kuma.io/protocol" = "http"
          "version"          = "v1"
        }
      }]
      # Explicit kuma.io/service outbounds — the LegacyOutbound model 3.0 replaces
      # with MeshService + backendRef. Each binds 127.0.0.1:<port> on this VM.
      outbound = local.demo_app_outbounds
    }
  }

  # legacy_fixtures swaps in the two Universal-only blockers: a top-level `probes`
  # block (removed in 3.0, no Universal replacement) and no `kuma.io/workload`
  # label. Off, the same proxy is written the way 3.0 wants it.
  demo_app_dataplane = var.legacy_fixtures ? yamlencode(merge(local.demo_app_base, {
    probes = {
      port = 9000
      endpoints = [{
        inboundPort = local.inbound_port
        inboundPath = "/"
        path        = "/health"
      }]
    }
    })) : yamlencode(merge(local.demo_app_base, {
    labels = { "kuma.io/workload" = local.demo_app_dp_name }
  }))

  kv_dataplane = yamlencode({
    type   = "Dataplane"
    mesh   = var.mesh
    name   = local.kv_dp_name
    labels = { "kuma.io/workload" = local.kv_dp_name }
    networking = {
      address           = local.kv_ip
      advertisedAddress = local.kv_ip
      inbound = [{
        port        = local.inbound_port
        servicePort = local.app_port
        tags = {
          "kuma.io/service"  = local.kv_dp_name
          "kuma.io/protocol" = "http"
          "version"          = "v1"
        }
      }]
      # The store reaches the Kubernetes zones too — same tags, same ports as
      # demo-app — so either VM can prove the cross-zone path.
      outbound = local.cross_zone_outbounds
    }
  })

  # advertisedAddress is the ingress VM's external address: another zone's Envoys
  # dial it from outside this VPC, so an internal address here silently kills every
  # cross-zone route into this zone.
  zone_ingress_dataplane = yamlencode({
    type = "ZoneIngress"
    name = "uni-zone-ingress"
    networking = {
      address           = local.ingress_ip
      port              = local.ingress_port
      advertisedAddress = google_compute_address.ingress_external.address
      advertisedPort    = local.ingress_port
    }
  })

  zone_egress_dataplane = yamlencode({
    type = "ZoneEgress"
    name = "uni-zone-egress"
    networking = {
      address = local.egress_ip
      port    = local.egress_port
    }
  })

  bootstrap = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    project_id = var.project_id
  })
}
