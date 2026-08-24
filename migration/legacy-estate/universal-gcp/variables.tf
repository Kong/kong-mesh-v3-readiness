# ---- GCP ---------------------------------------------------------------------

variable "project_id" {
  description = "GCP project that holds the Universal zone."
  type        = string
}

variable "gcp_region" {
  description = "GCP region for the subnet, Cloud NAT and the ingress address."
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone for every VM. Must live in var.gcp_region."
  type        = string
  default     = "us-central1-a"
}

variable "name_prefix" {
  description = "Prefix for every GCP resource name."
  type        = string
  default     = "kmesh-uni"
}

variable "subnet_cidr" {
  description = "Subnet for the zone. Needs at least 8 usable addresses; hosts .10-.22 are pinned."
  type        = string
  default     = "10.10.0.0/24"
}

variable "machine_type" {
  description = "Machine type for the data plane VMs (ingress, egress, both apps)."
  type        = string
  default     = "e2-small"
}

variable "cp_machine_type" {
  description = "Machine type for the zone control plane VM."
  type        = string
  default     = "e2-medium"
}

variable "boot_image" {
  description = "Boot image for every VM. Startup scripts assume apt and systemd."
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2204-lts"
}

variable "ingress_source_ranges" {
  description = "Who may reach the ZoneIngress port. Other zones dial this over the public internet, so narrow it to their egress addresses when you know them."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ---- Konnect -----------------------------------------------------------------

variable "konnect_cp_id" {
  description = "Konnect global control plane id (kuma.controlPlane.konnect.cpId in the zone helm values)."
  type        = string
}

variable "konnect_cp_token" {
  description = "Konnect zone token (spat_...) the zone CP authenticates to KDS with."
  type        = string
  sensitive   = true
}

variable "konnect_kds_address" {
  description = "Konnect KDS endpoint (kuma.controlPlane.kdsGlobalAddress in the zone helm values)."
  type        = string
  default     = "grpcs://us.mesh.sync.konghq.tech:443"
}

# ---- mesh --------------------------------------------------------------------

variable "zone_name" {
  description = "Kuma zone name. Must not collide with the k8s zones federated to the same global."
  type        = string
  default     = "uni-zone-3"
}

variable "mesh" {
  description = "Mesh the data planes join. Created on the global CP, synced down over KDS."
  type        = string
  default     = "default"
}

variable "kong_mesh_version" {
  description = "Kong Mesh version for kuma-cp, kuma-dp and kumactl."
  type        = string
  default     = "2.14.3"
}

variable "counter_demo_image" {
  description = "Demo application image. Same image serves both roles: with KV_URL set it is the frontend, without it the store."
  type        = string
  default     = "ghcr.io/kumahq/kuma-counter-demo:latest"
}

# ---- proxy tokens ------------------------------------------------------------
#
# All four are minted against the GLOBAL (Konnect) control plane before apply and
# reach their VM as instance metadata, which the startup script hands to kuma-dp as
# KUMA_DATAPLANE_RUNTIME_TOKEN. Global is the one CP that can issue both kinds: a
# federated zone CP has no zone-token signing key at all, and its dataplane-token
# key only exists once the mesh has synced — minting there would force a two-phase
# deploy. Instance metadata is readable by anyone holding compute.instances.get on
# the project, which is the trade for keeping this to one apply and no key store.

variable "zone_ingress_token" {
  description = <<-EOT
    Zone token with scope `ingress`:

      kumactl generate zone-token --zone <zone_name> --scope ingress --valid-for 720h
  EOT
  type        = string
  sensitive   = true
}

variable "zone_egress_token" {
  description = "Zone token with scope `egress`. `kumactl generate zone-token --zone <zone_name> --scope egress --valid-for 720h`."
  type        = string
  sensitive   = true
}

variable "demo_app_token" {
  description = "Dataplane token for `uni-demo-app`. `kumactl generate dataplane-token --mesh <mesh> --name uni-demo-app --valid-for 720h`."
  type        = string
  sensitive   = true
}

variable "kv_token" {
  description = "Dataplane token for `uni-kv`. `kumactl generate dataplane-token --mesh <mesh> --name uni-kv --valid-for 720h`."
  type        = string
  sensitive   = true
}

# ---- fixtures ----------------------------------------------------------------

variable "cross_zone_services" {
  description = <<-EOT
    `kuma.io/service` tag of every workload in another zone this zone can reach, mapped to the local
    port its explicit outbound binds on. Both Universal proxies get all of them.

    Without transparent proxying there is no VIP and no mesh DNS: a cross-zone destination exists
    only if it is written here, resolved through this zone's ZoneEgress and the remote ZoneIngress.
    The defaults are the counter-demo service tags the Kubernetes zones publish
    (`zone-1/00-counter-demo.yaml`); `demo-app-v2` runs in zone-1 only, so an outbound to it from
    here proves the cross-zone path rather than a local one. The builtin gateway is deliberately
    absent — it is an entry point into the k8s zones, not a service this zone consumes. Set to `{}`
    for a zone that talks to nobody.
  EOT
  type        = map(number)
  default = {
    "demo-app_kuma-demo_svc_5050"    = 25051
    "demo-app-v1_kuma-demo_svc_5050" = 25052
    "demo-app-v2_kuma-demo_svc_5050" = 25053
    "kv_kuma-demo_svc_5050"          = 25054
  }
}

variable "legacy_fixtures" {
  description = <<-EOT
    Shape the Dataplanes so the Universal-only 3.0 removals are present: a top-level `probes` block
    on demo-app and no `kuma.io/workload` label on it. Both are blockers kuma3-preflight can only
    observe on Universal — on Kubernetes the injector derives them from the Pod. Set false for a
    clean zone.
  EOT
  type        = bool
  default     = true
}
