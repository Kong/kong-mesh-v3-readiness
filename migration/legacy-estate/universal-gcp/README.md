# universal-gcp — the Universal zone, on GCE

The Universal half of the legacy estate: a Kong Mesh 2.14 **Universal** zone federated to the same Konnect global CP as the Kubernetes zones, carrying the checks that are unreachable on Kubernetes.

Five VMs, one per component, all on one subnet with pinned addresses:

```
                      Konnect global CP (KDS, grpcs)
                                  ^
                                  |
      zone CP  10.10.0.10  --------+
        |  dp-server :5678, API :5681 (VPC-internal only)
        |
        +-- zone-ingress 10.10.0.11 :10001  <-- other zones dial the external IP
        +-- zone-egress  10.10.0.12 :10002
        +-- demo-app     10.10.0.21  app :5050 · envoy inbound :15050
        |        `-- outbound 127.0.0.1:25050 -> uni-kv
        |        `-- outbound 127.0.0.1:2505x -> the k8s zones (see below)
        `-- kv           10.10.0.22  app :5050 · envoy inbound :15050
                 `-- outbound 127.0.0.1:2505x -> the k8s zones
```

Both applications are `kuma-counter-demo`, the same image the Kubernetes zones run. `KV_URL` is what selects the role: set, it is the frontend; unset, it is the store.

## No transparent proxy

Every proxy here is explicit-outbound. The frontend dials `http://127.0.0.1:25050` and Envoy's outbound listener carries it to `uni-kv` over the mesh. Turning transparent proxying on would discard `networking.outbound[]` in favour of mesh VIPs and the legacy-outbound fixture would silently stop existing — the same reason `validation/deploy/05-universal.sh` keeps `uni-client` non-transparent.

## Cross-zone

Without a transparent proxy there is no VIP and no mesh DNS on these VMs, so a destination the Dataplane does not name does not exist. Every Kubernetes-zone service this zone can reach is therefore written out as an explicit outbound, by the `kuma.io/service` tag the k8s zones publish, on both Universal proxies:

| `kuma.io/service` | Local port | Published by |
|:---|---:|:---|
| `demo-app_kuma-demo_svc_5050` | 25051 | both zones — the frontend Service |
| `demo-app-v1_kuma-demo_svc_5050` | 25052 | both zones |
| `demo-app-v2_kuma-demo_svc_5050` | 25053 | **zone-1 only** — every hit is cross-zone |
| `kv_kuma-demo_svc_5050` | 25054 | both zones — the store |

Traffic to any of them leaves through this zone's ZoneEgress and arrives at the remote ZoneIngress; the `v2` entry is the one worth watching, because zone-1 is the only place that version runs. The builtin `edge-gateway` is not in the list on purpose — it is an entry point into the k8s zones, not something this zone consumes. Override the whole set with `cross_zone_services` — a map of service tag to local port — or set it to `{}` for a zone that talks to nobody.

The reverse direction needs nothing here: the k8s zones reach `uni-demo-app` and `uni-kv` by tag through this zone's ZoneIngress, whose `advertisedAddress` is the external IP Terraform reserves.

## Apply

```bash
cp terraform.tfvars.example terraform.tfvars   # fill in, then
terraform init
terraform apply
```

Every proxy carries a real token, and all four are minted up front against the **global** (Konnect) CP — the only control plane that can issue both kinds. Mint them, then paste them into `terraform.tfvars`:

```bash
kumactl generate zone-token --zone uni-zone-3 --scope ingress --valid-for 720h   # zone_ingress_token
kumactl generate zone-token --zone uni-zone-3 --scope egress  --valid-for 720h   # zone_egress_token
kumactl generate dataplane-token --mesh default --name uni-demo-app --valid-for 720h   # demo_app_token
kumactl generate dataplane-token --mesh default --name uni-kv       --valid-for 720h   # kv_token
```

They reach their VM as instance metadata, and the startup script hands each one to `kuma-dp` as `KUMA_DATAPLANE_RUNTIME_TOKEN` — the env form of `--dataplane-token-file`, so no token is written to disk. No key store, no service accounts, one apply.

Minting on the zone instead would force a two-phase deploy: a federated zone CP has no zone-token signing key at all (`SigningKeyNotFound`), and its dataplane-token key only exists once the mesh has synced from global. The trade for avoiding that is instance metadata, which anyone holding `compute.instances.get` on the project can read. Tokens expire in 720h; re-mint and `terraform apply` to roll them.

Boot takes roughly 3-5 minutes: apt, image pulls, then the KDS handshake. Watch it with `/var/log/kmesh-bootstrap.log` on any VM.

## Check it

```bash
eval "$(terraform output -raw control_plane_tunnel)" &     # zone CP API on :5681
kumactl config control-planes add --name uni-zone-3 --address http://localhost:5681
kumactl get dataplanes
```

Expected: `uni-demo-app`, `uni-kv`, `uni-zone-ingress`, `uni-zone-egress`, all online, and the zone listed as `uni-zone-3` on the global CP. Then the counter demo itself:

```bash
eval "$(terraform output -raw demo_app_tunnel)" &          # http://localhost:5050
```

The counter increments only if the explicit outbound to `uni-kv` is actually carrying traffic. For the cross-zone outbounds, curl them from the VM — the sidecar shares its network namespace, so they are on the VM's own loopback:

```bash
terraform output cross_zone_outbounds
gcloud compute ssh kmesh-uni-demo-app --zone us-central1-a --tunnel-through-iap \
  -- curl -s -o /dev/null -w '%{http_code}\n' localhost:25053   # demo-app-v2, zone-1 only
```

A 503 with an empty upstream means the remote zone has no endpoint for that tag; a connection refused means the outbound is not in the Dataplane at all.

## What it adds to a preflight report

With `legacy_fixtures = true` (the default) this zone contributes the blockers a Kubernetes-only estate cannot produce, because on Kubernetes the injector derives all three from the Pod:

| preflight finding                        | Where it comes from                                               |
|:-----------------------------------------|:------------------------------------------------------------------|
| Universal Dataplane `probes`             | `probes` block on `uni-demo-app`                                  |
| Missing `kuma.io/workload` label         | `uni-demo-app` carries no label                                   |
| Legacy `outbound[]` entries              | every explicit outbound on both Universal proxies                 |
| Zone proxies                             | standalone `ZoneIngress` + `ZoneEgress`, zone-token authenticated |
| Dataplane not on unified resource naming | 2.14 default, no `kuma-dp` feature flag set                       |

Set `legacy_fixtures = false` to write the same two proxies the way 3.0 wants them (workload label, no probes) — useful for confirming a finding clears.

## Costs and teardown

Four `e2-small` plus one `e2-medium`, one static external address, one Cloud NAT gateway. `terraform destroy` removes all of it.

## Decisions worth knowing

- **Addresses pinned, names never used.** Every Dataplane file is rendered before the VMs exist, and cross-zone Envoys resolve `advertisedAddress` from outside this VPC. `advertisedAddress` on the ZoneIngress is therefore the external address, not the internal one.
- **Memory store on the CP.** This zone owns no state a restart needs to keep; meshes and policies live on the global CP and arrive over KDS.
- **`--skip-verify` on every `kuma-dp`.** The zone CP's dp-server serves an autogenerated self-signed certificate and `kuma-dp` has no CA for it.
- **The app and its sidecar share the VM's network namespace.** That is what lets Envoy's inbound listener forward to `127.0.0.1:5050` and lets the app reach its outbounds on loopback. Inbound port and service port must differ for the same reason.
- **No license on the zone CP.** Quota syncs from global over KDS.
- **The API is not published.** No VM but the ingress has an external address, and that one publishes a single mesh port. Reach the CP API through IAP (`terraform output control_plane_tunnel`).
