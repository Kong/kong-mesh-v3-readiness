module github.com/Kong/kong-mesh-v3-readiness/tools/openapigen

go 1.26.4

replace github.com/Kong/kong-mesh-v3-readiness => ../..

require (
	github.com/Kong/kong-mesh-v3-readiness v0.0.0-00010101000000-000000000000
	github.com/invopop/jsonschema v0.14.0
	sigs.k8s.io/yaml v1.6.0
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/buger/jsonparser v1.1.2 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.1 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v4 v4.0.0-rc.2 // indirect
)
