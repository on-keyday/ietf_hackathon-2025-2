module github.com/on-keyday/dplane_importer

go 1.24

replace github.com/osrg/gobgp/v3 => ./gobgp

require github.com/osrg/gobgp/v3 v3.34.0 // indirect

require golang.org/x/sys v0.30.0

require (
	github.com/cilium/ebpf v0.17.3 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
	google.golang.org/grpc v1.70.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
)
