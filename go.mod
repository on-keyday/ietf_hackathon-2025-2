module github.com/on-keyday/dplane_importer

go 1.23.5

//replace github.com/osrg/gobgp => ../gobgp

//require github.com/osrg/gobgp v3.0.0+incompatible // indirect

require golang.org/x/sys v0.30.0

require (
	github.com/cilium/ebpf v0.17.3 // indirect
	golang.org/x/net v0.35.0 // indirect
)
