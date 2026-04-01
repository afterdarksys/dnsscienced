module github.com/dnsscience/dnsscienced

go 1.25.0

require (
	github.com/dchest/siphash v1.2.3
	github.com/dnsscience/dnsscienced/dnsasm/go v0.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.72
	github.com/prometheus/client_golang v1.18.0
	github.com/stretchr/testify v1.11.1
	go.starlark.net v0.0.0-20260326113308-fadfc96def35
	golang.org/x/time v0.14.0
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
)

replace github.com/dnsscience/dnsscienced/dnsasm/go => ./dnsasm/go
