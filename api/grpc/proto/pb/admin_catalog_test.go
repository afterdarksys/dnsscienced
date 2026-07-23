package pb

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestCatalogAdminMessagesRoundTripAndServiceRegistration(t *testing.T) {
	input := &AdminListCatalogMembersResponse{
		Members: []*AdminCatalogMember{{
			Zone:              "alpha.example.",
			Label:             "a1",
			Groups:            []string{"blue"},
			OwnerCatalog:      "catalog.example.",
			EffectiveGroup:    "blue",
			Masters:           []string{"192.0.2.1"},
			TransferKeyName:   "catalog-key.example.",
			TransferAlgorithm: "hmac-sha256",
		}},
		NextPageToken:  "opaque",
		TotalCount:     1,
		SnapshotSerial: 42,
	}
	wire, err := proto.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var output AdminListCatalogMembersResponse
	if err := proto.Unmarshal(wire, &output); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !proto.Equal(input, &output) {
		t.Fatalf("round trip output = %+v", &output)
	}

	methods := make(map[string]bool, len(AdminService_ServiceDesc.Methods))
	for _, method := range AdminService_ServiceDesc.Methods {
		methods[method.MethodName] = true
	}
	if !methods["ListCatalogs"] || !methods["ListCatalogMembers"] {
		t.Fatalf("catalog RPCs missing from service descriptor: %v", methods)
	}
}
