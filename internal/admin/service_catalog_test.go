package admin_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"github.com/afterdarksys/dnsscienced/internal/admin"
	"github.com/afterdarksys/dnsscienced/internal/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type catalogStatuses []catalog.Status

func (s catalogStatuses) Statuses() []catalog.Status {
	return append([]catalog.Status(nil), s...)
}

func TestListCatalogMembersRejectsInvalidPageToken(t *testing.T) {
	svc := admin.NewService(
		nil, nil, nil, nil, nil, nil, "", "", nil, nil, nil, nil,
		catalogStatuses{{Name: "catalog.example."}},
	)
	_, err := svc.ListCatalogMembers(context.Background(), &pb.AdminListCatalogMembersRequest{
		Catalog:   "catalog.example.",
		PageToken: "***not-base64***",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %v, err=%v", status.Code(err), err)
	}
}

func (s catalogStatuses) CatalogMembers(
	name string,
	cursor string,
	limit int,
	expectedSerial *uint32,
) ([]catalog.MemberStatus, string, int, uint32, error) {
	if name != "catalog.example." {
		return nil, "", 0, 0, catalog.ErrCatalogNotFound
	}
	if expectedSerial != nil && *expectedSerial != 42 {
		return nil, "", 0, 0, catalog.ErrCatalogChanged
	}
	if cursor == "" && limit > 0 {
		return []catalog.MemberStatus{{
			Zone:              "alpha.example.",
			Label:             "a1",
			Groups:            []string{"blue"},
			OwnerCatalog:      "catalog.example.",
			EffectiveGroup:    "blue",
			Masters:           []string{"192.0.2.1"},
			TransferKeyName:   "catalog-key.example.",
			TransferAlgorithm: "hmac-sha256",
		}}, "alpha.example.", 2, 42, nil
	}
	return []catalog.MemberStatus{{Zone: "beta.example.", Label: "b1"}}, "", 2, 42, nil
}

func TestGetServerStatusIncludesCatalogHealth(t *testing.T) {
	lastSuccess := time.Now().Add(-2 * time.Minute)
	svc := admin.NewService(
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		"",
		"",
		nil,
		nil,
		nil,
		nil,
		catalogStatuses{{
			Name:        "catalog.example.",
			Serial:      42,
			Members:     7,
			LastSuccess: lastSuccess,
			LastError:   "transfer failed",
		}},
	)

	response, err := svc.GetServerStatus(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetServerStatus: %v", err)
	}
	if response.Healthy {
		t.Fatal("server status remained healthy after catalog failure")
	}
	var component *pb.AdminComponentStatus
	for _, candidate := range response.Components {
		if candidate.Name == "catalog:catalog.example." {
			component = candidate
			break
		}
	}
	if component == nil {
		t.Fatalf("catalog component missing from %+v", response.Components)
	}
	if component.Healthy ||
		!strings.Contains(component.Message, "serial=42") ||
		!strings.Contains(component.Message, "members=7") ||
		!strings.Contains(component.Message, "last_error=transfer failed") {
		t.Fatalf("catalog component = %+v", component)
	}
}

func TestCatalogAdminOperationsExposeStatusAndPaginateMembers(t *testing.T) {
	lastSuccess := time.Now().Add(-time.Minute).UTC()
	source := catalogStatuses{{
		Name:          "catalog.example.",
		Serial:        42,
		Members:       2,
		LastSuccess:   lastSuccess,
		PendingSerial: 43,
		PendingReason: "approval_required",
		PendingActionCounts: map[string]int{
			"remove": 2,
		},
	}}
	svc := admin.NewService(
		nil, nil, nil, nil, nil, nil, "", "", nil, nil, nil, nil, source,
	)

	catalogs, err := svc.ListCatalogs(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListCatalogs: %v", err)
	}
	if len(catalogs.Catalogs) != 1 ||
		catalogs.Catalogs[0].Serial != 42 ||
		catalogs.Catalogs[0].MemberCount != 2 ||
		catalogs.Catalogs[0].PendingSerial != 43 ||
		catalogs.Catalogs[0].PendingActionCounts["remove"] != 2 ||
		catalogs.Catalogs[0].LastSuccess == nil {
		t.Fatalf("catalog response = %+v", catalogs.Catalogs)
	}

	first, err := svc.ListCatalogMembers(context.Background(), &pb.AdminListCatalogMembersRequest{
		Catalog:  "catalog.example.",
		PageSize: 1,
	})
	if err != nil {
		t.Fatalf("ListCatalogMembers first: %v", err)
	}
	if len(first.Members) != 1 ||
		first.Members[0].Zone != "alpha.example." ||
		first.Members[0].TransferKeyName != "catalog-key.example." ||
		first.NextPageToken == "" ||
		first.TotalCount != 2 ||
		first.SnapshotSerial != 42 {
		t.Fatalf("first member page = %+v", first)
	}
	staleToken, err := base64.RawURLEncoding.DecodeString(first.NextPageToken)
	if err != nil {
		t.Fatalf("decode next page token: %v", err)
	}
	binary.BigEndian.PutUint32(staleToken[:4], 41)
	_, err = svc.ListCatalogMembers(context.Background(), &pb.AdminListCatalogMembersRequest{
		Catalog:   "catalog.example.",
		PageSize:  1,
		PageToken: base64.RawURLEncoding.EncodeToString(staleToken),
	})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("stale token status = %v, err=%v", status.Code(err), err)
	}
	second, err := svc.ListCatalogMembers(context.Background(), &pb.AdminListCatalogMembersRequest{
		Catalog:   "catalog.example.",
		PageSize:  1,
		PageToken: first.NextPageToken,
	})
	if err != nil {
		t.Fatalf("ListCatalogMembers second: %v", err)
	}
	if len(second.Members) != 1 ||
		second.Members[0].Zone != "beta.example." ||
		second.NextPageToken != "" {
		t.Fatalf("second member page = %+v", second)
	}
}
