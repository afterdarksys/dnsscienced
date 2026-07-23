package admin_test

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/dnsscience/dnsscienced/api/grpc/proto/pb"
	"github.com/dnsscience/dnsscienced/internal/admin"
	"github.com/dnsscience/dnsscienced/internal/catalog"
	"google.golang.org/protobuf/types/known/emptypb"
)

type catalogStatuses []catalog.Status

func (s catalogStatuses) Statuses() []catalog.Status {
	return append([]catalog.Status(nil), s...)
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
