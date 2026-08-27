package engine

import (
	"context"
	"testing"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZoneManager_AddAndGetZone(t *testing.T) {
	zm := NewZoneManager()

	zone := ports.ZoneInfo{
		Name: "example.com.",
		Type: "primary",
	}
	records := []ports.ResourceRecord{
		{Name: "example.com.", Type: "A", TTL: 3600, Data: "127.0.0.1"},
	}

	zm.AddZone(zone, records)

	// List
	ctx := context.Background()
	zones, err := zm.ListZones(ctx, "", "")
	require.NoError(t, err)
	assert.Len(t, zones, 1)
	assert.Equal(t, "example.com.", zones[0].Name)

	// Get with records
	z, recs, err := zm.GetZone(ctx, "example.com.", true, "")
	require.NoError(t, err)
	assert.NotNil(t, z)
	assert.Equal(t, "example.com.", z.Name)
	assert.Len(t, recs, 1)
	assert.Equal(t, "example.com.", recs[0].Name)
	assert.Equal(t, "127.0.0.1", recs[0].Data)
}
