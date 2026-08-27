package services

import (
	"context"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ZoneService struct {
	pb.UnimplementedZoneServiceServer
	Mgr ports.ZoneManager
}

func NewZoneService(m ports.ZoneManager) *ZoneService { return &ZoneService{Mgr: m} }

func toPBZone(z ports.ZoneInfo) *pb.Zone {
	p := &pb.Zone{
		Name:            z.Name,
		Type:            pb.ZoneType_ZONE_TYPE_PRIMARY,
		File:            z.File,
		Status:          z.Status,
		RecordCount:     z.RecordCount,
		DnssecEnabled:   z.DNSSECEnabled,
		DnssecAlgorithm: z.DNSSECAlgorithm,
		Primaries:       z.Primaries,
		NotifySlaves:    z.NotifySlaves,
		AllowTransfer:   z.AllowTransfer,
	}
	p.LastReload = nil
	p.LastTransfer = nil
	p.Soa = &pb.Zone_SOA{Primary: z.SOA.Primary, Admin: z.SOA.Admin, Serial: z.SOA.Serial, Refresh: z.SOA.Refresh, Retry: z.SOA.Retry, Expire: z.SOA.Expire, Minimum: z.SOA.Minimum}
	return p
}

func (s *ZoneService) ListZones(ctx context.Context, in *pb.ListZonesRequest) (*pb.ListZonesResponse, error) {
	zs, err := s.Mgr.ListZones(ctx, in.GetType().String(), in.GetNamePattern())
	if err != nil { return nil, err }
	out := &pb.ListZonesResponse{}
	for _, z := range zs { out.Zones = append(out.Zones, toPBZone(z)) }
	out.Total = int32(len(out.Zones))
	return out, nil
}

func (s *ZoneService) GetZone(ctx context.Context, in *pb.GetZoneRequest) (*pb.GetZoneResponse, error) {
	z, recs, err := s.Mgr.GetZone(ctx, in.GetZoneName(), in.GetIncludeRecords(), in.GetRecordType())
	if err != nil { return nil, err }
	resp := &pb.GetZoneResponse{Zone: toPBZone(*z)}
	for _, r := range recs {
		resp.Records = append(resp.Records, &pb.ResourceRecord{Name: r.Name, Type: r.Type, Class: r.Class, Ttl: r.TTL, Data: r.Data, Rdata: r.RData})
	}
	return resp, nil
}

func (s *ZoneService) ReloadZone(ctx context.Context, in *pb.ReloadZoneRequest) (*pb.ReloadZoneResponse, error) {
	ro, err := s.Mgr.ReloadZone(ctx, in.GetZoneName(), in.GetVerifyOnly())
	if err != nil { return nil, err }
	return &pb.ReloadZoneResponse{ZoneName: ro.Zone, Success: ro.Success, Message: ro.Message, OldSerial: ro.OldSerial, NewSerial: ro.NewSerial, RecordCount: ro.RecordCount}, nil
}

func (s *ZoneService) NotifySecondaries(ctx context.Context, in *pb.NotifyRequest) (*pb.NotifyResponse, error) {
	no, err := s.Mgr.Notify(ctx, in.GetZoneName(), in.GetServers())
	if err != nil { return nil, err }
	resp := &pb.NotifyResponse{ZoneName: no.Zone, Serial: no.Serial}
	for _, r := range no.Results { resp.Results = append(resp.Results, &pb.NotifyResponse_NotifyResult{Server: r.Server, Acknowledged: r.Acknowledged, Message: r.Message}) }
	return resp, nil
}

func (s *ZoneService) TransferZone(ctx context.Context, in *pb.TransferZoneRequest) (*pb.TransferZoneResponse, error) {
	to, err := s.Mgr.Transfer(ctx, in.GetZoneName(), in.GetTransferType(), in.GetServer())
	if err != nil { return nil, err }
	return &pb.TransferZoneResponse{ZoneName: to.Zone, TransferType: to.Type, Success: to.Success, OldSerial: to.OldSerial, NewSerial: to.NewSerial, RecordsChanged: to.Changed}, nil
}

func (s *ZoneService) UpdateRecords(ctx context.Context, in *pb.UpdateRecordsRequest) (*pb.UpdateRecordsResponse, error) {
	var ups []ports.RecordUpdate
	for _, u := range in.GetUpdates() { ups = append(ups, ports.RecordUpdate{Operation: u.GetOperation().String(), Name: u.GetName(), Type: u.GetType(), TTL: u.GetTtl(), Data: u.GetData(), OldData: u.GetOldData()}) }
	uo, err := s.Mgr.UpdateRecords(ctx, in.GetZoneName(), ups, in.GetIncrementSerial())
	if err != nil { return nil, err }
	resp := &pb.UpdateRecordsResponse{ZoneName: uo.Zone, NewSerial: uo.NewSerial, Applied: uo.Applied, Failed: uo.Failed}
	for _, r := range uo.Results { resp.Results = append(resp.Results, &pb.UpdateRecordsResponse_UpdateResult{Update: &pb.RecordUpdate{Name: r.Update.Name, Type: r.Update.Type, Ttl: r.Update.TTL, Data: r.Update.Data, OldData: r.Update.OldData}, Success: r.Success, Error: r.Error}) }
	return resp, nil
}

func (s *ZoneService) GetRecords(ctx context.Context, in *pb.GetRecordsRequest) (*pb.GetRecordsResponse, error) {
	recs, err := s.Mgr.GetRecords(ctx, in.GetZoneName(), in.GetName(), in.GetType())
	if err != nil { return nil, err }
	resp := &pb.GetRecordsResponse{ZoneName: in.GetZoneName()}
	for _, r := range recs { resp.Records = append(resp.Records, &pb.ResourceRecord{Name: r.Name, Type: r.Type, Class: r.Class, Ttl: r.TTL, Data: r.Data, Rdata: r.RData}) }
	resp.Count = int32(len(resp.Records))
	return resp, nil
}

func (s *ZoneService) WatchZone(*pb.WatchZoneRequest, pb.ZoneService_WatchZoneServer) error {
	return status.Error(codes.Unimplemented, "WatchZone not implemented yet")
}
