package services

import (
	"context"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DNSSECService struct {
	pb.UnimplementedDNSSECServiceServer
	Mgr ports.DNSSECManager
}

func NewDNSSECService(m ports.DNSSECManager) *DNSSECService { return &DNSSECService{Mgr: m} }

func (s *DNSSECService) GetStatus(ctx context.Context, in *pb.DNSSECStatusRequest) (*pb.DNSSECStatusResponse, error) {
	st, err := s.Mgr.Status(ctx, in.GetZoneName())
	if err != nil { return nil, err }
	mode := in.GetIncludePublicKeyMode()
	if mode == pb.IncludeKeyMode_INCLUDE_KEY_MODE_UNSPECIFIED {
		mode = pb.IncludeKeyMode_INCLUDE_KEY_MODE_MAY // default
	}
	resp := &pb.DNSSECStatusResponse{ZoneName: st.Zone, Enabled: st.Enabled, Signed: st.Signed, Algorithm: pb.DNSSECAlgorithm_DNSSEC_ALGORITHM_UNSPECIFIED}
	for _, k := range st.Keys {
		pk := ""
		switch mode {
		case pb.IncludeKeyMode_INCLUDE_KEY_MODE_OFF:
			pk = ""
		case pb.IncludeKeyMode_INCLUDE_KEY_MODE_ON:
			pk = k.PublicKey
		case pb.IncludeKeyMode_INCLUDE_KEY_MODE_MAY:
			if len(k.PublicKey) > 0 && len(k.PublicKey) <= 4096 { pk = k.PublicKey }
		}
		resp.Keys = append(resp.Keys, &pb.DNSSECKey{Id: k.ID, KeyTag: k.KeyTag, Type: pb.KeyType_KEY_TYPE_UNSPECIFIED, Algorithm: pb.DNSSECAlgorithm_DNSSEC_ALGORITHM_UNSPECIFIED, Status: pb.KeyStatus_KEY_STATUS_ACTIVE, PublicKey: pk, HasPrivateKey: k.HasPrivate, KeySize: k.KeySize})
	}
	return resp, nil
}

func (s *DNSSECService) Sign(ctx context.Context, in *pb.SignZoneRequest) (*pb.SignZoneResponse, error) {
	so, err := s.Mgr.Sign(ctx, in.GetZoneName(), in.GetIncrementSerial(), in.GetResignAll())
	if err != nil { return nil, err }
	return &pb.SignZoneResponse{ZoneName: so.Zone, Success: so.Success, OldSerial: so.OldSerial, NewSerial: so.NewSerial, SignaturesCreated: so.SignaturesCreated, SignaturesUpdated: so.SignaturesUpdated}, nil
}

func (s *DNSSECService) Rollover(ctx context.Context, in *pb.RolloverRequest) (*pb.RolloverResponse, error) {
	ro, err := s.Mgr.Rollover(ctx, in.GetZoneName(), in.GetKeyType().String(), in.GetNewAlgorithm().String(), in.GetKeySize())
	if err != nil { return nil, err }
	return &pb.RolloverResponse{ZoneName: ro.Zone, KeyType: pb.KeyType_KEY_TYPE_UNSPECIFIED, Status: ro.Status}, nil
}

func (s *DNSSECService) GetDS(ctx context.Context, in *pb.GetDSRequest) (*pb.GetDSResponse, error) {
	ds, err := s.Mgr.GetDS(ctx, in.GetZoneName(), in.GetKeyType().String())
	if err != nil { return nil, err }
	resp := &pb.GetDSResponse{ZoneName: in.GetZoneName()}
	for _, d := range ds { resp.DsRecords = append(resp.DsRecords, &pb.DSRecord{KeyTag: d.KeyTag, DigestType: d.DigestType, Digest: d.Digest, Record: d.Record}) }
	return resp, nil
}

func (s *DNSSECService) GenerateKey(ctx context.Context, in *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	km, err := s.Mgr.GenerateKey(ctx, in.GetZoneName(), in.GetType().String(), in.GetAlgorithm().String(), in.GetKeySize(), in.GetActivateImmediately())
	if err != nil { return nil, err }
	return &pb.GenerateKeyResponse{Key: &pb.DNSSECKey{Id: km.Key.ID, PublicKey: km.Key.PublicKey, HasPrivateKey: km.Key.HasPrivate}, PublicKey: km.Public, PrivateKey: km.Private}, nil
}

func (s *DNSSECService) ImportKey(ctx context.Context, in *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	ki, err := s.Mgr.ImportKey(ctx, in.GetZoneName(), in.GetType().String(), in.GetAlgorithm().String(), in.GetPublicKey(), in.GetPrivateKey(), in.GetActivateImmediately())
	if err != nil { return nil, err }
	return &pb.ImportKeyResponse{Key: &pb.DNSSECKey{Id: ki.ID, PublicKey: ki.PublicKey, HasPrivateKey: ki.HasPrivate}}, nil
}

func (s *DNSSECService) ExportKey(ctx context.Context, in *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	km, err := s.Mgr.ExportKey(ctx, in.GetZoneName(), in.GetKeyId(), in.GetIncludePrivate())
	if err != nil { return nil, err }
	return &pb.ExportKeyResponse{Key: &pb.DNSSECKey{Id: km.Key.ID}, PublicKey: km.Public, PrivateKey: km.Private}, nil
}

func (s *DNSSECService) DeleteKey(ctx context.Context, in *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	dr, err := s.Mgr.DeleteKey(ctx, in.GetZoneName(), in.GetKeyId(), in.GetForce())
	if err != nil { return nil, err }
	return &pb.DeleteKeyResponse{KeyId: dr.KeyID, Success: dr.Success, Message: dr.Message}, nil
}

func (s *DNSSECService) ValidateChain(ctx context.Context, in *pb.ValidateChainRequest) (*pb.ValidateChainResponse, error) {
	vr, err := s.Mgr.ValidateChain(ctx, in.GetZoneName(), in.GetTrustAnchors())
	if err != nil { return nil, err }
	return &pb.ValidateChainResponse{ZoneName: vr.Zone, Valid: vr.Valid, ValidationPath: vr.Path, Errors: vr.Errors}, nil
}

func (s *DNSSECService) WatchKeys(*pb.WatchKeysRequest, pb.DNSSECService_WatchKeysServer) error {
	return status.Error(codes.Unimplemented, "WatchKeys not implemented yet")
}
