package services

import (
	"context"

	"github.com/afterdarksys/dnsscienced/api/grpc/ports"
	pb "github.com/afterdarksys/dnsscienced/api/grpc/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DNSService struct {
	pb.UnimplementedDNSServiceServer
	Resolver ports.DNSResolver
}

func NewDNSService(res ports.DNSResolver) *DNSService { return &DNSService{Resolver: res} }

func (s *DNSService) Query(ctx context.Context, req *pb.QueryRequest) (*pb.QueryResponse, error) {
	res, err := s.Resolver.Resolve(ctx, req.GetName(), req.GetType(), req.GetClass(), req.GetDnssec(), req.GetRecursionDesired(), req.GetCheckingDisabled())
	if err != nil {
		if status.Code(err) == codes.Unavailable || status.Code(err) == codes.Unimplemented {
			return nil, err
		}
		return &pb.QueryResponse{Rcode: 2, RcodeName: "SERVFAIL", Error: &pb.ErrorDetail{Code: "RESOLVE_ERROR", Message: err.Error()}}, nil
	}
	toRR := func(rr ports.ResourceRecord) *pb.ResourceRecord {
		return &pb.ResourceRecord{Name: rr.Name, Type: rr.Type, Class: rr.Class, Ttl: rr.TTL, Data: rr.Data, Rdata: rr.RData}
	}
	resp := &pb.QueryResponse{
		Rcode:              res.RCode,
		RcodeName:          res.RCodeName,
		Authoritative:      res.Authoritative,
		Truncated:          res.Truncated,
		RecursionAvailable: res.RecursionAvailable,
		WireFormat:         res.Wire,
	}
	for _, a := range res.Answer {
		resp.Answer = append(resp.Answer, toRR(a))
	}
	for _, a := range res.Authority {
		resp.Authority = append(resp.Authority, toRR(a))
	}
	for _, a := range res.Additional {
		resp.Additional = append(resp.Additional, toRR(a))
	}
	return resp, nil
}

func (s *DNSService) StreamQueries(stream pb.DNSService_StreamQueriesServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		resp, _ := s.Query(stream.Context(), req)
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func (s *DNSService) BatchQueries(ctx context.Context, in *pb.BatchQueryRequest) (*pb.BatchQueryResponse, error) {
	out := &pb.BatchQueryResponse{}
	for _, q := range in.GetQueries() {
		resp, _ := s.Query(ctx, q)
		out.Responses = append(out.Responses, resp)
		if resp.GetError() != nil {
			out.Failed++
		} else {
			out.Successful++
		}
	}
	return out, nil
}
