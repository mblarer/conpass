package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	grpc "google.golang.org/grpc"
)

const address = "localhost:1234"

func main() {
	go func() {
		err := runServer()
		if err != nil {
			log.Fatal(err)
		}
	}()

	err := runClient()
	if err != nil {
		log.Fatal(err)
	}
}

func runClient() error {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return errors.New(fmt.Sprintf("did not connect: %v", err))
	}
	defer conn.Close()
	c := pb.NewNegotiationServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	segs, err := (&segmentGenerator{}).Query(addr.IA{})
	if err != nil {
		return err
	}
	request := &pb.Message{Segments: segs}
	response, err := c.Negotiate(ctx, request)
	if err != nil {
		return errors.New(fmt.Sprintf("could not greet: %v", err))
	}
	log.Printf("reply: %v, %v", response.GetOptions(), response.GetSegments())
	return nil
}

type server struct {
	pb.UnimplementedNegotiationServiceServer
}

func (s *server) Negotiate(cotx context.Context, in *pb.Message) (*pb.Message, error) {
	log.Printf("request: %v, %v", in.GetOptions(), in.GetSegments())
	return &pb.Message{
		Segments: filterSegments(in.GetSegments()),
	}, nil
}

func runServer() error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New(fmt.Sprintf("failed to listen: %v", err))
	}
	s := grpc.NewServer()
	pb.RegisterNegotiationServiceServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		return errors.New(fmt.Sprintf("failed to serve: %v", err))
	}
	return nil
}

func filterSegments(clientSegs []*pb.Segment) []*pb.Segment {
	memo := make(map[uint32]bool)
	n := uint32(len(clientSegs))
	serverSegs := make([]*pb.Segment, n)
	for i := uint32(0); i < n; i++ {
		if acceptSegment(memo, clientSegs[i]) {
			serverSegs = append(serverSegs, &pb.Segment{
				Id:          n + clientSegs[i].GetId(),
				Valid:       clientSegs[i].GetValid(),
				Composition: []uint32{clientSegs[i].GetId()},
			})
		}
	}
	return serverSegs
}

// Filter segments based on local attributes
func acceptSegment(memo map[uint32]bool, segment *pb.Segment) bool {
	segId := segment.GetId()
	if accept, ok := memo[segId]; ok {
		return accept
	}

	interfaces := segment.GetLiteral()
	ids := segment.GetComposition()
	if len(interfaces) > 0 {
		memo[segId] = acceptLiteral(interfaces)
	} else {
		memo[segId] = acceptComposition(memo, ids)
	}
	return memo[segId]
}

func acceptLiteral(interfaces []*pb.Interface) bool {
	for _, iface := range interfaces {
		if !acceptInterface(iface) {
			return false
		}
	}
	return true
}

func acceptComposition(memo map[uint32]bool, ids []uint32) bool {
	for _, id := range ids {
		if !memo[id] {
			return false
		}
	}
	return true
}

func acceptInterface(iface *pb.Interface) bool {
	blacklistIsdAs := []uint64{3, 4}
	ifaceIsdAs := iface.GetIsdAs()
	for _, entry := range blacklistIsdAs {
		if ifaceIsdAs == entry {
			return false
		}
	}
	return true
}

type SegmentQuerier interface {
	Query(addr.IA) ([]*pb.Segment, error)
}

type segmentGenerator struct{}

func (_ *segmentGenerator) Query(_ addr.IA) ([]*pb.Segment, error) {
	return []*pb.Segment{
		// UP: 1#2 --> 2#1,2 --> 3#1
		&pb.Segment{
			Id:    1,
			Valid: true,
			Literal: []*pb.Interface{
				&pb.Interface{IsdAs: 1, Id: 2},
				&pb.Interface{IsdAs: 2, Id: 1},
			},
		},
		&pb.Segment{
			Id:    2,
			Valid: false,
			Literal: []*pb.Interface{
				&pb.Interface{IsdAs: 2, Id: 2},
				&pb.Interface{IsdAs: 3, Id: 1},
			},
		},
		&pb.Segment{
			Id:          3,
			Valid:       true,
			Composition: []uint32{1, 2},
		},
		// CORE: 3#2 --> 4#1
		// PEER: 2#3 --> 5#3
		&pb.Segment{
			Id:    4,
			Valid: true,
			Literal: []*pb.Interface{
				&pb.Interface{IsdAs: 3, Id: 2},
				&pb.Interface{IsdAs: 4, Id: 1},
			},
		},
		&pb.Segment{
			Id:    5,
			Valid: true,
			Literal: []*pb.Interface{
				&pb.Interface{IsdAs: 2, Id: 3},
				&pb.Interface{IsdAs: 5, Id: 3},
			},
		},
		// DOWN: 4#2 --> 5#1,2 --> 6#1
		&pb.Segment{
			Id:    6,
			Valid: false,
			Literal: []*pb.Interface{
				&pb.Interface{IsdAs: 4, Id: 2},
				&pb.Interface{IsdAs: 5, Id: 1},
			},
		},
		&pb.Segment{
			Id:    7,
			Valid: true,
			Literal: []*pb.Interface{
				&pb.Interface{IsdAs: 5, Id: 2},
				&pb.Interface{IsdAs: 6, Id: 1},
			},
		},
		&pb.Segment{
			Id:          8,
			Valid:       true,
			Composition: []uint32{6, 7},
		},
	}, nil
}
