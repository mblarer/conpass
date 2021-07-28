package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	grpc "google.golang.org/grpc"
)

const address = "192.168.1.2:1234"

func main() {
	err := runServer()
	if err != nil {
		log.Fatal(err)
	}
}

type server struct {
	pb.UnimplementedNegotiationServiceServer
}

func (s *server) Negotiate(cotx context.Context, in *pb.Message) (*pb.Message, error) {
	log.Println("request:")
	printSeg(in.GetSegments())
	return &pb.Message{
		Segments: filterSegments(in.GetSegments()),
	}, nil
}

func printSeg(segs []*pb.Segment) {
	for _, seg := range segs {
		if len(seg.GetLiteral()) > 0 {
			fmt.Printf("  [%d]: ", seg.GetId())
			printLit(seg.GetLiteral())
			fmt.Printf("\n")
		} else {
			fmt.Printf("  [%d]: %v\n", seg.GetId(), seg.GetComposition())
		}
	}
}

func printLit(lit []*pb.Interface) {
	for i, iface := range lit {
		if i == len(lit) - 1 {
			fmt.Printf(">%d %s", iface.GetId(), addr.IAInt(iface.GetIsdAs()).IA())
		} else if i % 2 == 0 {
			fmt.Printf("%s %d", addr.IAInt(iface.GetIsdAs()).IA(), iface.GetId())
		} else if i % 2 == 1 {
			fmt.Printf(">%d ", iface.GetId())
		}
	}
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
	serverSegs := make([]*pb.Segment, 0, n)
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
