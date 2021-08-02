package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	ipn "github.com/mblarer/scion-ipn"
	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	pol "github.com/scionproto/scion/go/lib/pathpol"
	grpc "google.golang.org/grpc"
)

const address = "192.168.1.2:1234"

func main() {
	err := runServer()
	if err != nil {
		log.Fatal(err)
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

type server struct {
	pb.UnimplementedNegotiationServiceServer
}

func (s *server) Negotiate(cotx context.Context, in *pb.Message) (*pb.Message, error) {
	log.Println("request:")
	pbsegs := in.GetSegments()
	printSeg(pbsegs)
	segments := ipn.SegmentsFromPB(pbsegs)
	filtered, err := filterSegments(segments)
	if err != nil {
		return nil, err
	}
	filteredPB := ipn.SegmentsToPB(filtered)
	return &pb.Message{Segments: filteredPB}, nil
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
		if i == len(lit)-1 {
			fmt.Printf(">%d %s", iface.GetId(), addr.IAInt(iface.GetIsdAs()).IA())
		} else if i%2 == 0 {
			fmt.Printf("%s %d", addr.IAInt(iface.GetIsdAs()).IA(), iface.GetId())
		} else if i%2 == 1 {
			fmt.Printf(">%d ", iface.GetId())
		}
	}
}

func filterSegments(clientSegs []ipn.Segment) ([]ipn.Segment, error) {
	acl, err := createACL()
	if err != nil {
		return nil, err
	}
	return ipn.PredicateFilter{ipn.ACLPredicate{acl}}.Filter(clientSegs), nil
}

func createACL() (*pol.ACL, error) {
	var acl *pol.ACL
	jsonACL := []byte("[\"- 18-ffaa:0:1201\",\"+\"]")
	err := json.Unmarshal(jsonACL, acl)
	if err != nil {
		return nil, err
	}
	return acl, nil
}
