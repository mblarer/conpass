package main

import (
	"context"
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

var policy *pol.ACL

func main() {
	err := initializePolicy()
	if err != nil {
		log.Fatal(err)
	}
	err = runServer()
	if err != nil {
		log.Fatal(err)
	}
}

func initializePolicy() error {
	var err error
	entry1, entry2 := new(pol.ACLEntry), new(pol.ACLEntry)
	err = entry1.LoadFromString("- 18-ffaa:0:1201")
	if err != nil {
		return err
	}
	err = entry2.LoadFromString("+")
	if err != nil {
		return err
	}
	acl, err := pol.NewACL(entry1, entry2)
	if err != nil {
		return nil
	}
	policy = acl
	return nil
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
	filtered := filterSegments(segments)
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

func filterSegments(clientSegs []ipn.Segment) []ipn.Segment {
	return ipn.PredicateFilter{ipn.ACLPredicate{policy}}.Filter(clientSegs)
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
