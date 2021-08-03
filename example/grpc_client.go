package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	ipn "github.com/mblarer/scion-ipn"
	segment "github.com/mblarer/scion-ipn/segment"
	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	appnet "github.com/netsec-ethz/scion-apps/pkg/appnet"
	addr "github.com/scionproto/scion/go/lib/addr"
	pol "github.com/scionproto/scion/go/lib/pathpol"
	snet "github.com/scionproto/scion/go/lib/snet"
	grpc "google.golang.org/grpc"
)

const address = "192.168.1.2:1234"
const destinationIA = "20-ffaa:0:1401"

var aclFilepath string

func main() {
	err := runClient()
	if err != nil {
		log.Fatal(err)
	}
}

func runClient() error {
	flag.StringVar(&aclFilepath, "acl", "", "path to ACL definition file (JSON)")
	flag.Parse()
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return errors.New(fmt.Sprintf("did not connect: %v", err))
	}
	defer conn.Close()
	c := pb.NewNegotiationServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	//segs, err := (&segmentGenerator{}).Query(addr.IA{})
	ia, err := addr.IAFromString(destinationIA)
	if err != nil {
		return err
	}
	_, _ = segment.QuerySegments(ia)
	return nil
	segs, err := (&sciondQuerier{}).Query(ia)
	if err != nil {
		return err
	}
	segments := ipn.SegmentsFromPB(segs)
	filtered, err := filterSegments(segments)
	if err != nil {
		return err
	}
	filteredPB := ipn.SegmentsToPB(filtered)
	request := &pb.Message{Segments: filteredPB}
	response, err := c.Negotiate(ctx, request)
	if err != nil {
		return errors.New(fmt.Sprintf("could not greet: %v", err))
	}
	log.Println("reply:")
	printSeg(response.GetSegments())
	return nil
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
	acl := new(pol.ACL)
	jsonACL, err := os.ReadFile(aclFilepath)
	if err != nil {
		jsonACL = []byte(`["+"]`)
	}
	err = json.Unmarshal(jsonACL, &acl)
	if err != nil {
		return nil, err
	}
	return acl, nil
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

type sciondQuerier struct{}

func (_ *sciondQuerier) Query(ia addr.IA) ([]*pb.Segment, error) {
	paths, err := appnet.QueryPaths(ia)
	if err != nil {
		return nil, err
	}
	return pathsToPB(paths), nil
}

func pathsToPB(paths []snet.Path) []*pb.Segment {
	segments := make([]*pb.Segment, len(paths))
	for i, path := range paths {
		segments[i] = &pb.Segment{
			Id:      uint32(i),
			Valid:   true,
			Literal: interfacesToPB(path.Metadata().Interfaces),
		}
	}
	return segments
}

func interfacesToPB(ifaces []snet.PathInterface) []*pb.Interface {
	pbIfaces := make([]*pb.Interface, len(ifaces))
	for i, iface := range ifaces {
		pbIfaces[i] = &pb.Interface{
			Id:    uint64(iface.ID),
			IsdAs: uint64(iface.IA.IAInt()),
		}
	}
	return pbIfaces
}
