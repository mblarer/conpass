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

	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	segment "github.com/mblarer/scion-ipn/segment"
	appnet "github.com/netsec-ethz/scion-apps/pkg/appnet"
	addr "github.com/scionproto/scion/go/lib/addr"
	pol "github.com/scionproto/scion/go/lib/pathpol"
	snet "github.com/scionproto/scion/go/lib/snet"
	grpc "google.golang.org/grpc"
)

const (
	defaultAclFilepath     = ""
	defaultTargetIA        = "17-ffaa:1:ef4"
	defaultNegotiationHost = "192.168.1.2"
	defaultNegotiationPort = "1234"
)

var (
	aclFilepath     string
	targetIA        string
	negotiationHost string
	negotiationPort string
)

func main() {
	err := runClient()
	if err != nil {
		log.Fatal(err)
	}
}

func runClient() error {
	parseArgs()
	address := fmt.Sprintf("%s:%s", negotiationHost, negotiationPort)
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return errors.New(fmt.Sprintf("did not connect: %v", err))
	}
	defer conn.Close()
	c := pb.NewNegotiationServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ia, err := addr.IAFromString(targetIA)
	if err != nil {
		return err
	}
	segments, err := segment.QuerySegments(ia)
	if err != nil {
		return err
	}
	filtered, err := filterSegments(segments)
	if err != nil {
		return err
	}
	rawsegs := segment.EncodeSegments([]segment.Segment{}, filtered)
	request := &pb.Message{Segments: rawsegs}
	response, err := c.Negotiate(ctx, request)
	if err != nil {
		return errors.New(fmt.Sprintf("could not negotiate: %v", err))
	}
	log.Println("reply:")
	printSeg(response.GetSegments())
	return nil
}

func parseArgs() {
	flag.StringVar(&aclFilepath, "acl", defaultAclFilepath, "path to ACL definition file (JSON)")
	flag.StringVar(&targetIA, "ia", defaultTargetIA, "ISD-AS of the target host")
	flag.StringVar(&negotiationHost, "host", defaultNegotiationHost, "IP address of the negotiation server")
	flag.StringVar(&negotiationPort, "port", defaultNegotiationPort, "port number of the negotiation server")
	flag.Parse()
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

func filterSegments(segments []segment.Segment) ([]segment.Segment, error) {
	acl, err := createACL()
	if err != nil {
		return nil, err
	}
	filter := segment.PredicateFilter{segment.ACLPredicate{acl}}
	filtered := filter.Filter(segments)
	return filtered, nil
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
