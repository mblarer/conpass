package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	grpc "google.golang.org/grpc"
)

const address = "192.168.1.2:1234"
const destinationIA = "20-ffaa:0:1401"

func main() {
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
	//segs, err := (&segmentGenerator{}).Query(addr.IA{})
	ia, err := addr.IAFromString(destinationIA)
	if err != nil {
		return err
	}
	segs, err := (&sciondQuerier{}).Query(ia)
	if err != nil {
		return err
	}
	request := &pb.Message{Segments: segs}
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
