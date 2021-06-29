package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	pb "github.com/mblarer/scion-ipn/proto/negotiation"
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
	r, err := c.NegotiateSegments(ctx, &pb.NegotiationRequest{
		SegmentSets: generateSegmentSets(),
	})
	if err != nil {
		return errors.New(fmt.Sprintf("could not greet: %v", err))
	}
	log.Printf("reply: %s", r.GetSegmentSets())
	return nil
}

type server struct {
	pb.UnimplementedNegotiationServiceServer
}

func (s *server) NegotiateSegments(cotx context.Context, in *pb.NegotiationRequest) (*pb.NegotiationReply, error) {
	log.Printf("request: %v", in.GetSegmentSets())
	return &pb.NegotiationReply{
		SegmentSets: filterSegmentSets(in.GetSegmentSets()),
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

func filterSegmentSets(css []*pb.ClientSegmentSet) []*pb.ServerSegmentSet {
	sss := make([]*pb.ServerSegmentSet, len(css))
	for i := 0; i < len(css); i++ {
		clientSegs := css[i].GetSegments()
		serverSegs := make([]*pb.ServerSegment, len(clientSegs))
		for j := 0; j < len(clientSegs); j++ {
			serverSegs[j] = &pb.ServerSegment{
				SegmentId:   clientSegs[j].GetSegmentId(),
				Subsegments: clientSegs[j].GetSubsegments(),
			}
		}
		sss[i] = &pb.ServerSegmentSet{
			SetId:              css[i].GetSetId(),
			CompatibleNextSets: css[i].GetCompatibleNextSets(),
			Segments:           serverSegs,
		}
	}
	return sss
}

func generateSegmentSets() []*pb.ClientSegmentSet {
	return []*pb.ClientSegmentSet{
		// UP: 1#2 --> 2#1,2 --> 3#1
		&pb.ClientSegmentSet{
			SetId:              1,
			CompatibleNextSets: []uint32{2, 3},
			Segments: []*pb.ClientSegment{
				&pb.ClientSegment{
					SegmentId: 1,
					Subsegments: []*pb.Subsegment{
						&pb.Subsegment{
							Type: pb.Subsegment_LINK,
							Link: &pb.Link{
								Egress:  &pb.Interface{IsdAs: 1, Id: 2},
								Ingress: &pb.Interface{IsdAs: 2, Id: 1},
							},
						},
					},
				},
				&pb.ClientSegment{
					SegmentId: 2,
					Subsegments: []*pb.Subsegment{
						&pb.Subsegment{
							Type:      pb.Subsegment_REFERENCE,
							Reference: 1,
						},
						&pb.Subsegment{
							Type: pb.Subsegment_LINK,
							Link: &pb.Link{
								Egress:  &pb.Interface{IsdAs: 2, Id: 2},
								Ingress: &pb.Interface{IsdAs: 3, Id: 1},
							},
						},
					},
				},
			},
		},
		// CORE: 3#2 --> 4#1
		// PEER: 2#3 --> 5#3
		&pb.ClientSegmentSet{
			SetId:              2,
			CompatibleNextSets: []uint32{3},
			Segments: []*pb.ClientSegment{
				&pb.ClientSegment{
					SegmentId: 3,
					Subsegments: []*pb.Subsegment{
						&pb.Subsegment{
							Type: pb.Subsegment_LINK,
							Link: &pb.Link{
								Egress:  &pb.Interface{IsdAs: 3, Id: 2},
								Ingress: &pb.Interface{IsdAs: 4, Id: 1},
							},
						},
					},
				},
				&pb.ClientSegment{
					SegmentId: 4,
					Subsegments: []*pb.Subsegment{
						&pb.Subsegment{
							Type: pb.Subsegment_LINK,
							Link: &pb.Link{
								Egress:  &pb.Interface{IsdAs: 2, Id: 3},
								Ingress: &pb.Interface{IsdAs: 5, Id: 3},
							},
						},
					},
				},
			},
		},
		// DOWN: 4#2 --> 5#1,2 --> 6#1
		&pb.ClientSegmentSet{
			SetId:              3,
			CompatibleNextSets: []uint32{},
			Segments: []*pb.ClientSegment{
				&pb.ClientSegment{
					SegmentId: 5,
					Subsegments: []*pb.Subsegment{
						&pb.Subsegment{
							Type: pb.Subsegment_LINK,
							Link: &pb.Link{
								Egress:  &pb.Interface{IsdAs: 5, Id: 2},
								Ingress: &pb.Interface{IsdAs: 6, Id: 1},
							},
						},
					},
				},
				&pb.ClientSegment{
					SegmentId: 6,
					Subsegments: []*pb.Subsegment{
						&pb.Subsegment{
							Type: pb.Subsegment_LINK,
							Link: &pb.Link{
								Egress:  &pb.Interface{IsdAs: 4, Id: 2},
								Ingress: &pb.Interface{IsdAs: 5, Id: 1},
							},
						},
						&pb.Subsegment{
							Type:      pb.Subsegment_REFERENCE,
							Reference: 5,
						},
					},
				},
			},
		},
	}
}
