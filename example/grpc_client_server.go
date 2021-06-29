package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	pb "github.com/mblarer/scion-ipn/proto/negotiation"
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

type server struct {
	pb.UnimplementedNegotiationServiceServer
}

func (s *server) NegotiateSegments(cotx context.Context, in *pb.NegotiationRequest) (*pb.NegotiationReply, error) {
	log.Printf("request: %v", in.GetName())
	return &pb.NegotiationReply{Message: "fine, send me your segments"}, nil
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

func runClient() error {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return errors.New(fmt.Sprintf("did not connect: %v", err))
	}
	defer conn.Close()
	c := pb.NewNegotiationServiceClient(conn)
	name := "let's negotiate path segments"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.NegotiateSegments(ctx, &pb.NegotiationRequest{Name:name})
	if err != nil {
		return errors.New(fmt.Sprintf("could not greet: %v", err))
	}
	log.Printf("reply: %s", r.GetMessage())
	return nil
}
