package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	filter "github.com/mblarer/scion-ipn/filter"
	segment "github.com/mblarer/scion-ipn/segment"
	pol "github.com/scionproto/scion/go/lib/pathpol"
	grpc "google.golang.org/grpc"
)

const address = "192.168.1.2:1234"

var aclFilepath string

func main() {
	err := runServer()
	if err != nil {
		log.Fatal(err)
	}
}

func runServer() error {
	flag.StringVar(&aclFilepath, "acl", "", "path to ACL definition file (JSON)")
	flag.Parse()
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
	rawoldsegs := in.GetSegments()
	oldsegs, err := segment.DecodeSegments(rawoldsegs, []segment.Segment{})
	for _, segment := range oldsegs {
		fmt.Println(" ", segment)
	}
	if err != nil {
		return nil, err
	}
	newsegs, err := filterSegments(oldsegs)
	if err != nil {
		return nil, err
	}
	rawnewsegs := segment.EncodeSegments(newsegs, oldsegs)
	return &pb.Message{Segments: rawnewsegs}, nil
}

func filterSegments(segments []segment.Segment) ([]segment.Segment, error) {
	acl, err := createACL()
	if err != nil {
		return nil, err
	}
	filtered := filter.FromACL(*acl).Filter(segments)
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
