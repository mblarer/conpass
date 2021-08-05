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
	filter "github.com/mblarer/scion-ipn/filter"
	appnet "github.com/netsec-ethz/scion-apps/pkg/appnet"
	addr "github.com/scionproto/scion/go/lib/addr"
	pol "github.com/scionproto/scion/go/lib/pathpol"
	grpc "google.golang.org/grpc"
)

const (
	defaultAclFilepath     = ""
	defaultSeqFilepath     = ""
	defaultTargetIA        = "17-ffaa:1:ef4"
	defaultNegotiationHost = "192.168.1.2"
	defaultNegotiationPort = "1234"
)

var (
	aclFilepath     string
	seqFilepath     string
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
	paths, err := appnet.QueryPaths(ia)
	if err != nil {
		return fmt.Errorf("failed to query paths: %s", err.Error())
	}
	segments, err := segment.SplitPaths(paths)
	if err != nil {
		return fmt.Errorf("failed to split paths: %s", err.Error())
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
	flag.StringVar(&seqFilepath, "seq", defaultSeqFilepath, "path to sequence definition file (JSON)")
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
		fmt.Println("could not create ACL policy:", err.Error())
	}
	seq, err := createSequence()
	if err != nil {
		fmt.Println("could not create sequence policy:", err.Error())
	}
	filters := make([]segment.Filter, 0)
	if acl != nil {
		aclFilter := filter.FromACL(*acl)
		filters = append(filters, aclFilter)
	}
	if seq != nil {
		srcIA := (*appnet.DefNetwork()).IA
		dstIA, _ := addr.IAFromString(targetIA)
		pathEnumerator := filter.SrcDstPathEnumerator(srcIA, dstIA)
		sequenceFilter := filter.FromSequence(*seq)
		filters = append(filters, pathEnumerator, sequenceFilter)
	}
	filtered := filter.FromFilters(filters...).Filter(segments)
	return filtered, nil
}

func createACL() (*pol.ACL, error) {
	acl := new(pol.ACL)
	jsonACL, err := os.ReadFile(aclFilepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonACL, &acl)
	if err != nil {
		return nil, err
	}
	return acl, nil
}

func createSequence() (*pol.Sequence, error) {
	seq := new(pol.Sequence)
	jsonSeq, err := os.ReadFile(seqFilepath)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonSeq, &seq)
	if err != nil {
		return nil, err
	}
	return seq, nil
}
