package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go"
	filter "github.com/mblarer/scion-ipn/filter"
	segment "github.com/mblarer/scion-ipn/segment"
	appnet "github.com/netsec-ethz/scion-apps/pkg/appnet"
	addr "github.com/scionproto/scion/go/lib/addr"
	snet "github.com/scionproto/scion/go/lib/snet"
	pol "github.com/scionproto/scion/go/lib/pathpol"
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
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"scion-ipn-example"},
	}
	session, err := quic.DialAddr(address, tlsConfig, nil)
	if err != nil {
		return err
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()
	ia, err := addr.IAFromString(targetIA)
	if err != nil {
		return err
	}
	paths, err := appnet.QueryPaths(ia)
	if err != nil {
		return fmt.Errorf("failed to query paths: %s", err.Error())
	}
	log.Println("queried", len(paths), "different paths to", targetIA)
	for _, path := range paths {
		fmt.Println(" ", path)
	}
	segments, err := segment.SplitPaths(paths)
	if err != nil {
		return fmt.Errorf("failed to split paths: %s", err.Error())
	}
	log.Println("split paths into", len(segments), "different segments:")
	for _, segment := range segments {
		fmt.Println(" ", segment)
	}
	newsegs, err := filterSegments(segments)
	if err != nil {
		return err
	}
	log.Println(len(newsegs), "segments remaining after initial filtering:")
	for _, segment := range newsegs {
		fmt.Println(" ", segment)
	}
	oldsegs := []segment.Segment{}
	bytes := segment.EncodeSegments(newsegs, oldsegs)
	_, err = stream.Write(bytes)
	if err != nil {
		return err
	}
	recvbuf := make([]byte, 64 * 1024)
	_, err = stream.Read(recvbuf)
	if err != nil {
		return err
	}
	oldsegs = newsegs
	newsegs, err = segment.DecodeSegments(recvbuf, oldsegs)
	if err != nil {
		return fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	log.Println("the server replied with", len(newsegs), "segments:")
	for _, segment := range newsegs {
		fmt.Println(" ", segment)
	}
	//newsegs, err = filterSegments(segments)
	log.Println(len(newsegs), "segments remaining after final filtering:")
	for _, segment := range newsegs {
		fmt.Println(" ", segment)
	}
	srcIA := (*appnet.DefNetwork()).IA
	dstIA, _ := addr.IAFromString(targetIA)
	newsegs = segment.SrcDstPaths(newsegs, srcIA, dstIA)
	if err != nil {
		return err
	}
	newpaths := make([]snet.Path, 0)
	// This is currently O(n*n), we can do it in O(n)
	for _, path := range paths {
		for _, seg := range newsegs {
			if string(snet.Fingerprint(path)) == segment.Fingerprint(seg) {
				newpaths = append(newpaths, path)
			}
		}
	}
	fmt.Println()
	log.Println("negotiated", len(newpaths), "paths in total:")
	for _, path := range newpaths {
		fmt.Println(" ", path)
	}

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
