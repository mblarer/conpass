package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/scion-ipn"
	"github.com/mblarer/scion-ipn/filter"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	defaultAclFilepath     = ""
	defaultSeqFilepath     = ""
	defaultTargetIA        = "17-ffaa:1:ef4"
	defaultHost            = "192.168.1.2"
	defaultNegotiationPort = "50000"
	defaultPingPort        = "50001"
)

var (
	aclFilepath     string
	seqFilepath     string
	targetIA        string
	host            string
	negotiationPort string
	pingPort        string
)

func main() {
	parseArgs()
	paths, err := runNegotiationClient()
	err = runPingClient(paths)
	if err != nil {
		log.Fatal(err)
	}
}

func runNegotiationClient() ([]snet.Path, error) {
	address := fmt.Sprintf("%s:%s", host, negotiationPort)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"scion-ipn-example"},
	}
	session, err := quic.DialAddr(address, tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	srcIA := (*appnet.DefNetwork()).IA
	dstIA, _ := addr.IAFromString(targetIA)
	paths, err := appnet.QueryPaths(dstIA)
	if err != nil {
		return nil, fmt.Errorf("failed to query paths: %s", err.Error())
	}
	log.Println("queried", len(paths), "different paths to", dstIA)
	for _, path := range paths {
		fmt.Println(" ", path)
	}
	segments, err := segment.SplitPaths(paths)
	if err != nil {
		return nil, fmt.Errorf("failed to split paths: %s", err.Error())
	}
	log.Println("split paths into", len(segments), "different segments:")
	for _, segment := range segments {
		fmt.Println(" ", segment)
	}
	segset := segment.SegmentSet{
		Segments: segments,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}
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
		pathEnumerator := filter.SrcDstPathEnumerator()
		sequenceFilter := filter.FromSequence(*seq)
		filters = append(filters, pathEnumerator, sequenceFilter)
	}
	agent := ipn.Initiator{
		InitialSegset: segset,
		Filter:        filter.FromFilters(filters...),
		Verbose:       true,
	}
	segset, err = agent.NegotiateOver(stream)
	if err != nil {
		return nil, err
	}
	newpaths := make([]snet.Path, 0)
	srcDstPaths := segment.SrcDstPaths(segset.Segments, srcIA, dstIA)
	accepted := make(map[string]bool)
	for _, sdpath := range srcDstPaths {
		accepted[segment.Hash(sdpath)] = true
	}
	for _, path := range paths {
		if accepted[string(snet.Fingerprint(path))] {
			newpaths = append(newpaths, path)
		}
	}
	fmt.Println()
	log.Println("negotiated", len(newpaths), "paths in total:")
	for _, path := range newpaths {
		fmt.Println(" ", path)
	}
	return newpaths, nil
}

func runPingClient(paths []snet.Path) error {
	address := fmt.Sprintf("%s:%s", host, pingPort)
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

	_, err = stream.Write([]byte("PING"))
	if err != nil {
		return err
	}
	buffer := make([]byte, 64)
	n, err := stream.Read(buffer)
	if err != nil && err != io.EOF {
		return err
	}
	buffer = buffer[:n]
	fmt.Println("client received:", string(buffer))
	return nil
}

func parseArgs() {
	flag.StringVar(&aclFilepath, "acl", defaultAclFilepath, "path to ACL definition file (JSON)")
	flag.StringVar(&seqFilepath, "seq", defaultSeqFilepath, "path to sequence definition file (JSON)")
	flag.StringVar(&targetIA, "ia", defaultTargetIA, "ISD-AS of the target host")
	flag.StringVar(&host, "host", defaultHost, "IP address of the negotiation server")
	flag.StringVar(&negotiationPort, "port", defaultNegotiationPort, "port number of the negotiation server")
	flag.StringVar(&pingPort, "ping", defaultPingPort, "port number of the ping server")
	flag.Parse()
}

func createACL() (*pathpol.ACL, error) {
	acl := new(pathpol.ACL)
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

func createSequence() (*pathpol.Sequence, error) {
	seq := new(pathpol.Sequence)
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
