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
	"time"

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
	quicTransport bool = false
	tlsTransport  bool = true

	defaultAclFilepath     = ""
	defaultHost            = "127.0.0.1"
	defaultNegotiationPort = "50000"
	defaultPingPort        = "50001"
	defaultSeqFilepath     = ""
	defaultShouldNegotiate = true
	defaultTargetIA        = "17-ffaa:0:1102" // ETHZ
	defaultTransport       = quicTransport
)

var (
	aclFilepath     string
	host            string
	negotiationPort string
	pingPort        string
	seqFilepath     string
	shouldNegotiate bool
	targetIA        string
	transport       bool
)

func main() {
	defer unpanic()
	start := time.Now()
	parseArgs()
	if shouldNegotiate {
		paths := runNegotiationClient()
		runPingClient(paths)
	} else {
		runPingClient(nil)
	}
	fmt.Println(int64(time.Since(start)))
}

func unpanic() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatal("client error: ", err)
		}
	}()
}

func parseArgs() {
	flag.StringVar(&aclFilepath, "acl", defaultAclFilepath,
		"path to ACL definition file (JSON)")
	flag.StringVar(&host, "host", defaultHost,
		"IP address of the negotiation server")
	flag.StringVar(&negotiationPort, "port", defaultNegotiationPort,
		"port number of the negotiation server")
	flag.StringVar(&pingPort, "ping", defaultPingPort,
		"port number of the ping server")
	flag.StringVar(&seqFilepath, "seq", defaultSeqFilepath,
		"path to sequence definition file (JSON)")
	flag.BoolVar(&shouldNegotiate, "neg", defaultShouldNegotiate,
		"whether client should negotiate")
	flag.StringVar(&targetIA, "ia", defaultTargetIA,
		"ISD-AS of the target host")
	flag.BoolVar(&transport, "tls", defaultTransport,
		"use TLS instead of default QUIC")
	flag.Parse()
}

func runNegotiationClient() []snet.Path {
	srcIA, dstIA := connIAs()
	paths := fetchPaths(dstIA)
	log.Println("queried", len(paths), "different paths to", dstIA)
	segset := buildSegmentSet(paths, srcIA, dstIA)
	log.Println("split paths into", len(segset.Segments), "different segments:")
	filter := buildFilter()
	agent := ipn.Initiator{InitialSegset: segset, Filter: filter, Verbose: true}

	address := fmt.Sprintf("%s:%s", host, negotiationPort)
	stream := dial(address)
	defer stream.Close()
	segset, err := agent.NegotiateOver(stream)
	if err != nil {
		panic(err)
	}

	negotiatedPaths := segset.MatchingPaths(paths)
	log.Println("negotiated", len(negotiatedPaths), "paths in total:")
	return negotiatedPaths
}

func connIAs() (srcIA, dstIA addr.IA) {
	srcIA = (*appnet.DefNetwork()).IA
	dstIA, err := addr.IAFromString(targetIA)
	if err != nil {
		panic(err)
	}
	return
}

func fetchPaths(dstIA addr.IA) []snet.Path {
	paths, err := appnet.QueryPaths(dstIA)
	if err != nil {
		panic(err)
	}
	return paths
}

func buildSegmentSet(paths []snet.Path, srcIA, dstIA addr.IA) segment.SegmentSet {
	segments, err := segment.SplitPaths(paths)
	if err != nil {
		panic(err)
	}
	return segment.SegmentSet{
		Segments: segments,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}
}

func buildFilter() segment.Filter {
	acl := createACL()
	seq := createSequence()
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
	return filter.FromFilters(filters...)
}

func dial(address string) io.ReadWriteCloser {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"scion-ipn-example"},
	}
	switch transport {
	case quicTransport:
		return quicStream(address, tlsConfig)
	case tlsTransport:
		return tlsConn(address, tlsConfig)
	}
	panic("transport is undefined")
}

func quicStream(address string, tlsConfig *tls.Config) quic.Stream {
	session, err := quic.DialAddr(address, tlsConfig, nil)
	if err != nil {
		panic(err)
	}
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}
	return stream
}

func tlsConn(address string, tlsConfig *tls.Config) *tls.Conn {
	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		panic(err)
	}
	return conn
}

func runPingClient(paths []snet.Path) {
	address := fmt.Sprintf("%s:%s", host, pingPort)
	stream := dial(address)
	defer stream.Close()
	_, err := stream.Write([]byte("PING"))
	if err != nil {
		panic(err)
	}
	buffer := make([]byte, 64)
	n, err := stream.Read(buffer)
	if err != nil && err != io.EOF {
		panic(err)
	}
	buffer = buffer[:n]
	fmt.Println("client received:", string(buffer))
}

func createACL() *pathpol.ACL {
	if aclFilepath == "" {
		return nil
	}
	acl := new(pathpol.ACL)
	jsonACL, err := os.ReadFile(aclFilepath)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(jsonACL, &acl)
	if err != nil {
		panic(err)
	}
	return acl
}

func createSequence() *pathpol.Sequence {
	if seqFilepath == "" {
		return nil
	}
	seq := new(pathpol.Sequence)
	jsonSeq, err := os.ReadFile(seqFilepath)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(jsonSeq, &seq)
	if err != nil {
		panic(err)
	}
	return seq
}
