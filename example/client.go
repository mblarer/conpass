package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/pprof"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/scion-ipn"
	"github.com/mblarer/scion-ipn/filter"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/netsec-ethz/scion-apps/pkg/appnet"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/pkg/ping"
)

const (
	quicTransport bool = false
	tlsTransport  bool = true

	defaultAclFilepath     = ""
	defaultHost            = "127.0.0.1"
	defaultNegotiationPort = "50000"
	defaultProfileFilepath = ""
	defaultSeqFilepath     = ""
	defaultShouldNegotiate = true
	defaultTargetIA        = "17-ffaa:0:1102" // ETHZ
	defaultTransport       = quicTransport
	defaultVerbose         = false
)

var (
	aclFilepath     string
	host            string
	negotiationPort string
	profileFilepath string
	seqFilepath     string
	shouldNegotiate bool
	targetIA        string
	transport       bool
	verbose         bool

	profileFile *os.File
	startTime   time.Time
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatal("client error: ", err)
		}
	}()
	parseArgs()
	startMeasurements()
	srcIA, dstIA := connIAs()
	paths := fetchPaths(dstIA)
	if shouldNegotiate {
		paths = negotiate(paths, srcIA, dstIA)
	}
	if len(paths) > 0 {
		pingOnPath(paths[0], srcIA, dstIA)
	} else if verbose {
		log.Println("there are no paths available for pinging")
	}
	stopMeasurements()
}

func startMeasurements() {
	if profileFilepath != "" {
		profileFile, err := os.Create(profileFilepath)
		if err != nil {
			panic(err)
		}
		err = pprof.StartCPUProfile(profileFile)
		if err != nil {
			panic(err)
		}
	}
	startTime = time.Now()
}

func stopMeasurements() {
	fmt.Println(int64(time.Since(startTime)))
	if profileFilepath != "" {
		pprof.StopCPUProfile()
		profileFile.Close()
	}
}

func parseArgs() {
	flag.StringVar(&aclFilepath, "acl", defaultAclFilepath,
		"path to ACL definition file (JSON)")
	flag.StringVar(&host, "host", defaultHost,
		"IP address of the negotiation server")
	flag.StringVar(&negotiationPort, "port", defaultNegotiationPort,
		"port number of the negotiation server")
	flag.StringVar(&profileFilepath, "prof", defaultProfileFilepath,
		"output file for profiling (default: none)")
	flag.StringVar(&seqFilepath, "seq", defaultSeqFilepath,
		"path to sequence definition file (JSON)")
	flag.BoolVar(&shouldNegotiate, "neg", defaultShouldNegotiate,
		"whether client should negotiate")
	flag.StringVar(&targetIA, "ia", defaultTargetIA,
		"ISD-AS of the target host")
	flag.BoolVar(&transport, "tls", defaultTransport,
		"use TLS instead of default QUIC")
	flag.BoolVar(&verbose, "v", defaultVerbose,
		"be verbose and log to stdout")
	flag.Parse()
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
	if verbose {
		log.Println("queried", len(paths), "different paths to", dstIA)
	}
	return paths
}

func negotiate(paths []snet.Path, srcIA, dstIA addr.IA) []snet.Path {
	segset := buildSegmentSet(paths, srcIA, dstIA)
	if verbose {
		log.Println("split paths into", len(segset.Segments), "different segments")
	}
	filter := buildFilter()
	agent := ipn.Initiator{InitialSegset: segset, Filter: filter, Verbose: verbose}

	address := fmt.Sprintf("%s:%s", host, negotiationPort)
	stream := dial(address)
	defer stream.Close()
	segset, err := agent.NegotiateOver(stream)
	if err != nil {
		panic(err)
	}

	negotiatedPaths := segset.MatchingPaths(paths)
	if verbose {
		log.Println("negotiated", len(negotiatedPaths), "paths in total")
	}
	return negotiatedPaths
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

func pingOnPath(path snet.Path, srcIA, dstIA addr.IA) {
	localhost := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	ping.Run(context.Background(), ping.Config{
		Dispatcher: reliable.NewDispatcher(reliable.DefaultDispPath),
		Local:      &snet.UDPAddr{IA: srcIA, Host: localhost},
		Remote:     &snet.UDPAddr{IA: dstIA, Host: localhost, Path: path.Path(), NextHop: path.UnderlayNextHop()},
		Attempts:   1,
		Interval:   1 * time.Second,
		Timeout:    150 * time.Millisecond,
	})
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
