package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/scion-ipn"
	"github.com/mblarer/scion-ipn/filter"
	"github.com/mblarer/scion-ipn/internal"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

type doublepipe struct {
	io.Reader
	io.Writer
}

const (
	host = "127.0.0.1"
	port = "50000"

	quicTransport bool = false
	tlsTransport  bool = true
	transport     bool = quicTransport
)

func main() {
	p, k, hops, enum, prof := argsOrExit()

	srcIA, _ := addr.IAFromString("1-ffaa:0:1")
	core1, _ := addr.IAFromString("1-ffaa:0:1000")
	core2, _ := addr.IAFromString("2-ffaa:0:1")
	dstIA, _ := addr.IAFromString("2-ffaa:0:1000")
	segments := make([]segment.Segment, 0)
	segments = append(segments, internal.CreateSegments(k, hops, srcIA, core1)...)
	segments = append(segments, internal.CreateSegments(k, hops, core1, core2)...)
	segments = append(segments, internal.CreateSegments(k, hops, core2, dstIA)...)
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}

	var cfilter, sfilter segment.Filter
	switch enum {
	case "n":
		cfilter = filter.FromFilters()
		sfilter = filter.FromFilters()
	case "c":
		cfilter = filter.SrcDstPathEnumerator()
		sfilter = filter.FromFilters()
	case "s":
		cfilter = filter.FromFilters()
		sfilter = filter.SrcDstPathEnumerator()
	}

	server := conpass.Responder{Filter: sfilter}
	go runServer(server, p)

	address := fmt.Sprintf("%s:%s", host, port)
	channel := make(chan string)
	// Create p worker threads
	for i := 0; i < p; i++ {
		go func() {
			client := conpass.Initiator{InitialSegset: segset, Filter: cfilter}
			bytes := prepareBytes(client)
			for {
				address := <-channel
				stream := dial(address)
				stream.Write(bytes)
				lenbuf := make([]byte, 4)
				stream.Read(lenbuf)
				msglen := int64(binary.BigEndian.Uint32(lenbuf))
				io.Copy(io.Discard, io.LimitReader(stream, msglen))
				stream.Close()
			}
		}()
	}

	N := 2000
	start := time.Now()
	for i := 0; i < N; i++ {
		channel <- address
	}

	if prof {
		f, _ := os.Create("mem.prof")
		defer f.Close()
		runtime.GC()
		pprof.WriteHeapProfile(f)
	}

	fmt.Print(int64(N) * 1_000_000_000 / int64(time.Since(start)))
}

func prepareBytes(agent conpass.Initiator) []byte {
	newsegset := agent.Filter.Filter(agent.InitialSegset)
	oldsegs := []segment.Segment{}
	bytes, _ := segment.EncodeSegments(newsegset.Segments, oldsegs, newsegset.SrcIA, newsegset.DstIA)
	lenbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbuf, uint32(len(bytes)))
	return append(lenbuf, bytes...)

}

func argsOrExit() (int, int, int, string, bool) {
	if len(os.Args) != 6 {
		usageAndExit()
	}
	p, err := strconv.Atoi(os.Args[1])
	if err != nil {
		usageAndExit()
	}
	k, err := strconv.Atoi(os.Args[2])
	if err != nil {
		usageAndExit()
	}
	hops, err := strconv.Atoi(os.Args[3])
	if err != nil {
		usageAndExit()
	}
	enum := os.Args[4]
	if enum != "n" && enum != "c" && enum != "s" {
		usageAndExit()
	}
	prof := os.Args[5]
	if prof != "y" && prof != "n" {
		usageAndExit()
	}
	return p, k, hops, enum, prof == "y"
}

func usageAndExit() {
	fmt.Println("wrong command line arguments:", os.Args[0], "p:<int> k:<int> hops:<int> enum:n|c|s prof:y|n")
	os.Exit(1)
}

func runServer(agent conpass.Responder, p int) {
	address := fmt.Sprintf("%s:%s", host, port)
	listener := listen(address)
	streams := make(chan io.ReadWriteCloser, p)
	// Create p worker threads
	for i := 0; i < p; i++ {
		go func(responder conpass.Responder) {
			for {
				stream := <-streams
				responder.NegotiateOver(stream)
				stream.Close()
			}
		}(agent)
	}
	for {
		streams <- listener.accept()
	}
}

type transportListener struct {
	quicListener quic.Listener
	tlsListener  net.Listener
}

func (tl transportListener) accept() io.ReadWriteCloser {
	switch transport {
	case quicTransport:
		return quicAccept(tl.quicListener)
	case tlsTransport:
		return tlsAccept(tl.tlsListener)
	}
	panic("transport is undefined")
}

func quicAccept(listener quic.Listener) quic.Stream {
	session, err := listener.Accept(context.Background())
	if err != nil {
		panic(err)
	}
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	return stream
}

func tlsAccept(listener net.Listener) net.Conn {
	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	return conn
}

func listen(address string) transportListener {
	tlsConfig := generateTLSConfig()
	switch transport {
	case quicTransport:
		return transportListener{quicListener: quicListener(address, tlsConfig)}
	case tlsTransport:
		return transportListener{tlsListener: tlsListener(address, tlsConfig)}
	}
	panic("transport is undefined")
}

func quicListener(address string, tlsConfig *tls.Config) quic.Listener {
	listener, err := quic.ListenAddr(address, tlsConfig, nil)
	if err != nil {
		panic(err)
	}
	return listener
}

func tlsListener(address string, tlsConfig *tls.Config) net.Listener {
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		panic(err)
	}
	return listener
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &key.PublicKey, key,
	)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"scion-ipn-example"},
	}
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
