package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/conpass"
	"github.com/mblarer/conpass/filter"
	"github.com/mblarer/conpass/segment"
	"github.com/scionproto/scion/go/lib/pathpol"
)

const (
	quicTransport bool = false
	tlsTransport  bool = true

	defaultAclFilepath     = ""
	defaultSeqFilepath     = ""
	defaultHost            = "127.0.0.1"
	defaultNegotiationPort = "50000"
	defaultTransport       = quicTransport
	defaultVerbose         = false
)

var (
	aclFilepath     string
	seqFilepath     string
	targetIA        string
	host            string
	negotiationPort string
	transport       bool
	verbose         bool
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatal("server error: ", err)
		}
	}()
	parseArgs()
	runNegotiationServer()
}

func parseArgs() {
	flag.StringVar(&aclFilepath, "acl", defaultAclFilepath,
		"path to ACL definition file (JSON)")
	flag.StringVar(&seqFilepath, "seq", defaultSeqFilepath,
		"path to sequence definition file (JSON)")
	flag.StringVar(&host, "host", defaultHost,
		"IP address to bind to")
	flag.StringVar(&negotiationPort, "port", defaultNegotiationPort,
		"port number to listen on")
	flag.BoolVar(&transport, "tls", defaultTransport,
		"use TLS instead of default QUIC")
	flag.BoolVar(&verbose, "v", defaultVerbose,
		"be verbose and log to stdout")
	flag.Parse()
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

func runNegotiationServer() {
	address := fmt.Sprintf("%s:%s", host, negotiationPort)
	listener := listen(address)
	if verbose {
		log.Printf("server listening at %s", address)
	}
	filter := buildFilter()
	agent := conpass.Responder{Filter: filter, Verbose: verbose}
	for {
		stream := listener.accept()
		go agent.NegotiateOver(stream)
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
		NextProtos:   []string{"conpass-example"},
	}
}
