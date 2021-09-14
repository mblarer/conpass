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
	"os"

	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/scion-ipn"
	"github.com/mblarer/scion-ipn/filter"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/pathpol"
)

const (
	defaultAclFilepath     = ""
	defaultSeqFilepath     = ""
	defaultHost            = "127.0.0.1"
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
	go runPingServer()
	err := runNegotiationServer()
	if err != nil {
		log.Fatal(err)
	}
}

func runNegotiationServer() error {
	address := fmt.Sprintf("%s:%s", host, negotiationPort)
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
	agent := ipn.Responder{
		Filter:  filter.FromFilters(filters...),
		Verbose: true,
	}
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr(address, tlsConfig, nil)
	if err != nil {
		return err
	}
	log.Printf("server listening at %s", address)
	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		_, err = agent.NegotiateOver(stream)
		if err != nil {
			return err
		}
	}
	return nil
}

func runPingServer() {
	address := fmt.Sprintf("%s:%s", host, pingPort)
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		fmt.Println(err)
		return
	}
	listener, err := quic.ListenAddr(address, tlsConfig, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	log.Printf("server listening at %s", address)
	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Println(err)
			return
		}
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			fmt.Println(err)
			return
		}
		buffer := make([]byte, 64)
		n, err := stream.Read(buffer)
		if err != nil && err != io.EOF {
			fmt.Println(err)
			return
		}
		buffer = buffer[:n]
		fmt.Println("server received:", string(buffer))
		_, err = stream.Write([]byte("PONG"))
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func parseArgs() {
	flag.StringVar(&aclFilepath, "acl", defaultAclFilepath, "path to ACL definition file (JSON)")
	flag.StringVar(&seqFilepath, "seq", defaultSeqFilepath, "path to sequence definition file (JSON)")
	flag.StringVar(&host, "host", defaultHost, "IP address to bind to")
	flag.StringVar(&negotiationPort, "port", defaultNegotiationPort, "port number to listen on")
	flag.StringVar(&pingPort, "ping", defaultPingPort, "port number to listen on for ping")
	flag.Parse()
}

func createACL() (*pathpol.ACL, error) {
	acl := new(pathpol.ACL)
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

func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &key.PublicKey, key,
	)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"scion-ipn-example"},
	}, nil
}
