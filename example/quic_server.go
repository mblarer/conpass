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
	"log"
	"math/big"
	"os"

	"github.com/mblarer/scion-ipn"
	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/scion-ipn/filter"
	"github.com/scionproto/scion/go/lib/pathpol"
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
	acl, err := createACL()
	if err != nil {
		return err
	}
	agent := ipn.Responder{Filter: filter.FromACL(*acl)}
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
