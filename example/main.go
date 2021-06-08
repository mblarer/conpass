package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"

	"github.com/lucas-clemente/quic-go"
	"github.com/mblarer/scion-ipn"
	"github.com/scionproto/scion/go/lib/addr"
)

const address = "localhost:1234"

func main() {
	go func() {
		err := runServer()
		if err != nil {
			log.Fatal(err)
		}
	}()

	err := runClient()
	if err != nil {
		log.Fatal(err)
	}
}

func runServer() error {
	tlsConfig, err := generateTLSConfig()
	if err != nil {
		return err
	}
	listener, err := quic.ListenAddr(address, tlsConfig, nil)
	if err != nil {
		return err
	}
	session, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}
	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		return err
	}
	err = ipn.ServerNegotiatePath(stream)
	if err != nil {
		return err
	}
	return nil
}

func runClient() error {
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
	_, err = ipn.ClientNegotiatePath(stream, addr.IA{})
	return err
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
