package ipn

import (
	"encoding/gob"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

func ClientNegotiatePath(stream quic.Stream, target addr.IA) (snet.Path, error) {
	availablePaths, err := queryAvailablePaths(target)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(availablePaths); i++ {
		path := availablePaths[i]
		if !clientIsAcceptable(path) {
			continue
		}
		err := sendOffer(stream, path)
		if err != nil {
			return nil, err
		}
		accept, err := recvAnswer(stream)
		if err != nil {
			return nil, err
		}
		if accept {
			return path, nil
		}
	}
	return nil, errors.New("No common path found.")
}

func ServerNegotiatePath(stream quic.Stream) error {
	for {
		path, err := recvOffer(stream)
		if err != nil {
			return err
		}
		accept := serverIsAcceptable(path)
		err = sendAnswer(stream, accept)
		if err != nil {
			return err
		}
		if accept {
			break
		}
	}
	return nil
}

func queryAvailablePaths(target addr.IA) ([]snet.Path, error) {
	numPaths := rand.Intn(100)
	paths := make([]snet.Path, numPaths)
	for i := 0; i < numPaths; i++ {
		paths[i] = randomPath(target)
	}
	return paths, nil
}

func clientIsAcceptable(_ snet.Path) bool {
	r := rand.Intn(5)
	return r == 0
}

func serverIsAcceptable(_ snet.Path) bool {
	r := rand.Intn(5)
	return r == 0
}

type testPath struct {
	metadata *snet.PathMetadata
}

func (_ *testPath) UnderlayNextHop() *net.UDPAddr {
	panic("Not implemented.")
}

func (_ *testPath) Path() spath.Path {
	panic("Not implemented.")
}

func (_ *testPath) Destination() addr.IA {
	panic("Not implemented.")
}

func (p *testPath) Metadata() *snet.PathMetadata {
	return p.metadata
}

func (p *testPath) Copy() snet.Path {
	panic("Not implemented.")
}

func randomPath(_ addr.IA) snet.Path {
	return &testPath{metadata: randomMetadata()}
}

func randomMetadata() *snet.PathMetadata {
	numHops := 2 + rand.Intn(63) // between 2 and 64 (inclusive)
	numInterDomainLinks := numHops - 1
	numIntraDomainLinks := numHops - 2
	numLinks := numInterDomainLinks + numIntraDomainLinks
	numInterfaces := numLinks + 1
	return &snet.PathMetadata{
		Interfaces:   randomInterfaces(numInterfaces),
		MTU:          uint16(1000 + rand.Intn(500)),
		Expiry:       time.Now().Add(time.Duration(rand.Int63())),
		Latency:      randomLatencies(numLinks),
		Bandwidth:    randomBandwidths(numLinks),
		Geo:          randomCoordinates(numInterfaces),
		LinkType:     randomLinkTypes(numInterDomainLinks),
		InternalHops: randomInternalHops(numIntraDomainLinks),
	}
}

func randomInterfaces(num int) []snet.PathInterface {
	interfaces := make([]snet.PathInterface, num)
	for i := 0; i < num; i++ {
		interfaces[i] = snet.PathInterface{
			ID: common.IFIDType(rand.Uint64()),
			IA: addr.IA{I: addr.ISD(rand.Intn(2 << 16)), A: addr.AS(rand.Uint64())},
		}
	}
	return interfaces
}

func randomLatencies(num int) []time.Duration {
	latencies := make([]time.Duration, num)
	for i := 0; i < num; i++ {
		latencies[i] = time.Duration(rand.Int63())
	}
	return latencies
}

func randomBandwidths(num int) []uint64 {
	bandwidths := make([]uint64, num)
	for i := 0; i < num; i++ {
		bandwidths[i] = rand.Uint64()
	}
	return bandwidths
}

func randomCoordinates(num int) []snet.GeoCoordinates {
	coordinates := make([]snet.GeoCoordinates, num)
	for i := 0; i < num; i++ {
		coordinates[i] = snet.GeoCoordinates{
			Latitude:  rand.Float32(),
			Longitude: rand.Float32(),
		}
	}
	return coordinates
}

func randomLinkTypes(num int) []snet.LinkType {
	linkTypes := make([]snet.LinkType, num)
	for i := 0; i < num; i++ {
		linkTypes[i] = snet.LinkType(rand.Intn(4))
	}
	return linkTypes
}

func randomInternalHops(num int) []uint32 {
	hops := make([]uint32, num)
	for i := 0; i < num; i++ {
		hops[i] = rand.Uint32()
	}
	return hops
}

func sendOffer(stream quic.Stream, path snet.Path) error {
	log.Printf("Client: Sending path '%s'\n", path)
	enc := gob.NewEncoder(stream)
	err := enc.Encode(path.Metadata())
	return err
}

func recvOffer(stream quic.Stream) (snet.Path, error) {
	var metadata snet.PathMetadata
	dec := gob.NewDecoder(stream)
	err := dec.Decode(&metadata)
	if err != nil {
		return nil, err
	}
	path := &testPath{metadata: &metadata}
	log.Printf("Server: Got '%s'\n", path)
	return path, nil
}

func sendAnswer(stream quic.Stream, accept bool) error {
	log.Printf("Server: Sending '%t'\n", accept)
	b2i := map[bool]byte{false: 0, true: 1}
	_, err := stream.Write([]byte{b2i[accept]})
	return err
}

func recvAnswer(stream quic.Stream) (bool, error) {
	buffer := make([]byte, 1)
	_, err := io.ReadFull(stream, buffer)
	if err != nil {
		return false, err
	}
	accept := buffer[0] == 1
	log.Printf("Client: Got '%t'\n", accept)
	return accept, err
}
