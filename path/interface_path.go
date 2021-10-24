package path

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

// InterfacePath is a partial implementation of the snet.Path interface as a
// work-around for situations where snet.Path is officially required by
// external code but only the path interfaces are actually needed and accessed
// behind the scenes.
type InterfacePath struct {
	// Interfaces is the sequence of ingress-egress interfaces on the path.
	Interfaces []snet.PathInterface
}

func (ip InterfacePath) Metadata() *snet.PathMetadata {
	return &snet.PathMetadata{Interfaces: ip.Interfaces}
}

func (_ InterfacePath) UnderlayNextHop() *net.UDPAddr { panic("not implemented") }

func (_ InterfacePath) Path() spath.Path { panic("not implemented") }

func (_ InterfacePath) Destination() addr.IA { panic("not implemented") }

func (_ InterfacePath) Copy() snet.Path { panic("not implemented") }
