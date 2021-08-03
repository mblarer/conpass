package segment

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// FromInterfaces creates a new Segment from a sequence of interfaces. The
// interface slice is copied to prevent problems with shared slices.
func FromInterfaces(interfaces ...snet.PathInterface) Segment {
	return Literal{append([]snet.PathInterface(nil), interfaces...)}
}

// Literal implements the Segment interface.
type Literal struct {
	Interfaces []snet.PathInterface
}

func (l Literal) PathInterfaces() []snet.PathInterface {
	return append([]snet.PathInterface(nil), l.Interfaces...)
}

func (l Literal) SrcIA() addr.IA {
	return l.Interfaces[0].IA
}

func (l Literal) DstIA() addr.IA {
	return l.Interfaces[len(l.Interfaces)-1].IA
}
