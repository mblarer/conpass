package segment

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// FromSegments creates a new Segment from a sequence of pointers to segments.
// The pointers slice is copied to prevent problems with shared slices.
func FromSegments(segments ...*Segment) Segment {
	return Composition{append([]*Segment(nil), segments...)}
}

// Composition implements the Segment interface.
type Composition struct {
	Segments []*Segment
}

func (c Composition) PathInterfaces() []snet.PathInterface {
	interfaces := make([]snet.PathInterface, 0)
	for _, segment := range c.Segments {
		interfaces = append(interfaces, (*segment).PathInterfaces()...)
	}
	return interfaces
}

func (c Composition) SrcIA() addr.IA {
	return (*c.Segments[0]).SrcIA()
}

func (c Composition) DstIA() addr.IA {
	return (*c.Segments[len(c.Segments)-1]).DstIA()
}
