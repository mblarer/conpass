package segment

import (
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// FromSegments creates a new Segment from a sequence of pointers to segments.
// The segments slice is copied to prevent problems with shared slices.
func FromSegments(segments ...Segment) Segment {
	var sb strings.Builder
	for _, segment := range segments {
		sb.WriteString(segment.Fingerprint())
	}
	return Composition{
		Segments:    append([]Segment(nil), segments...),
		fingerprint: sb.String(),
	}
}

// Composition implements the Segment interface.
type Composition struct {
	Segments    []Segment
	fingerprint string
}

func (c Composition) PathInterfaces() []snet.PathInterface {
	interfaces := make([]snet.PathInterface, 0)
	for _, segment := range c.Segments {
		interfaces = append(interfaces, segment.PathInterfaces()...)
	}
	return interfaces
}

func (c Composition) SrcIA() addr.IA {
	return c.Segments[0].SrcIA()
}

func (c Composition) DstIA() addr.IA {
	return c.Segments[len(c.Segments)-1].DstIA()
}

func (c Composition) Fingerprint() string {
	return c.fingerprint
}

func (c Composition) String() string {
	str := "["
	for i, segment := range c.Segments {
		str += "("
		str += segment.String()
		str += ")"
		if i == len(c.Segments)-1 {
			break
		}
		str += ", "
	}
	str += "]"
	return str
}
