package segment

import "github.com/scionproto/scion/go/lib/addr"

type SegmentSet struct {
	Segments []Segment
	SrcIA    addr.IA
	DstIA    addr.IA
}
