package filter

import (
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

// PathEnumerator implements the segment.Filter interface.
type PathEnumerator struct {
	SrcIA, DstIA addr.IA
}

func (pe PathEnumerator) Filter(segments []segment.Segment) []segment.Segment {
	return segment.SrcDstPaths(segments, pe.SrcIA, pe.DstIA)
}

func SrcDstPathEnumerator(srcIA, dstIA addr.IA) segment.Filter {
	return PathEnumerator{SrcIA: srcIA, DstIA: dstIA}
}
