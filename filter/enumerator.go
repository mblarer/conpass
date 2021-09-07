package filter

import (
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

// PathEnumerator implements the segment.Filter interface.
type PathEnumerator struct {
	SrcIA, DstIA addr.IA
}

func (pe PathEnumerator) Filter(segset segment.SegmentSet) segment.SegmentSet {
	paths := segment.SrcDstPaths(segset.Segments, pe.SrcIA, pe.DstIA)
	return segment.SegmentSet{Segments: paths}
}

func SrcDstPathEnumerator(srcIA, dstIA addr.IA) segment.Filter {
	return PathEnumerator{SrcIA: srcIA, DstIA: dstIA}
}
