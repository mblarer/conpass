package filter

import "github.com/mblarer/scion-ipn/segment"

// PathEnumerator implements the segment.Filter interface.
type PathEnumerator struct{}

func (_ PathEnumerator) Filter(segset segment.SegmentSet) segment.SegmentSet {
	return segment.SegmentSet{
		Segments: segment.SrcDstPaths(segset.Segments, segset.SrcIA, segset.DstIA),
		SrcIA:    segset.SrcIA,
		DstIA:    segset.DstIA,
	}
}

func SrcDstPathEnumerator() segment.Filter {
	return PathEnumerator{}
}
