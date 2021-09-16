package filter

import "github.com/mblarer/scion-ipn/segment"

// SrcDstPathEnumerator returns a segment.Filter that enumerates all paths
// between the given source ISD-AS and the destination ISD-AS that can be
// constructed from the given path segments.
func SrcDstPathEnumerator() segment.Filter {
	return pathEnumerator{}
}

type pathEnumerator struct{}

func (_ pathEnumerator) Filter(segset segment.SegmentSet) segment.SegmentSet {
	return segment.SegmentSet{
		Segments: segset.EnumeratePaths(),
		SrcIA:    segset.SrcIA,
		DstIA:    segset.DstIA,
	}
}
