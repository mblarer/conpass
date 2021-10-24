package filter

import "github.com/mblarer/conpass/segment"

// FromPredicate returns a segment.Filter that keeps path segments if and only
// if they satisfy a given predicate.
func FromPredicate(accept func(segment.Segment) bool) segment.Filter {
	return predicateFilter{accept: accept}
}

type predicateFilter struct {
	accept func(segment.Segment) bool
}

func (pf predicateFilter) Filter(segset segment.SegmentSet) segment.SegmentSet {
	filtered := make([]segment.Segment, 0)
	for _, segment := range segset.Segments {
		if pf.accept(segment) {
			filtered = append(filtered, segment)
		}
	}
	return segment.SegmentSet{
		Segments: filtered,
		SrcIA:    segset.SrcIA,
		DstIA:    segset.DstIA,
	}
}
