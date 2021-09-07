package filter

import "github.com/mblarer/scion-ipn/segment"

// PredicateFilter is an implementation of the segment.Filter interface.
type PredicateFilter struct {
	Accept func(segment.Segment) bool
}

func (pf PredicateFilter) Filter(segset segment.SegmentSet) segment.SegmentSet {
	filtered := make([]segment.Segment, 0)
	for _, segment := range segset.Segments {
		if pf.Accept(segment) {
			filtered = append(filtered, segment)
		}
	}
	return segment.SegmentSet{Segments: filtered}
}

func FromPredicate(accept func(segment.Segment) bool) segment.Filter {
	return PredicateFilter{Accept: accept}
}
