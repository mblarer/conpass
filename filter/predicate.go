package filter

import "github.com/mblarer/scion-ipn/segment"

// PredicateFilter is an implementation of the segment.Filter interface.
type PredicateFilter struct {
	Accept func(segment.Segment) bool
}

func (pf PredicateFilter) Filter(segments []segment.Segment) []segment.Segment {
	filtered := make([]segment.Segment, 0)
	for _, segment := range segments {
		if pf.Accept(segment) {
			filtered = append(filtered, segment)
		}
	}
	return filtered
}

func FromPredicate(accept func(segment.Segment) bool) segment.Filter {
	return PredicateFilter{Accept: accept}
}
