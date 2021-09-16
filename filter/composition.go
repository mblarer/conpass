package filter

import "github.com/mblarer/scion-ipn/segment"

// FromFilters returns a segment.Filter that applies a sequence of
// caller-supplied filters, in the given order.
func FromFilters(filters ...segment.Filter) segment.Filter {
	return filterComposition{filters: filters}
}

type filterComposition struct {
	filters []segment.Filter
}

func (fc filterComposition) Filter(segset segment.SegmentSet) segment.SegmentSet {
	for _, filter := range fc.filters {
		segset = filter.Filter(segset)
	}
	return segset
}
