package filter

import "github.com/mblarer/scion-ipn/segment"

// FilterComposition implements the segment.Filter interface.
type FilterComposition struct {
	Filters []segment.Filter
}

func (fc FilterComposition) Filter(segset segment.SegmentSet) segment.SegmentSet {
	for _, filter := range fc.Filters {
		segset = filter.Filter(segset)
	}
	return segset
}

func FromFilters(filters ...segment.Filter) segment.Filter {
	return FilterComposition{Filters: filters}
}
