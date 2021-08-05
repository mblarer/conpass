package filter

import "github.com/mblarer/scion-ipn/segment"

// FilterComposition implements the segment.Filter interface.
type FilterComposition struct {
	Filters []segment.Filter
}

func (fc FilterComposition) Filter(segments []segment.Segment) []segment.Segment {
	for _, filter := range fc.Filters {
		segments = filter.Filter(segments)
	}
	return segments
}

func FromFilters(filters ...segment.Filter) segment.Filter {
	return FilterComposition{Filters: filters}
}
