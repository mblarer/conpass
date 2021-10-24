package segment

// Filter is the interface that CONPASS agents need to implement in order to
// apply their consent logic. In order to allow for all kinds of consent logic,
// a filter is simply a function from one SegmentSet to another SegmentSet. In
// most cases, the resulting SegmentSet is a subset of the original SegmentSet.
// It is, however, also possible to include new segments in the resulting
// SegmentSet or segments that are combinations of the original segments.
type Filter interface {
	// Filter maps the original to the resulting (accepted) SegmentSet.
	Filter(SegmentSet) SegmentSet
}
