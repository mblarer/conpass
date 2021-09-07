package segment

type Filter interface {
	Filter(SegmentSet) SegmentSet
}
