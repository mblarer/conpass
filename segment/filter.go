package segment

type Filter interface {
	Filter([]Segment) []Segment
}
