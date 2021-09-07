package filter

import (
	"github.com/mblarer/scion-ipn/path"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

// SequenceFilter implements the segment.Filter interface.
type SequenceFilter struct {
	Sequence pathpol.Sequence
}

func (sf SequenceFilter) Filter(segset segment.SegmentSet) segment.SegmentSet {
	return FromPredicate(func(segment segment.Segment) bool {
		path := path.InterfacePath{segment.PathInterfaces()}
		result := sf.Sequence.Eval([]snet.Path{path})
		accept := len(result) == 1
		return accept
	}).Filter(segset)
}

func FromSequence(sequence pathpol.Sequence) segment.Filter {
	return SequenceFilter{Sequence: sequence}
}
