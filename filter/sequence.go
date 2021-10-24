package filter

import (
	"github.com/mblarer/conpass/path"
	"github.com/mblarer/conpass/segment"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

// FromSequence returns a segment.Filter that filters path segments according
// to a given pathpol.Sequence policy.
func FromSequence(sequence pathpol.Sequence) segment.Filter {
	return sequenceFilter{sequence: sequence}
}

type sequenceFilter struct {
	sequence pathpol.Sequence
}

func (sf sequenceFilter) Filter(segset segment.SegmentSet) segment.SegmentSet {
	return FromPredicate(func(segment segment.Segment) bool {
		path := path.InterfacePath{segment.PathInterfaces()}
		result := sf.sequence.Eval([]snet.Path{path})
		accept := len(result) == 1
		return accept
	}).Filter(segset)
}
