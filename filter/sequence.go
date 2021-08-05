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

func (sf SequenceFilter) Filter(segments []segment.Segment) []segment.Segment {
	return FromPredicate(func(segment segment.Segment) bool {
		// This implementation can be optimized quite a bit. If segment is a
		// segment composition, then every subsegment should only be evaluated
		// once and for all.
		path := path.InterfacePath{segment.PathInterfaces()}
		result := sf.Sequence.Eval([]snet.Path{path})
		accept := len(result) == 1
		return accept
	}).Filter(segments)
}

func FromSequence(sequence pathpol.Sequence) segment.Filter {
	return SequenceFilter{Sequence: sequence}
}
