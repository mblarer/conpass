package segment

import (
	"github.com/mblarer/scion-ipn/path"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

type Filter interface {
	Filter([]Segment) []Segment
}

type PredicateFilter struct {
	P Predicate
}

func (p PredicateFilter) Filter(segments []Segment) []Segment {
	filtered := make([]Segment, 0)
	for _, segment := range segments {
		if p.P.Accept(segment) {
			filtered = append(filtered, segment)
		}
	}
	return filtered
}

type Predicate interface {
	Accept(Segment) bool
}

type ACLPredicate struct {
	ACL *pathpol.ACL
}

func (ap ACLPredicate) Accept(segment Segment) bool {
	// This implementation can be optimized quite a bit. If segment is a
	// segment composition, then every subsegment should only be evaluated once
	// and for all.
	path := path.InterfacePath{segment.PathInterfaces()}
	result := ap.ACL.Eval([]snet.Path{path})
	return len(result) == 1
}
