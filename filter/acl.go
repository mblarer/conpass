package filter

import (
	"github.com/mblarer/scion-ipn/path"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

// ACLFilter implements the segment.Filter interface.
type ACLFilter struct {
	ACL pathpol.ACL
}

func (af ACLFilter) Filter(segments []segment.Segment) []segment.Segment {
	return FromPredicate(func(segment segment.Segment) bool {
		// This implementation can be optimized quite a bit. If segment is a
		// segment composition, then every subsegment should only be evaluated
		// once and for all.
		path := path.InterfacePath{segment.PathInterfaces()}
		result := af.ACL.Eval([]snet.Path{path})
		accept := len(result) == 1
		return accept
	}).Filter(segments)
}

func FromACL(acl pathpol.ACL) segment.Filter {
	return ACLFilter{ACL: acl}
}
