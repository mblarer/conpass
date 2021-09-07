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

func (af ACLFilter) Filter(segset segment.SegmentSet) segment.SegmentSet {
	return FromPredicate(func(segment segment.Segment) bool {
		// This implementation is not optimal. If the segment is a segment
		// composition, then every subsegment should be evaluated only once.
		path := path.InterfacePath{segment.PathInterfaces()}
		result := af.ACL.Eval([]snet.Path{path})
		accept := len(result) == 1
		return accept
	}).Filter(segset)
}

func FromACL(acl pathpol.ACL) segment.Filter {
	return ACLFilter{ACL: acl}
}
