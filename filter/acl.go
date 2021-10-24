package filter

import (
	"github.com/mblarer/conpass/path"
	"github.com/mblarer/conpass/segment"
	"github.com/scionproto/scion/go/lib/pathpol"
	"github.com/scionproto/scion/go/lib/snet"
)

// FromACL returns a segment.Filter that filters path segments according to a
// pathpol.ACL policy.
func FromACL(acl pathpol.ACL) segment.Filter {
	return aclFilter{acl: acl}
}

type aclFilter struct {
	acl pathpol.ACL
}

func (af aclFilter) Filter(segset segment.SegmentSet) segment.SegmentSet {
	return FromPredicate(func(segment segment.Segment) bool {
		// This implementation is not optimal. If the segment is a segment
		// composition, then every subsegment should be evaluated only once.
		path := path.InterfacePath{segment.PathInterfaces()}
		result := af.acl.Eval([]snet.Path{path})
		accept := len(result) == 1
		return accept
	}).Filter(segset)
}
