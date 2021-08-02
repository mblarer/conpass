package ipn

import (
	"net"

	addr "github.com/scionproto/scion/go/lib/addr"
	pathpol "github.com/scionproto/scion/go/lib/pathpol"
	snet "github.com/scionproto/scion/go/lib/snet"
	spath "github.com/scionproto/scion/go/lib/spath"
)

type Filter interface {
	Filter([]Segment) []Segment
}

type PredicateFilter struct {
	P Predicate
}

func (p PredicateFilter) Filter(unfiltered []Segment) []Segment {
	filtered := make([]Segment, 0, len(unfiltered))
	for _, segment := range unfiltered {
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
	iflist := interfaceList{interfaces: segment.Interfaces()}
	paths := append(make([]snet.Path, 0), iflist)
	result := ap.ACL.Eval(paths)
	return len(result) == 1
}

type interfaceList struct {
	interfaces []snet.PathInterface
}

func (iflist interfaceList) Metadata() *snet.PathMetadata {
	return &snet.PathMetadata{Interfaces: iflist.interfaces}
}

func (_ interfaceList) UnderlayNextHop() *net.UDPAddr { return nil }
func (_ interfaceList) Path() spath.Path              { return spath.Path{} }
func (_ interfaceList) Destination() addr.IA          { return addr.IA{} }
func (_ interfaceList) Copy() snet.Path               { return nil }
