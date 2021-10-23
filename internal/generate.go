package internal

import (
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

// GenerateSegments generates n disjoint segments with a given number of hops
// between a source and destination ISD-AS address pair.
func GenerateSegments(n, hops int, srcIA, dstIA addr.IA) []segment.Segment {
	segments := make([]segment.Segment, n)
	for i := 0; i < n; i++ {
		segments[i] = generateSegment(i, hops, srcIA, dstIA)
	}
	return segments
}

func generateSegment(seed, hops int, srcIA, dstIA addr.IA) segment.Segment {
	interfaces := make([]snet.PathInterface, (hops-1)*2)
	interfaces[0] = snet.PathInterface{ID: common.IFIDType(seed), IA: srcIA}
	for i := 1; i < hops-1; i++ {
		ia := addr.IA{I: srcIA.I, A: srcIA.A + addr.AS(i)}
		id1 := common.IFIDType(i * seed * hops)
		id2 := common.IFIDType(i*seed*hops + 1)
		interfaces[2*i-1] = snet.PathInterface{ID: id1, IA: ia}
		interfaces[2*i] = snet.PathInterface{ID: id2, IA: ia}
	}
	interfaces[(hops-1)*2-1] = snet.PathInterface{ID: common.IFIDType(seed), IA: dstIA}
	return segment.FromInterfaces(interfaces...)
}
