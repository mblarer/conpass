package segment

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

type SegmentSet struct {
	Segments []Segment
	SrcIA    addr.IA
	DstIA    addr.IA
}

func (ss SegmentSet) MatchingPaths(paths []snet.Path) []snet.Path {
	matching := make([]snet.Path, 0)
	srcDstPaths := SrcDstPaths(ss.Segments, ss.SrcIA, ss.DstIA)
	accepted := make(map[string]bool)
	for _, sdpath := range srcDstPaths {
		accepted[Hash(sdpath)] = true
	}
	for _, path := range paths {
		if accepted[string(snet.Fingerprint(path))] {
			matching = append(matching, path)
		}
	}
	return matching
}
