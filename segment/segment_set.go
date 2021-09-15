package segment

import (
	"github.com/mblarer/scion-ipn/path"
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
	accepted := make(map[string]bool)
	for _, spath := range ss.EnumeratePaths() {
		accepted[spath.Fingerprint()] = true
	}
	for _, spath := range paths {
		if accepted[path.Fingerprint(spath)] {
			matching = append(matching, spath)
		}
	}
	return matching
}

func (ss SegmentSet) EnumeratePaths() []Segment {
	return SrcDstPaths(ss.Segments, ss.SrcIA, ss.DstIA)
}
