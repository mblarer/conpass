package segment

import (
	"github.com/mblarer/conpass/path"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// SegmentSet is a data structure that combines a set of segments with the
// corresponding source and destination ISD-AS addresses.
type SegmentSet struct {
	// Segments is the set of segments in the SegmentSet.
	Segments []Segment
	// SrcIA is the source ISD-AS address of the SegmentSet.
	SrcIA addr.IA
	// DstIA is the destination ISD-AS address of the SegmentSet.
	DstIA addr.IA
}

// MatchingPaths takes a set of SCION paths and returns the paths that are
// constructed from segments in the SegmentSet.
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

// EnumeratePaths enumerates all end-to-end paths from the given SegmentSet.
func (ss SegmentSet) EnumeratePaths() []Segment {
	return SrcDstPaths(ss.Segments, ss.SrcIA, ss.DstIA)
}
