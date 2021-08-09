package segment

import (
	"github.com/scionproto/scion/go/lib/addr"
)

// SrcDstPaths enumerates all possible end-to-end segments between a source and
// destination ISD-AS pair from a given set of segments. For constant-bounded
// segment length, the runtime complexity is linear in the number of
// enumeratable segments starting at the source ISD-AS.
func SrcDstPaths(segments []Segment, srcIA, dstIA addr.IA) []Segment {
	buckets := createSegmentBuckets(segments)
	seglists := recursiveSrcDstSeglists(srcIA, dstIA, buckets)
	flattened := flattenSeglists(seglists)
	return flattened
}

func createSegmentBuckets(segments []Segment) map[string][]Segment {
	buckets := make(map[string][]Segment, len(segments))
	for _, segment := range segments {
		segmentSrcIA := segment.SrcIA()
		buckets[segmentSrcIA.String()] = append(buckets[segmentSrcIA.String()], segment)
	}
	return buckets
}

func recursiveSrcDstSeglists(srcIA, dstIA addr.IA, buckets map[string][]Segment) [][]*Segment {
	if srcIA.String() == dstIA.String() {
		return [][]*Segment{[]*Segment{}}
	}
	srcToDstSeglists := make([][]*Segment, 0)
	for _, srcToMidSegment := range buckets[srcIA.String()] {
		midIA := srcToMidSegment.DstIA()
		midToDstSeglists := recursiveSrcDstSeglists(midIA, dstIA, buckets)
		for _, midToDstSeglist := range midToDstSeglists {
			srcToDstSeglist := append([]*Segment{&srcToMidSegment}, midToDstSeglist...)
			srcToDstSeglists = append(srcToDstSeglists, srcToDstSeglist)
		}
	}
	return srcToDstSeglists
}

func flattenSeglists(seglists [][]*Segment) []Segment {
	segments := make([]Segment, 0)
	for _, seglist := range seglists {
		switch len(seglist) {
		case 0: // Skip if segment list is empty
		case 1:
			segments = append(segments, *seglist[0])
		default:
			segments = append(segments, FromSegments(seglist...))
		}
	}
	return segments
}
