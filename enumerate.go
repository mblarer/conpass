package ipn

import (
	"github.com/scionproto/scion/go/lib/addr"
)

// AllSrcDst enumerates all possible end-to-end segments between a source and
// destination ISD-AS pair from a given set of segments. For constant-bounded
// segment length, the runtime complexity is linear in the number of
// enumeratable segments starting at the source ISD-AS.
func AllSrcDst(segments []Segment, srcIA, dstIA addr.IA) []Segment {
	buckets := createSegmentBuckets(segments)
	seglists := recursiveSrcDstSeglists(srcIA, dstIA, buckets)
	flattened := flattenSeglists(seglists)
	return flattened
}

func createSegmentBuckets(segments []Segment) map[addr.IA][]Segment {
	buckets := make(map[addr.IA][]Segment, len(segments))
	for _, segment := range segments {
		segmentSrcIA := segment.SrcIA()
		buckets[segmentSrcIA] = append(buckets[segmentSrcIA], segment)
	}
	return buckets
}

func recursiveSrcDstSeglists(srcIA, dstIA addr.IA, buckets map[addr.IA][]Segment) [][]Segment {
	if srcIA == dstIA {
		return [][]Segment{[]Segment{}}
	}
	srcToDstSeglists := make([][]Segment, 0)
	for _, srcToMidSegment := range buckets[srcIA] {
		midIA := srcToMidSegment.DstIA()
		midToDstSeglists := recursiveSrcDstSeglists(midIA, dstIA, buckets)
		for _, midToDstSeglist := range midToDstSeglists {
			srcToDstSeglist := append([]Segment{srcToMidSegment}, midToDstSeglist...)
			srcToDstSeglists = append(srcToDstSeglists, srcToDstSeglist)
		}
	}
	return srcToDstSeglists
}

func flattenSeglists(seglists [][]Segment) []Segment {
	segments := make([]Segment, 0)
	for _, seglist := range seglists {
		switch len(seglist) {
		case 0: // Skip if segment list is empty
		case 1:
			segments = append(segments, seglist[0])
		default:
			// TODO: replace 0 id with real id or refactor code
			segments = append(segments, NewSegmentComposition(0, true, seglist...))
		}
	}
	return segments
}
