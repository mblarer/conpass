package segment

import (
	"github.com/scionproto/scion/go/lib/addr"
)

// SrcDstPaths enumerates all possible end-to-end segments between a source and
// destination ISD-AS pair from a given set of segments. For constant-bounded
// segment length, the runtime complexity is linear in the number of
// enumeratable segments starting at the source ISD-AS.
func SrcDstPaths(segments []Segment, srcIA, dstIA addr.IA) []Segment {
	maxSegLen := 3 // SCION-specific
	buckets := createSegmentBuckets(segments)
	seglists := recursiveSrcDstSeglists(maxSegLen, srcIA, dstIA, buckets)
	flattened := flattenSeglists(seglists)
	return flattened
}

func createSegmentBuckets(segments []Segment) map[addr.IA][]Segment {
	buckets := make(map[addr.IA][]Segment, len(segments))
	for _, segment := range segments {
		srcIA, dstIA := segment.SrcIA(), segment.DstIA()
		if srcIA == dstIA { // cyclic
			continue
		}
		buckets[srcIA] = append(buckets[srcIA], segment)
	}
	return buckets
}

func recursiveSrcDstSeglists(maxlen int, srcIA, dstIA addr.IA, buckets map[addr.IA][]Segment) [][]Segment {
	if srcIA == dstIA {
		return [][]Segment{{}} // outer list contains one empty segment list
	} else if maxlen <= 0 {
		return [][]Segment{} // outer list is empty
	}
	srcToDstSeglists := make([][]Segment, 0)
	for _, srcToMidSegment := range buckets[srcIA] {
		midIA := srcToMidSegment.DstIA()
		midToDstSeglists := recursiveSrcDstSeglists(maxlen-1, midIA, dstIA, buckets)
		for _, midToDstSeglist := range midToDstSeglists {
			cyclic := false
			for _, seg := range midToDstSeglist {
				if srcIA == seg.DstIA() {
					cyclic = true
				}
			}
			if !cyclic {
				srcToDstSeglist := append([]Segment{srcToMidSegment}, midToDstSeglist...)
				srcToDstSeglists = append(srcToDstSeglists, srcToDstSeglist)
			}
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
			segments = append(segments, FromSegments(seglist...))
		}
	}
	return segments
}
