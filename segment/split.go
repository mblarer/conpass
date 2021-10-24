package segment

import (
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
)

// SplitPaths splits the given paths into up-/core-/down-/peering segments.
// Segments that occur multiple times are only returned once.
func SplitPaths(paths []snet.Path) ([]Segment, error) {
	allsegs := make([]Segment, 0)
	alreadyseen := make(map[string]bool)
	for _, path := range paths {
		currsegs, err := SplitPath(path)
		if err != nil {
			return nil, err
		}
		for _, segment := range currsegs {
			fprint := segment.Fingerprint()
			if !alreadyseen[fprint] {
				allsegs = append(allsegs, segment)
				alreadyseen[fprint] = true
			}
		}
	}
	return allsegs, nil
}

// SplitPath splits the given path into up-/core-/down-/peering segments.
func SplitPath(path snet.Path) ([]Segment, error) {
	decoded := new(scion.Decoded)
	if err := decoded.DecodeFromBytes(path.Path().Raw); err != nil {
		return nil, err
	}
	interfaces := path.Metadata().Interfaces
	seglen := decoded.PathMeta.SegLen
	segments := make([]Segment, 0)
	for i := uint(0); i < 3; i++ {
		if seglen[i] > 0 {
			segments = append(segments, ithSegment(i, interfaces, seglen))
		}
	}
	return segments, nil
}

func ithSegment(i uint, interfaces []snet.PathInterface, seglen [3]uint8) Segment {
	firstIf := uint(0)
	for j := uint(0); j < i; j++ {
		firstIf += numInterfaces(seglen[j])
	}
	lastIfExcl := firstIf + numInterfaces(seglen[i])
	return FromInterfaces(interfaces[firstIf:lastIfExcl]...)
}

func numInterfaces(seglen uint8) uint {
	if seglen == 0 {
		return 0
	}
	return uint(2*seglen - 2)
}
