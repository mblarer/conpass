package segment

import (
	"fmt"
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
			fprint := Fingerprint(segment)
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
	segments := make([]Segment, 0)
	seglen := decoded.PathMeta.SegLen
	fmt.Println("Segment lengths:", seglen)
	fmt.Println("Number of interfaces:", len(path.Metadata().Interfaces))
	return segments, nil
}
/*
func ithSegment(i uint, interfaces []snet.PathInterface, seglen [3]uint8) Segment {
	
}
*/

