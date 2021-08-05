package segment

import (
	"errors"

	proto "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

func DecodeSegments(oldsegs []Segment, rawsegs []*proto.Segment) ([]Segment, error) {
	newsegs := make([]Segment, len(rawsegs))
	for i, rawseg := range rawsegs {
		rawifs := rawseg.GetLiteral()
		segids := rawseg.GetComposition()
		if len(rawifs) > 0 {
			newsegs[i] = FromInterfaces(DecodeInterfaces(rawifs)...)
		} else {
			subsegs := make([]*Segment, len(segids))
			for j, id := range segids {
				switch {
				case int(id) < len(oldsegs):
					subsegs[j] = &oldsegs[id]
				case int(id) < len(oldsegs)+len(newsegs):
					subsegs[j] = &newsegs[int(id)-len(oldsegs)]
				default:
					return nil, errors.New("subsegment id is greater/equal to segment id")
				}
			}
			newsegs[i] = FromSegments(subsegs...)
		}
	}
	return newsegs, nil
}

func DecodeInterfaces(rawifs []*proto.Interface) []snet.PathInterface {
	interfaces := make([]snet.PathInterface, len(rawifs))
	for i, rawif := range rawifs {
		interfaces[i] = snet.PathInterface{
			ID: common.IFIDType(rawif.GetId()),
			IA: addr.IAInt(rawif.GetIsdAs()).IA(),
		}
	}
	return interfaces
}

// EncodeSegments encodes a set of new segments for transport with respect to a
// set of old (already seen) segments.
func EncodeSegments(oldsegs []Segment, newsegs []Segment) []*proto.Segment {
	segindex := make(map[string]int)
	for i, oldseg := range oldsegs {
		segindex[Fingerprint(oldseg)] = i
	}
	rawsegs := make([]*proto.Segment, 0)
	// If newsegs contain subsegments that have not been seen before (e.g.
	// because the agent enumerated paths based on new segments), then the
	// subsegments should be included in the newsegs before the actual segment.
	// If newsegs contains subsegments that have the same fingerprint as some
	// old segment, then the newer subsegment should not be included in the new
	// segments because it can be referenced by the old id.
	for _, newseg := range newsegs {
		subsegs := RecursiveSubsegments(newseg)
		for _, subseg := range subsegs {
			fingerprint := Fingerprint(subseg)
			if _, seenbefore := segindex[fingerprint]; !seenbefore {
				id := len(oldsegs) + len(rawsegs)
				valid := false // because it is a subsegment
				segindex[fingerprint] = id
				switch segment := subseg.(type) {
				case Literal:
					rawsegs = append(rawsegs, &proto.Segment{
						Id:      uint32(id),
						Valid:   valid,
						Literal: EncodeInterfaces(segment.Interfaces),
					})
				case Composition:
					rawids := make([]uint32, len(segment.Segments))
					for j, subsubseg := range segment.Segments {
						rawids[j] = uint32(segindex[Fingerprint(*subsubseg)])
					}
					rawsegs = append(rawsegs, &proto.Segment{
						Id:          uint32(id),
						Valid:       valid,
						Composition: rawids,
					})
				default:
					panic("unknown segment type")
				}
			}
		}
	}
	// Now we encode the segments that were actually accepted by the agent.
	for _, newseg := range newsegs {
		id := len(oldsegs) + len(rawsegs)
		valid := true // because it is not a subsegment
		fingerprint := Fingerprint(newseg)
		// If newsegs itself has segments with the same fingerprint as some old
		// segment, then we create a new "composite" segment with a single
		// reference to the old segment.
		if index, seenbefore := segindex[fingerprint]; seenbefore {
			rawsegs = append(rawsegs, &proto.Segment{
				Id:          uint32(id),
				Valid:       valid,
				Composition: []uint32{uint32(index)},
			})
		} else {
			segindex[fingerprint] = id
			switch segment := newseg.(type) {
			case Literal:
				rawsegs = append(rawsegs, &proto.Segment{
					Id:      uint32(id),
					Valid:   valid,
					Literal: EncodeInterfaces(segment.Interfaces),
				})
			case Composition:
				rawids := make([]uint32, len(segment.Segments))
				for j, subseg := range segment.Segments {
					rawids[j] = uint32(segindex[Fingerprint(*subseg)])
				}
				rawsegs = append(rawsegs, &proto.Segment{
					Id:          uint32(id),
					Valid:       valid,
					Composition: rawids,
				})
			default:
				panic("unknown segment type")
			}
		}
	}
	return rawsegs
}

func RecursiveSubsegments(segment Segment) []Segment {
	switch typedseg := segment.(type) {
	case Literal:
		return []Segment{}
	case Composition:
		subsegs := make([]Segment, 0)
		for _, subseg := range typedseg.Segments {
			subsegs = append(subsegs, RecursiveSubsegments(*subseg)...)
			subsegs = append(subsegs, *subseg)
		}
		return subsegs
	default:
		panic("unknown segment type")
	}
	return nil
}

func EncodeInterfaces(interfaces []snet.PathInterface) []*proto.Interface {
	rawifs := make([]*proto.Interface, len(interfaces))
	for i, iface := range interfaces {
		rawifs[i] = &proto.Interface{
			Id:    uint64(iface.ID),
			IsdAs: uint64(iface.IA.IAInt()),
		}
	}
	return rawifs
}
