package segment

import (
	"errors"

	proto "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

func DecodeSegments(rawsegs []*proto.Segment) ([]Segment, error) {
	segments := make([]Segment, len(rawsegs))
	for i, rawseg := range rawsegs {
		rawifs := rawseg.GetLiteral()
		segids := rawseg.GetComposition()
		if len(rawifs) > 0 {
			segments[i] = FromInterfaces(DecodeInterfaces(rawifs)...)
		} else {
			subsegs := make([]*Segment, len(segids))
			for j, id := range segids {
				if id >= uint32(i) {
					return nil, errors.New("subsegment id is greater/equal to segment id")
				}
				subsegs[j] = &segments[id]
			}
			segments[i] = FromSegments(subsegs...)
		}
	}
	return segments, nil
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

func EncodeSegments(oldsegs []Segment, newsegs []Segment) []*proto.Segment {
	segindex := make(map[string]int)
	for i, oldseg := range oldsegs {
		segindex[Fingerprint(oldseg)] = i
	}
	rawsegs := make([]*proto.Segment, len(newsegs))
	for i, newseg := range newsegs {
		id := i + len(oldsegs)
		valid := true
		segindex[Fingerprint(newseg)] = id
		switch segment := newseg.(type) {
		case Literal:
			rawsegs[i] = &proto.Segment{
				Id:      uint32(id),
				Valid:   valid,
				Literal: EncodeInterfaces(segment.Interfaces),
			}
		case Composition:
			rawids := make([]uint32, len(segment.Segments))
			for j, subseg := range segment.Segments {
				rawids[j] = uint32(segindex[Fingerprint(*subseg)])
			}
			rawsegs[i] = &proto.Segment{
				Id:          uint32(id),
				Valid:       valid,
				Composition: rawids,
			}
		default:
			panic("unknown segment type")
		}
	}
	return rawsegs
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
