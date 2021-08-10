package segment

import (
	"encoding/binary"
	"errors"

	proto "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

func DecodeSegments(rawsegs []*proto.Segment, oldsegs []Segment) ([]Segment, error) {
	newsegs := make([]Segment, len(rawsegs))
	for i, rawseg := range rawsegs {
		rawifs := rawseg.GetLiteral()
		segids := rawseg.GetComposition()
		if len(rawifs) > 0 {
			newsegs[i] = FromInterfaces(DecodeInterfaces(rawifs)...)
		} else {
			subsegs := make([]Segment, len(segids))
			for j, id := range segids {
				switch {
				case int(id) < len(oldsegs):
					subsegs[j] = oldsegs[id]
				case int(id) < len(oldsegs)+len(newsegs):
					subsegs[j] = newsegs[int(id)-len(oldsegs)]
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
		bytes := rawif.GetData()
		id := binary.BigEndian.Uint64(bytes[0:8])
		ia := binary.BigEndian.Uint64(bytes[8:16])
		interfaces[i] = snet.PathInterface{
			ID: common.IFIDType(id),
			IA: addr.IAInt(ia).IA(),
		}
	}
	return interfaces
}

// EncodeSegments encodes a new set of segments for transport.
func EncodeSegments(newsegs, oldsegs []Segment) []*proto.Segment {
	rawsegs := make([]*proto.Segment, len(newsegs))
	for i, newseg := range newsegs {
		rawsegs[i] = &proto.Segment{
			Id:      uint32(len(oldsegs) + i),
			Valid:   true,
			Literal: EncodeInterfaces(newseg.PathInterfaces()),
		}
	}
	return rawsegs
}

func EncodeInterfaces(interfaces []snet.PathInterface) []*proto.Interface {
	rawifs := make([]*proto.Interface, len(interfaces))
	for i, iface := range interfaces {
		bytes := make([]byte, 16)
		binary.BigEndian.PutUint64(bytes[0:8], uint64(iface.ID))
		binary.BigEndian.PutUint64(bytes[8:16], uint64(iface.IA.IAInt()))
		rawifs[i] = &proto.Interface{Data: bytes}
	}
	return rawifs
}
