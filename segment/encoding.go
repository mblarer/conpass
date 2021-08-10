package segment

import (
	"encoding/binary"
	"errors"

	proto "github.com/mblarer/scion-ipn/proto/negotiation"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	SegTypeLiteral     uint8 = 0 << 0
	SegTypeComposition uint8 = 1 << 0
	SegTypeMask        uint8 = 1 << 0

	SegAcceptedFalse uint8 = 0 << 1
	SegAcceptedTrue  uint8 = 1 << 1
	SegAcceptedMask  uint8 = 1 << 1
)

func DecodeSegments(rawsegs []*proto.Segment, oldsegs []Segment) ([]Segment, error) {
	newsegs := make([]Segment, len(rawsegs))
	for i, rawseg := range rawsegs {
		bytes := rawseg.GetData()
		flags := bytes[0]
		segtype := flags & SegTypeMask
		//accepted := SegAcceptedTrue == (flags & SegAcceptedMask)
		seglen := int(bytes[1])
		//optlen := binary.BigEndian.Uint16(bytes[2:])

		switch segtype {
		case SegTypeLiteral:
			newsegs[i] = FromInterfaces(DecodeInterfaces(bytes[4:], seglen)...)
		case SegTypeComposition:
			subsegs := make([]Segment, seglen)
			for j := 0; j < seglen; j++ {
				id := binary.BigEndian.Uint16(bytes[4+j*2:])
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

func DecodeInterfaces(bytes []byte, seglen int) []snet.PathInterface {
	interfaces := make([]snet.PathInterface, seglen)
	for i := 0; i < seglen; i++ {
		id := binary.BigEndian.Uint64(bytes[i*16:])
		ia := binary.BigEndian.Uint64(bytes[i*16+8:])
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
		interfaces := newseg.PathInterfaces()
		flags := SegTypeLiteral | SegAcceptedTrue
		seglen := len(interfaces)
		optlen := 0

		bytes := make([]byte, 4+seglen*16+optlen)
		bytes[0] = flags
		bytes[1] = uint8(seglen)
		binary.BigEndian.PutUint16(bytes[2:], uint16(optlen))
		EncodeInterfaces(bytes[4:], interfaces)
		
		rawsegs[i] = &proto.Segment{Data: bytes}
	}
	return rawsegs
}

func EncodeInterfaces(bytes []byte, interfaces []snet.PathInterface) {
	for i, iface := range interfaces {
		binary.BigEndian.PutUint64(bytes[i*16:], uint64(iface.ID))
		binary.BigEndian.PutUint64(bytes[i*16+8:], uint64(iface.IA.IAInt()))
	}
}
