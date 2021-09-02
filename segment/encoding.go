package segment

import (
	"encoding/binary"
	"errors"

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

func DecodeSegments(bytes []byte, oldsegs []Segment) ([]Segment, addr.IA, addr.IA, error) {
	hdrlen := int(bytes[1])
	numsegs := int(binary.BigEndian.Uint16(bytes[2:]))
	srcIA := addr.IAInt(binary.BigEndian.Uint64(bytes[4:])).IA()
	dstIA := addr.IAInt(binary.BigEndian.Uint64(bytes[12:])).IA()
	newsegs := make([]Segment, numsegs)
	bytes = bytes[hdrlen:]
	for i := 0; i < numsegs; i++ {
		flags := bytes[0]
		segtype := flags & SegTypeMask
		//accepted := SegAcceptedTrue == (flags & SegAcceptedMask)
		seglen := int(bytes[1])
		optlen := int(binary.BigEndian.Uint16(bytes[2:]))

		switch segtype {
		case SegTypeLiteral:
			newsegs[i] = FromInterfaces(DecodeInterfaces(bytes[4:], seglen)...)
			bytes = bytes[4 + seglen * 16 + optlen:]
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
					err := errors.New("subsegment id is greater/equal to segment id")
					return nil, srcIA, dstIA, err
				}
			}
			newsegs[i] = FromSegments(subsegs...)
			bytes = bytes[4 + seglen * 2 + optlen:]
		}
	}
	return newsegs, srcIA, dstIA, nil
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
func EncodeSegments(newsegs, oldsegs []Segment, srcIA, dstIA addr.IA) []byte {
	hdrlen := 20
	allbytes := make([]byte, hdrlen)
	numsegs := uint16(len(newsegs))
	allbytes[1] = uint8(hdrlen)
	binary.BigEndian.PutUint16(allbytes[2:], numsegs)
	binary.BigEndian.PutUint64(allbytes[4:], uint64(srcIA.IAInt()))
	binary.BigEndian.PutUint64(allbytes[12:], uint64(dstIA.IAInt()))
	for _, newseg := range newsegs {
		interfaces := newseg.PathInterfaces()
		flags := SegTypeLiteral | SegAcceptedTrue
		seglen := len(interfaces)
		optlen := 0

		bytes := make([]byte, 4+seglen*16+optlen)
		bytes[0] = flags
		bytes[1] = uint8(seglen)
		binary.BigEndian.PutUint16(bytes[2:], uint16(optlen))
		EncodeInterfaces(bytes[4:], interfaces)

		allbytes = append(allbytes, bytes...)
	}
	return allbytes
}

func EncodeInterfaces(bytes []byte, interfaces []snet.PathInterface) {
	for i, iface := range interfaces {
		binary.BigEndian.PutUint64(bytes[i*16:], uint64(iface.ID))
		binary.BigEndian.PutUint64(bytes[i*16+8:], uint64(iface.IA.IAInt()))
	}
}
