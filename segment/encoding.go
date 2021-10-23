package segment

import (
	"encoding/binary"
	"errors"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	// The segment type is encoded as the least significant bit.
	segTypeMask        uint8 = 1 << 0
	segTypeLiteral     uint8 = 0 << 0
	segTypeComposition uint8 = 1 << 0
	// The consent of a segment is the second least significant bit.
	segAcceptedMask  uint8 = 1 << 1
	segAcceptedFalse uint8 = 0 << 1
	segAcceptedTrue  uint8 = 1 << 1
)

// DecodeSegments decodes the bytes received from the other CONPASS agent into
// segments. This function also takes into account the ``old'' set of segments,
// which is already known to both agents.  The first set of segments contains
// all segments that were transmitted, the second set contains only the
// accepted segments. This function also returns the source and destination
// ASes. If the decoding failed, an error is returned instead.
func DecodeSegments(bytes []byte, oldsegs []Segment) ([]Segment, []Segment, addr.IA, addr.IA, error) {
	hdrlen := int(bytes[1])
	numsegs := int(binary.BigEndian.Uint16(bytes[2:]))
	srcIA := addr.IAInt(binary.BigEndian.Uint64(bytes[4:])).IA()
	dstIA := addr.IAInt(binary.BigEndian.Uint64(bytes[12:])).IA()
	newsegs := make([]Segment, numsegs)
	accsegs := make([]Segment, 0)
	bytes = bytes[hdrlen:]
	for i := 0; i < numsegs; i++ {
		flags := bytes[0]
		segtype := flags & segTypeMask
		accepted := segAcceptedTrue == (flags & segAcceptedMask)
		seglen := int(bytes[1])
		optlen := int(binary.BigEndian.Uint16(bytes[2:]))

		switch segtype {
		case segTypeLiteral:
			newsegs[i] = FromInterfaces(decodeInterfaces(bytes[4:], seglen)...)
			bytes = bytes[4+seglen*16+optlen:]
		case segTypeComposition:
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
					return nil, nil, srcIA, dstIA, err
				}
			}
			newsegs[i] = FromSegments(subsegs...)
			bytes = bytes[4+seglen*2+optlen:]
		}
		if accepted {
			accsegs = append(accsegs, newsegs[i])
		}
	}
	return newsegs, accsegs, srcIA, dstIA, nil
}

func decodeInterfaces(bytes []byte, seglen int) []snet.PathInterface {
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

// EncodeSegments encodes the segments to sent to the other CONPASS segments in
// bytes. This function also takes into account the ``old'' set of segments,
// which is already known to both agents. The function returns the byte
// sequence as well the encoded segments in the order of transmission.
func EncodeSegments(newsegs, oldsegs []Segment, srcIA, dstIA addr.IA) ([]byte, []Segment) {
	hdrlen := 20
	allbytes := make([]byte, hdrlen)
	allbytes[1] = uint8(hdrlen)
	binary.BigEndian.PutUint64(allbytes[4:], uint64(srcIA.IAInt()))
	binary.BigEndian.PutUint64(allbytes[12:], uint64(dstIA.IAInt()))

	segidx := make(map[string]int)
	for idx, seg := range oldsegs {
		segidx[seg.Fingerprint()] = idx
	}
	currentIdx := len(oldsegs)
	sentsegs := make([]Segment, 0)

	for _, newseg := range newsegs {
		// encode (unaccepted) subsegments
		subsegs := recursiveSubsegments(newseg)
		for _, subseg := range subsegs {
			fprint := subseg.Fingerprint()
			if _, ok := segidx[fprint]; !ok { // not seen before
				segidx[fprint] = currentIdx
				currentIdx++
				accepted := false
				allbytes = append(allbytes, encodeSegment(subseg, accepted, segidx)...)
				sentsegs = append(sentsegs, subseg)
			}
		}
		// encode (accepted) segment
		fprint := newseg.Fingerprint()
		if idx, ok := segidx[fprint]; !ok { // not seen before
			segidx[fprint] = currentIdx
			currentIdx++
			accepted := true
			allbytes = append(allbytes, encodeSegment(newseg, accepted, segidx)...)
			sentsegs = append(sentsegs, newseg)
		} else { // seen before
			currentIdx++
			accepted := true
			allbytes = append(allbytes, encodeSegment(FromSegments(oldsegs[idx]), accepted, segidx)...)
			sentsegs = append(sentsegs, FromSegments(oldsegs[idx]))
		}
	}

	numsegs := uint16(currentIdx - len(oldsegs))
	binary.BigEndian.PutUint16(allbytes[2:], numsegs)
	return allbytes, sentsegs
}

func encodeSegment(segment Segment, accepted bool, segidx map[string]int) []byte {
	var flags uint8
	var seglen, optlen int
	if accepted {
		flags = segAcceptedTrue
	} else {
		flags = segAcceptedFalse
	}
	var bytes []byte

	switch s := segment.(type) {
	case Literal:
		flags |= segTypeLiteral
		seglen = len(s.Interfaces)
		bytes = make([]byte, 4+seglen*16+optlen)
		encodeInterfaces(bytes[4:], s.Interfaces)
	case Composition:
		flags |= segTypeComposition
		seglen = len(s.Segments)
		bytes = make([]byte, 4+seglen*2+optlen)
		for i, subseg := range s.Segments {
			binary.BigEndian.PutUint16(bytes[4+i*2:], uint16(segidx[subseg.Fingerprint()]))
		}
	}

	bytes[0] = flags
	bytes[1] = uint8(seglen)
	binary.BigEndian.PutUint16(bytes[2:], uint16(optlen))
	return bytes
}

func recursiveSubsegments(segment Segment) []Segment {
	switch s := segment.(type) {
	case Composition:
		segments := make([]Segment, 0)
		for _, segment := range s.Segments {
			segments = append(segments, recursiveSubsegments(segment)...)
			segments = append(segments, segment)
		}
		return segments
	}
	return []Segment{}
}

func encodeInterfaces(bytes []byte, interfaces []snet.PathInterface) {
	for i, iface := range interfaces {
		binary.BigEndian.PutUint64(bytes[i*16:], uint64(iface.ID))
		binary.BigEndian.PutUint64(bytes[i*16+8:], uint64(iface.IA.IAInt()))
	}
}
