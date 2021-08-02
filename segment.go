package ipn

import (
	pb "github.com/mblarer/scion-ipn/proto/negotiation"
	addr "github.com/scionproto/scion/go/lib/addr"
	common "github.com/scionproto/scion/go/lib/common"
	snet "github.com/scionproto/scion/go/lib/snet"
)

type SegmentID uint32

type Segment interface {
	ID() SegmentID
	Valid() bool
	Interfaces() []snet.PathInterface
	PB() *pb.Segment
	SrcIA() addr.IA
	DstIA() addr.IA
}

func SegmentsFromPB(pbsegs []*pb.Segment) []Segment {
	// TODO: refactor, rename
	segments := make([]Segment, len(pbsegs))
	for i, pbseg := range pbsegs {
		pbintfs := pbseg.GetLiteral()
		if len(pbintfs) > 0 {
			intfs := make([]snet.PathInterface, len(pbintfs))
			for j, pbintf := range pbintfs {
				intfs[j] = snet.PathInterface{
					ID: common.IFIDType(pbintf.GetId()),
					IA: addr.IAInt(pbintf.GetIsdAs()).IA(),
				}
			}
			segments[i] = NewSegmentLiteral(SegmentID(pbseg.GetId()), pbseg.GetValid(), intfs...)
		} else {
			pbids := pbseg.GetComposition()
			subsegs := make([]Segment, len(pbids))
			for j, pbid := range pbids {
				subsegs[j] = segments[pbid]
			}
			segments[i] = NewSegmentComposition(SegmentID(pbseg.GetId()), pbseg.GetValid(), subsegs...)
		}
	}
	return segments
}

func SegmentsToPB(segs []Segment) []*pb.Segment {
	pbsegs := make([]*pb.Segment, len(segs))
	for i, seg := range segs {
		pbsegs[i] = seg.PB()
	}
	return pbsegs
}

// SegmentLiteral implements the Segment interface.
type SegmentLiteral struct {
	id         SegmentID
	valid      bool
	interfaces []snet.PathInterface
}

func NewSegmentLiteral(id SegmentID, valid bool, ifs ...snet.PathInterface) Segment {
	return &SegmentLiteral{id, valid, ifs}
}

func (sl SegmentLiteral) ID() SegmentID { return sl.id }
func (sl SegmentLiteral) Valid() bool   { return sl.valid }

func (sl SegmentLiteral) Interfaces() []snet.PathInterface {
	intfs := make([]snet.PathInterface, 0, len(sl.interfaces))
	intfs = append(intfs, sl.interfaces...)
	return intfs
}

func (sl SegmentLiteral) PB() *pb.Segment {
	return &pb.Segment{
		Id:      uint32(sl.id),
		Valid:   sl.valid,
		Literal: intfsToPB(sl.interfaces),
	}
}

func (sl SegmentLiteral) SrcIA() addr.IA {
	if len(sl.interfaces) == 0 {
		panic("segment literal is empty")
	}
	return sl.interfaces[0].IA
}

func (sl SegmentLiteral) DstIA() addr.IA {
	if len(sl.interfaces) == 0 {
		panic("segment literal is empty")
	}
	return sl.interfaces[len(sl.interfaces)-1].IA
}

func intfsToPB(intfs []snet.PathInterface) []*pb.Interface {
	pbifs := make([]*pb.Interface, len(intfs))
	for i, intf := range intfs {
		pbifs[i] = &pb.Interface{
			Id:    uint64(intf.ID),
			IsdAs: uint64(intf.IA.IAInt()),
		}
	}
	return pbifs
}

// SegmentComposition implements the Segment interface.
type SegmentComposition struct {
	id       SegmentID
	valid    bool
	segments []Segment
}

func NewSegmentComposition(id SegmentID, valid bool, segs ...Segment) Segment {
	return SegmentComposition{id, valid, segs}
}

func (sc SegmentComposition) ID() SegmentID { return sc.id }
func (sc SegmentComposition) Valid() bool   { return sc.valid }

func (sc SegmentComposition) Interfaces() []snet.PathInterface {
	intfs := make([]snet.PathInterface, 0)
	for _, seg := range sc.segments {
		intfs = append(intfs, seg.Interfaces()...)
	}
	return intfs
}

func (sc SegmentComposition) PB() *pb.Segment {
	return &pb.Segment{
		Id:          uint32(sc.id),
		Valid:       sc.valid,
		Composition: segPtrsToPB(sc.segments),
	}
}

func (sc SegmentComposition) SrcIA() addr.IA {
	if len(sc.segments) == 0 {
		panic("segment composition is empty")
	}
	return sc.segments[0].SrcIA()
}

func (sc SegmentComposition) DstIA() addr.IA {
	if len(sc.segments) == 0 {
		panic("segment composition is empty")
	}
	return sc.segments[len(sc.segments)-1].DstIA()
}

func segPtrsToPB(ptrs []Segment) []uint32 {
	refs := make([]uint32, len(ptrs))
	for i, segptr := range ptrs {
		refs[i] = uint32(segptr.ID())
	}
	return refs
}
