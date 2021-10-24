package conpass

import (
	"io"
	"testing"

	"github.com/mblarer/conpass/filter"
	"github.com/mblarer/conpass/segment"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/pathpol"
)

func TestNegotiation1PathNoFilter(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	cfilter, sfilter := filter.FromFilters(), filter.FromFilters()
	want := segments
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathClientEnum(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	cfilter, sfilter := filter.SrcDstPathEnumerator(), filter.FromFilters()
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302 2>1 17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathServerEnum(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	cfilter, sfilter := filter.FromFilters(), filter.SrcDstPathEnumerator()
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302 2>1 17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathBothEnum(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	cfilter, sfilter := filter.SrcDstPathEnumerator(), filter.SrcDstPathEnumerator()
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302 2>1 17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathClientACLAllow(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	acl := new(pathpol.ACL)
	_ = acl.UnmarshalJSON([]byte(`["+"]`))
	cfilter, sfilter := filter.FromACL(*acl), filter.FromFilters()
	want := segments
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathServerACLAllow(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	acl := new(pathpol.ACL)
	_ = acl.UnmarshalJSON([]byte(`["+"]`))
	cfilter, sfilter := filter.FromFilters(), filter.FromACL(*acl)
	want := segments
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathClientACLDeny(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	acl := new(pathpol.ACL)
	_ = acl.UnmarshalJSON([]byte(`["- 19", "+"]`))
	cfilter, sfilter := filter.FromACL(*acl), filter.FromFilters()
	want := []segment.Segment{
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathServerACLDeny(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	acl := new(pathpol.ACL)
	_ = acl.UnmarshalJSON([]byte(`["+ 19", "-"]`))
	cfilter, sfilter := filter.FromFilters(), filter.FromACL(*acl)
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathClientSequenceAllow(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	seq := new(pathpol.Sequence)
	_ = seq.UnmarshalJSON([]byte(`"0*"`))
	cfilter := filter.FromFilters(filter.SrcDstPathEnumerator(), filter.FromSequence(*seq))
	sfilter := filter.FromFilters()
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302 2>1 17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathServerSequenceAllow(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	seq := new(pathpol.Sequence)
	_ = seq.UnmarshalJSON([]byte(`"19* 17*"`))
	cfilter := filter.FromFilters()
	sfilter := filter.FromFilters(filter.SrcDstPathEnumerator(), filter.FromSequence(*seq))
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302 2>1 17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathClientSequenceDeny(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	seq := new(pathpol.Sequence)
	_ = seq.UnmarshalJSON([]byte(`"17* 19*"`))
	cfilter := filter.FromFilters(filter.SrcDstPathEnumerator(), filter.FromSequence(*seq))
	sfilter := filter.FromFilters()
	want := []segment.Segment{}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiation1PathServerSequenceDeny(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	seq := new(pathpol.Sequence)
	_ = seq.UnmarshalJSON([]byte(`"19 19 19+"`))
	cfilter := filter.FromFilters()
	sfilter := filter.FromFilters(filter.SrcDstPathEnumerator(), filter.FromSequence(*seq))
	want := []segment.Segment{}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiationTooLongPath(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1109"),
		segment.FromString("17-ffaa:0:1109 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	cfilter, sfilter := filter.FromFilters(), filter.SrcDstPathEnumerator()
	want := []segment.Segment{}
	test(segset, cfilter, sfilter, want, t)
}

func TestNegotiationCyclicPath(t *testing.T) {
	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>2 19-ffaa:0:1303"),
		segment.FromString("19-ffaa:0:1303 3>4 19-ffaa:0:1303"),
		segment.FromString("19-ffaa:0:1303 5>1 17-ffaa:0:1107"),
		segment.FromString("19-ffaa:0:1303 6>1 19-ffaa:0:1304"),
		segment.FromString("19-ffaa:0:1304 2>7 19-ffaa:0:1303"),
	}
	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")
	segset := segment.SegmentSet{Segments: segments, SrcIA: srcIA, DstIA: dstIA}
	cfilter, sfilter := filter.SrcDstPathEnumerator(), filter.FromFilters()
	want := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 5>1 17-ffaa:0:1107"),
	}
	test(segset, cfilter, sfilter, want, t)
}

func test(ss segment.SegmentSet, cf, sf segment.Filter, want []segment.Segment, t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	p1, p2 := doublepipe{r1, w2}, doublepipe{r2, w1}
	client := Initiator{InitialSegset: ss, Filter: cf}
	server := Responder{Filter: sf}
	channel := make(chan segment.SegmentSet, 1)
	go func(c chan segment.SegmentSet, t *testing.T) {
		ssegset, err := server.NegotiateOver(p1)
		if err != nil {
			t.Error(err)
		}
		c <- ssegset
	}(channel, t)
	csegset, err := client.NegotiateOver(p2)
	if err != nil {
		t.Fatal(err)
	}
	ssegset := <-channel
	assertEqual(csegset.Segments, want, t)
	assertEqual(ssegset.Segments, want, t)
}

type doublepipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func assertEqual(have, want []segment.Segment, t *testing.T) {
	if len(have) != len(want) {
		t.Fatal("segments have not right length, want:", len(want), ", have:", len(have))
	}
	for i := 0; i < len(have); i++ {
		if have[i].Fingerprint() != want[i].Fingerprint() {
			t.Error("want:", want[i], "have:", have[i])
		}
	}
}
