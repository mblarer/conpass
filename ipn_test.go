package ipn

import (
	"io"
	"testing"

	"github.com/mblarer/scion-ipn/filter"
	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

type doublepipe struct {
	*io.PipeReader
	*io.PipeWriter
}

func TestNegotiation1PathNoFilter(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	p1, p2 := doublepipe{r1, w2}, doublepipe{r2, w1}

	segments := []segment.Segment{
		segment.FromString("19-ffaa:0:1303 1>1 19-ffaa:0:1302"),
		segment.FromString("19-ffaa:0:1302 2>1 17-ffaa:0:1108"),
		segment.FromString("17-ffaa:0:1108 2>1 17-ffaa:0:1102 2>1 17-ffaa:0:1107"),
	}

	srcIA, _ := addr.IAFromString("19-ffaa:0:1303")
	dstIA, _ := addr.IAFromString("17-ffaa:0:1107")

	segset := segment.SegmentSet{
		Segments: segments,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	}

	client := Initiator{
		InitialSegset: segset,
		Filter:        filter.FromFilters(),
	}
	server := Responder{
		Filter: filter.FromFilters(),
	}

	channel := make(chan segment.SegmentSet, 1)
	go func(c chan segment.SegmentSet, t *testing.T) {
		ssegset, err := server.NegotiateOver(p1)
		if err != nil {
			t.Fatal(err)
		}
		c <- ssegset
	}(channel, t)

	csegset, err := client.NegotiateOver(p2)
	if err != nil {
		t.Fatal(err)
	}
	ssegset := <-channel

	csegs := csegset.Segments
	ssegs := ssegset.Segments

	if len(segments) != len(ssegs) {
		t.Fatal("server segments have not right length:", len(csegs))
	}
	for i := 0; i < len(segments); i++ {
		if segments[i].Fingerprint() != ssegs[i].Fingerprint() {
			t.Error("server wanted:", segments[i], "got:", ssegs[i])
		}
	}
	if len(segments) != len(csegs) {
		t.Fatal("client segments have not right length:", len(csegs))
	}
	for i := 0; i < len(segments); i++ {
		if segments[i].Fingerprint() != csegs[i].Fingerprint() {
			t.Error("client wanted:", segments[i], "got:", csegs[i])
		}
	}
}
