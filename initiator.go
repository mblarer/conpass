package ipn

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

type Initiator struct {
	SrcIA         addr.IA
	DstIA         addr.IA
	InitialSegset segment.SegmentSet
	Filter        segment.Filter
	Verbose       bool
}

func (agent Initiator) NegotiateOver(stream io.ReadWriter) (segment.SegmentSet, error) {
	newsegset := agent.Filter.Filter(agent.InitialSegset)
	if agent.Verbose {
		log.Println(len(newsegset.Segments), "segments remaining after initial filtering:")
		for _, segment := range newsegset.Segments {
			fmt.Println(" ", segment)
		}
	}
	oldsegs := []segment.Segment{}
	bytes, sentsegs := segment.EncodeSegments(newsegset.Segments, oldsegs, agent.SrcIA, agent.DstIA)
	_, err := stream.Write(bytes)
	if err != nil {
		return segment.SegmentSet{nil}, err
	}
	recvbuf := make([]byte, 1<<20) // 1 MiB buffer
	_, err = stream.Read(recvbuf)
	if err != nil {
		return segment.SegmentSet{nil}, err
	}
	_, accsegs, _, _, err := segment.DecodeSegments(recvbuf, sentsegs)
	if err != nil {
		return segment.SegmentSet{nil}, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	if agent.Verbose {
		log.Println("the server replied with", len(accsegs), "segments:")
		for _, segment := range accsegs {
			fmt.Println(" ", segment)
		}
	}
	newsegset = agent.Filter.Filter(segment.SegmentSet{Segments: accsegs})
	if agent.Verbose {
		log.Println(len(newsegset.Segments), "segments remaining after final filtering:")
		for _, segment := range newsegset.Segments {
			fmt.Println(" ", segment)
		}
	}
	return newsegset, nil
}
