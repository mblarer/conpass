package ipn

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
)

type Initiator struct {
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
	bytes, sentsegs := segment.EncodeSegments(newsegset.Segments, oldsegs, newsegset.SrcIA, newsegset.DstIA)
	_, err := stream.Write(bytes)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	recvbuf := make([]byte, 1<<20) // 1 MiB buffer
	_, err = stream.Read(recvbuf)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	_, accsegs, _, _, err := segment.DecodeSegments(recvbuf, sentsegs)
	if err != nil {
		return segment.SegmentSet{}, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	if agent.Verbose {
		log.Println("the server replied with", len(accsegs), "segments:")
		for _, segment := range accsegs {
			fmt.Println(" ", segment)
		}
	}
	accsegset := segment.SegmentSet{
		Segments: accsegs,
		SrcIA:    agent.InitialSegset.SrcIA,
		DstIA:    agent.InitialSegset.DstIA,
	}
	newsegset = agent.Filter.Filter(accsegset)
	if agent.Verbose {
		log.Println(len(newsegset.Segments), "segments remaining after final filtering:")
		for _, segment := range newsegset.Segments {
			fmt.Println(" ", segment)
		}
	}
	return newsegset, nil
}
