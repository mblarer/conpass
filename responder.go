package ipn

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
)

type Responder struct {
	Filter  segment.Filter
	Verbose bool
}

func (agent Responder) NegotiateOver(stream io.ReadWriter) (segment.SegmentSet, error) {
	recvbuffer := make([]byte, 1<<20) // 1 MiB buffer
	_, err := stream.Read(recvbuffer)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	segsin, accsegs, srcIA, dstIA, err := segment.DecodeSegments(recvbuffer, []segment.Segment{})
	if err != nil {
		return segment.SegmentSet{}, err
	}
	if agent.Verbose {
		log.Println("request contains", len(segsin), "segments:")
		for _, segment := range segsin {
			fmt.Println(" ", segment)
		}
	}
	segsetout := agent.Filter.Filter(segment.SegmentSet{
		Segments: accsegs,
		SrcIA:    srcIA,
		DstIA:    dstIA,
	})
	if agent.Verbose {
		log.Println("responding with", len(segsetout.Segments), "segments:")
		for _, segment := range segsetout.Segments {
			fmt.Println(" ", segment)
		}
	}
	sendbuffer, _ := segment.EncodeSegments(segsetout.Segments, segsin, srcIA, dstIA)
	_, err = stream.Write(sendbuffer)
	if err != nil {
		return segment.SegmentSet{}, err
	}
	return segsetout, nil
}
