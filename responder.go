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

func (agent Responder) NegotiateOver(stream io.ReadWriter) ([]segment.Segment, error) {
	recvbuffer := make([]byte, 1<<20) // 1 MiB buffer
	_, err := stream.Read(recvbuffer)
	if err != nil {
		return nil, err
	}
	segsin, accsegs, srcIA, dstIA, err := segment.DecodeSegments(recvbuffer, []segment.Segment{})
	if err != nil {
		return nil, err
	}
	if agent.Verbose {
		log.Println("request contains", len(segsin), "segments:")
		for _, segment := range segsin {
			fmt.Println(" ", segment)
		}
	}
	segsout := agent.Filter.Filter(accsegs)
	if agent.Verbose {
		log.Println("responding with", len(segsout), "segments:")
		for _, segment := range segsout {
			fmt.Println(" ", segment)
		}
	}
	sendbuffer, _ := segment.EncodeSegments(segsout, segsin, srcIA, dstIA)
	_, err = stream.Write(sendbuffer)
	if err != nil {
		return nil, err
	}
	return segsout, nil
}
