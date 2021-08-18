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
	recvbuffer := make([]byte, 64*1024)
	_, err := stream.Read(recvbuffer)
	if err != nil {
		return nil, err
	}
	segsin, err := segment.DecodeSegments(recvbuffer, []segment.Segment{})
	if err != nil {
		return nil, err
	}
	if agent.Verbose {
		log.Println("request contains", len(segsin), "segments:")
		for _, segment := range segsin {
			fmt.Println(" ", segment)
		}
	}
	segsout := agent.Filter.Filter(segsin)
	if agent.Verbose {
		log.Println("responding with", len(segsout), "segments:")
		for _, segment := range segsout {
			fmt.Println(" ", segment)
		}
	}
	sendbuffer := segment.EncodeSegments(segsout, segsin)
	_, err = stream.Write(sendbuffer)
	if err != nil {
		return nil, err
	}
	return segsout, nil
}
