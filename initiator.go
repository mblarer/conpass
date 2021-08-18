package ipn

import (
	"fmt"
	"io"
	"log"

	"github.com/mblarer/scion-ipn/segment"
	"github.com/scionproto/scion/go/lib/addr"
)

type Initiator struct {
	SrcIA    addr.IA
	DstIA    addr.IA
	Segments []segment.Segment
	Filter   segment.Filter
	Verbose  bool
}

func (agent Initiator) NegotiateOver(stream io.ReadWriter) ([]segment.Segment, error) {
	newsegs := agent.Filter.Filter(agent.Segments)
	if agent.Verbose {
		log.Println(len(newsegs), "segments remaining after initial filtering:")
		for _, segment := range newsegs {
			fmt.Println(" ", segment)
		}
	}
	oldsegs := []segment.Segment{}
	bytes := segment.EncodeSegments(newsegs, oldsegs)
	_, err := stream.Write(bytes)
	if err != nil {
		return nil, err
	}
	recvbuf := make([]byte, 64*1024)
	_, err = stream.Read(recvbuf)
	if err != nil {
		return nil, err
	}
	oldsegs = newsegs
	newsegs, err = segment.DecodeSegments(recvbuf, oldsegs)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server response: %s", err.Error())
	}
	if agent.Verbose {
		log.Println("the server replied with", len(newsegs), "segments:")
		for _, segment := range newsegs {
			fmt.Println(" ", segment)
		}
	}
	newsegs = agent.Filter.Filter(newsegs)
	if agent.Verbose {
		log.Println(len(newsegs), "segments remaining after final filtering:")
		for _, segment := range newsegs {
			fmt.Println(" ", segment)
		}
	}
	return newsegs, nil
}
